#!/usr/bin/env python3
"""
tls_case_study.py  -  Cryptographic Failures in TLS
23CSE331 Cryptography - Case Study, Topic 3

One pipeline that covers every stage the report needs:

    Vulnerability identification  -> audit_host() / audit_lab()
    Attack model (explicit)       -> print_attack_model()
    Attack steps / demonstration  -> attack_padding_oracle, attack_rc4,
                                      attack_weak_dh, attack_forward_secrecy
    Countermeasure                -> countermeasure checks inside each attack,
                                      plus the hardened-server comparison
    Real-world incident           -> INCIDENTS table, printed with each attack

Usage
  python tls_case_study.py                 # full automated run, lab servers only
  python tls_case_study.py --host example.com   # also audit a real server
  python tls_case_study.py --menu           # interactive step-through menu
  python tls_case_study.py --rc4-sessions 200000 --dh-bits 32

Everything except --host runs locally. Only audit hosts you own or are
permitted to test (badssl.com is fine).

Setup: pip install cryptography matplotlib
"""
import argparse
import datetime as dt
import http.client
import ipaddress
import math
import os
import secrets
import socket
import ssl
import sys
import tempfile
import threading
import time
import warnings
from collections import Counter

warnings.simplefilter("ignore", DeprecationWarning)

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes, padding, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519
    from cryptography.hazmat.primitives.asymmetric import padding as apad
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    sys.exit("Missing package. Run:  pip install cryptography")

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAVE_PLOT = True
except ImportError:
    HAVE_PLOT = False

V = ssl.TLSVersion
PROTOCOLS = [("TLSv1.0", V.TLSv1), ("TLSv1.1", V.TLSv1_1),
             ("TLSv1.2", V.TLSv1_2), ("TLSv1.3", V.TLSv1_3)]
WEAK_CIPHERS = {
    "kRSA":   "Static RSA key exchange: no forward secrecy",
    "3DES":   "3DES: 64-bit block, Sweet32 birthday attack",
    "RC4":    "RC4: biased keystream, plaintext recovery",
    "eNULL":  "NULL cipher: no encryption at all",
    "EXPORT": "EXPORT-grade: 40/512-bit keys, FREAK / Logjam",
}
SEV_ORDER = {"OK": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

ATTACK_MODELS = {
    "padding_oracle": dict(
        name="CBC Padding-Oracle Attack (Vaudenay 2002 / POODLE 2014 / Lucky13 2013)",
        adversary="Active, chosen-ciphertext attacker",
        knowledge="IV, ciphertext, algorithm (AES-CBC + PKCS7). Does NOT know the key.",
        capability="Submits forged ciphertexts to the server and observes ONE bit of "
                    "feedback: 'padding valid?' (a distinct alert, or timing in Lucky13).",
        goal="Recover the plaintext without ever learning the key.",
        assumption="Server decrypts-then-checks-MAC (MAC-then-encrypt), and leaks a "
                    "distinguishable signal on padding failure.",
    ),
    "rc4": dict(
        name="RC4 Keystream Bias Attack (Mantin-Shamir 2001 / AlFardan et al. 2013)",
        adversary="Passive, ciphertext-only attacker",
        knowledge="Many independently-keyed encryptions of the SAME plaintext "
                   "(e.g. a repeated session cookie sent on every request).",
        capability="Collects ciphertexts across N sessions and performs frequency analysis.",
        goal="Recover one or more bytes of the repeated secret.",
        assumption="RC4 is used as the stream cipher; the plaintext byte position repeats "
                    "across sessions with fresh keys.",
    ),
    "weak_dh": dict(
        name="Weak / Export Diffie-Hellman (Logjam, Adrian et al. 2015)",
        adversary="Passive eavesdropper, compute-bound",
        knowledge="Public parameters p, g and the public values A, B (all sent in clear).",
        capability="Solves the discrete log problem for small p (here: baby-step giant-step).",
        goal="Recover the shared session key and decrypt recorded traffic.",
        assumption="The server negotiates (or can be downgraded to) a small/export-grade "
                    "DH group. Real attacks use NFS with precomputation per prime.",
    ),
    "forward_secrecy": dict(
        name="Retroactive Decryption after Long-Term Key Compromise",
        adversary="Passive recorder, later becomes key-compromise attacker",
        knowledge="All traffic from static-RSA sessions, recorded and stored.",
        capability="Obtains the server's long-term RSA private key at a LATER time "
                    "(theft, legal process, leak).",
        goal="Decrypt old, previously-recorded sessions.",
        assumption="Key exchange was static-RSA (TLS_RSA_*), not ephemeral (EC)DHE.",
    ),
}

INCIDENTS = {
    "padding_oracle": "POODLE (CVE-2014-3566), Lucky13 (CVE-2013-0169)",
    "rc4": "RC4 NOMORE attack (2015); RC4 banned in TLS by RFC 7465 (2015)",
    "weak_dh": "Logjam (CVE-2015-4000, Adrian et al., CCS 2015)",
    "forward_secrecy": "Heartbleed (2014) made this realistic: stolen RSA keys could "
                        "decrypt previously recorded static-RSA traffic",
}


def banner(title):
    print("\n" + "=" * 74)
    print(f"=== {title}")
    print("=" * 74)


def print_attack_model(key):
    m = ATTACK_MODELS[key]
    print(f"\n--- Attack model: {m['name']} ---")
    print(f"  Adversary  : {m['adversary']}")
    print(f"  Knowledge  : {m['knowledge']}")
    print(f"  Capability : {m['capability']}")
    print(f"  Goal       : {m['goal']}")
    print(f"  Assumption : {m['assumption']}")
    print(f"  Real-world : {INCIDENTS[key]}")


def ask(prompt, default=""):
    text = f"{prompt} [{default}]: " if default else f"{prompt}: "
    return input(text).strip() or default


def derive_key(secret: bytes, info: bytes = b"tls-demo") -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(secret)


def printable(bs):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in bs)


def _legacy_ctx(minv=None, maxv=None, ciphers=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if minv:
        ctx.minimum_version = minv
    if maxv:
        ctx.maximum_version = maxv
    ctx.set_ciphers((ciphers or "ALL") + ":@SECLEVEL=0")
    return ctx


def _handshake(host, port, ctx):
    with socket.create_connection((host, port), timeout=3) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t:
            return {"version": t.version(), "cipher": t.cipher(),
                    "der": t.getpeercert(binary_form=True)}


def probe(host, port, **kw):
    try:
        ctx = _legacy_ctx(**kw)
    except (ssl.SSLError, ValueError):
        return "untestable"
    try:
        _handshake(host, port, ctx)
        return "accepted"
    except (ssl.SSLError, OSError):
        return "rejected"


def trust_check(host, port, cafile=None):
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    try:
        _handshake(host, port, ctx)
        return True, "valid"
    except ssl.SSLCertVerificationError as e:
        return False, e.verify_message
    except (ssl.SSLError, OSError) as e:
        return False, str(e)


def hsts_header(host, port):
    try:
        conn = http.client.HTTPSConnection(host, port, timeout=3, context=_legacy_ctx())
        conn.request("HEAD", "/")
        return conn.getresponse().getheader("Strict-Transport-Security")
    except Exception:
        return None


def analyze_cert(der):
    c = x509.load_der_x509_certificate(der)
    out = []
    now = dt.datetime.now(dt.timezone.utc)
    left = (c.not_valid_after_utc - now).days
    if left < 0:
        out.append(("CRITICAL", "Certificate", f"Expired {-left} days ago"))
    elif left < 30:
        out.append(("MEDIUM", "Certificate", f"Expires in {left} days"))
    else:
        out.append(("OK", "Certificate", f"Valid, {left} days remaining"))

    pub = c.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        bits, kind, bad = pub.key_size, "RSA", pub.key_size < 2048
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        bits, kind, bad = pub.key_size, f"EC ({pub.curve.name})", pub.key_size < 224
    else:
        bits, kind, bad = 0, type(pub).__name__, False
    out.append(("HIGH" if bad else "OK", "Key strength",
                f"{kind} {bits}-bit" + (" - below NIST minimum" if bad else "")))

    h = c.signature_hash_algorithm
    hname = h.name if h else "n/a (EdDSA)"
    weak = h is not None and h.name in ("md5", "sha1")
    out.append(("HIGH" if weak else "OK", "Signature algorithm",
                f"{hname}" + (" - collision attacks possible" if weak else "")))
    return out


def audit(host, port, cafile=None):
    findings, info = [], {}
    try:
        base = _handshake(host, port, _legacy_ctx())
    except Exception as e:
        raise ConnectionError(f"Cannot complete a handshake with {host}:{port}: {e}")

    ver, (cipher, _, bits) = base["version"], base["cipher"]
    info["negotiated"] = f"{ver} / {cipher} ({bits}-bit)"

    info["protocols"] = {}
    for name, v in PROTOCOLS:
        r = probe(host, port, minv=v, maxv=v)
        info["protocols"][name] = r
        if name in ("TLSv1.0", "TLSv1.1") and r == "accepted":
            findings.append(("HIGH", "Protocol", f"{name} accepted - deprecated by RFC 8996"))
    if info["protocols"]["TLSv1.3"] != "accepted":
        findings.append(("LOW", "Protocol", "TLS 1.3 not supported"))

    info["weak_ciphers"] = {}
    for fam, why in WEAK_CIPHERS.items():
        r = probe(host, port, maxv=V.TLSv1_2, ciphers=fam)
        info["weak_ciphers"][fam] = r
        if r == "accepted":
            sev = "CRITICAL" if fam in ("eNULL", "EXPORT", "RC4") else "HIGH" if fam == "3DES" else "MEDIUM"
            findings.append((sev, "Cipher suite", why))

    if ver != "TLSv1.3" and not ("ECDHE" in cipher or "DHE" in cipher):
        findings.append(("MEDIUM", "Key exchange", f"Negotiated {cipher} has no forward secrecy"))

    findings += analyze_cert(base["der"])
    ok, why = trust_check(host, port, cafile)
    findings.append(("OK" if ok else "HIGH", "Trust chain / hostname",
                     "Chain and hostname verified" if ok else f"Verification failed: {why}"))

    h = hsts_header(host, port)
    findings.append(("OK", "HSTS", h) if h else
                    ("LOW", "HSTS", "Header missing - SSL-stripping possible on first visit"))
    return info, findings


def grade(findings):
    worst = max(SEV_ORDER[s] for s, _, _ in findings)
    return {0: "A", 1: "B", 2: "C", 3: "D", 4: "F"}[worst]


def print_audit_report(host, port, info, findings):
    g = grade(findings)
    print(f"\n{'-' * 74}\n TLS audit: {host}:{port}      GRADE: {g}\n{'-' * 74}")
    print(f" Negotiated  : {info['negotiated']}")
    print(" Protocols   : " + "  ".join(f"{k}={v}" for k, v in info["protocols"].items()))
    print(" Weak ciphers: " + "  ".join(f"{k}={v}" for k, v in info["weak_ciphers"].items()))
    print("-" * 74)
    for s, c, d in sorted(findings, key=lambda f: -SEV_ORDER[f[0]]):
        print(f" [{s:<8}] {c:<22} {d}")
    return g


def make_cert(cn, bits, hash_alg, expired=False):
    key = rsa.generate_private_key(65537, bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    nb, na = ((now - dt.timedelta(days=800), now - dt.timedelta(days=30)) if expired
              else (now - dt.timedelta(days=1), now + dt.timedelta(days=365)))
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(nb).not_valid_after(na)
               .add_extension(x509.SubjectAlternativeName([
                   x509.DNSName(cn),
                   x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
               ]), False)
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), True))
    try:
        cert = builder.sign(key, hash_alg)
    except Exception:
        print(f"[lab] this OpenSSL build refuses {hash_alg.name} signatures; using SHA-256 instead")
        cert = builder.sign(key, hashes.SHA256())
    d = tempfile.mkdtemp()
    cf, kf = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    open(cf, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kf, "wb").write(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
    return cf, kf


def serve(port, certf, keyf, minv, maxv, ciphers=None, hsts=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version, ctx.maximum_version = minv, maxv
    if ciphers:
        ctx.set_ciphers(ciphers)
    ctx.load_cert_chain(certf, keyf)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    extra = "Strict-Transport-Security: max-age=31536000\r\n" if hsts else ""

    def handle_client(c):
        try:
            with ctx.wrap_socket(c, server_side=True) as t:
                t.settimeout(1.5)
                try:
                    t.recv(2048)
                except Exception:
                    pass
                t.sendall(f"HTTP/1.1 200 OK\r\n{extra}Content-Length: 2\r\n"
                          f"Connection: close\r\n\r\nok".encode())
        except Exception:
            pass
        finally:
            try:
                c.close()
            except Exception:
                pass

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle_client, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


_LAB = {}


def audit_lab(verbose=True, as_dict=False):
    """Detection stage: audit a deliberately vulnerable server vs a hardened one."""
    if verbose:
        banner("Stage 1: Vulnerability identification (local lab)")
        print("Starting a VULNERABLE server (TLS1.0+, weak ciphers, 1024-bit SHA-1 expired cert, no HSTS)")
        print("and a HARDENED server (TLS1.2+, AEAD+PFS only, 2048-bit cert, HSTS) on 127.0.0.1 ...")
    if not _LAB:
        vc, vk = make_cert("localhost", 1024, hashes.SHA1(), expired=True)
        hc, hk = make_cert("localhost", 2048, hashes.SHA256(), expired=False)
        serve(9441, vc, vk, V.TLSv1, V.TLSv1_3, "ALL:@SECLEVEL=0", hsts=False)
        serve(9442, hc, hk, V.TLSv1_2, V.TLSv1_3, "ECDHE+AESGCM:ECDHE+CHACHA20", hsts=True)
        _LAB.update(vc=vc, hc=hc)
        time.sleep(0.3)
    vc, hc = _LAB["vc"], _LAB["hc"]

    grades = {}
    details = {}
    for label, port, ca in (("VULNERABLE", 9441, vc), ("HARDENED", 9442, hc)):
        if verbose:
            print(f"\n>>> {label} server (127.0.0.1:{port})")
        info, f = audit("127.0.0.1", port, cafile=ca)
        g = print_audit_report("127.0.0.1", port, info, f) if verbose else grade(f)
        grades[label] = g
        details[label] = {"grade": g, "info": info, "findings": f, "port": port}

    if verbose:
        print(f"\nSummary: vulnerable server graded {grades['VULNERABLE']}, "
              f"hardened server graded {grades['HARDENED']}.")
        print("The demos below are local simulations of the same classes of weakness this audit flags.")
    if as_dict:
        return details
    return grades


class CBCServer:
    def __init__(self):
        self.key = os.urandom(16)
        self.queries = 0

    def encrypt(self, plaintext):
        iv = os.urandom(16)
        pd = padding.PKCS7(128).padder()
        data = pd.update(plaintext) + pd.finalize()
        enc = Cipher(algorithms.AES(self.key), modes.CBC(iv)).encryptor()
        return iv, enc.update(data) + enc.finalize()

    def padding_ok(self, iv, ct):
        self.queries += 1
        dec = Cipher(algorithms.AES(self.key), modes.CBC(iv)).decryptor()
        data = dec.update(ct) + dec.finalize()
        un = padding.PKCS7(128).unpadder()
        try:
            un.update(data)
            un.finalize()
            return True
        except ValueError:
            return False


def recover_block(server, prev, block, label, verbose=True):
    inter = bytearray(16)
    for pad in range(1, 17):
        pos = 16 - pad
        hit = None
        for guess in range(256):
            forged = bytearray(16)
            for k in range(pos + 1, 16):
                forged[k] = inter[k] ^ pad
            forged[pos] = guess
            if server.padding_ok(bytes(forged), block):
                if pad == 1:
                    check = bytearray(forged)
                    check[14] ^= 0xFF
                    if not server.padding_ok(bytes(check), block):
                        continue
                hit = guess
                break
        if hit is None:
            raise RuntimeError("oracle gave no valid padding (attack not possible)")
        inter[pos] = hit ^ pad
        so_far = bytes(inter[i] ^ prev[i] for i in range(pos, 16))
        if verbose:
            print(f"\r  {label}: recovered {16 - pos:2d}/16 bytes  ...{printable(so_far):<16}", end="", flush=True)
    if verbose:
        print()
    return bytes(inter[i] ^ prev[i] for i in range(16))


def attack_padding_oracle(secret_message: bytes, verbose: bool = True, as_dict: bool = False):
    if verbose:
        print_attack_model("padding_oracle")
        banner("Stage 2a: Attack - CBC padding oracle")
    server = CBCServer()
    iv, ct = server.encrypt(secret_message)
    blocks = [ct[i:i + 16] for i in range(0, len(ct), 16)]
    if verbose:
        print(f"Server encrypted {len(secret_message)} bytes with AES-128-CBC -> {len(blocks)} blocks.")
        print(f"Attacker sees ONLY: IV + ciphertext + oracle 'padding valid?'.")
        print(f"IV: {iv.hex()}   ciphertext: {ct.hex()[:64]}...")

    t0 = time.time()
    plain, prev = b"", iv
    for n, blk in enumerate(blocks, 1):
        plain += recover_block(server, prev, blk, f"block {n}/{len(blocks)}", verbose=verbose)
        prev = blk
    dt_sec = time.time() - t0

    un = padding.PKCS7(128).unpadder()
    try:
        recovered = un.update(plain) + un.finalize()
    except ValueError:
        recovered = plain

    if verbose:
        print(f"\nRecovered plaintext : {recovered.decode(errors='replace')!r}")
        print(f"Matches original    : {recovered == secret_message}")
        print(f"Oracle queries      : {server.queries} "
              f"(~{server.queries / max(1, len(plain)):.0f}/byte; theory avg 128, max 256)")
        print(f"Time                : {dt_sec:.2f} s   (key brute force would need 2^128 tries)")

        print("\n--- Countermeasure: AEAD (AES-GCM, what TLS 1.3 mandates) ---")
    aead = AESGCM(AESGCM.generate_key(256))
    nonce = os.urandom(12)
    rec = aead.encrypt(nonce, b"A" * 16, None)
    accepted = 0
    for g in range(1, 256):
        forged = bytearray(rec)
        forged[-1] ^= g
        try:
            aead.decrypt(nonce, bytes(forged), None)
            accepted += 1
        except InvalidTag:
            pass
    if verbose:
        print(f"255 tampered records submitted, {accepted} accepted, all others fail identically.")
        print("No padding, no oracle: the integrity tag is checked before any padding logic runs.")

    if as_dict:
        return {
            "success": recovered == secret_message,
            "recovered": recovered.decode(errors="replace"),
            "original": secret_message.decode(errors="replace"),
            "queries": server.queries,
            "time_sec": round(dt_sec, 3),
            "num_blocks": len(blocks),
            "iv": iv.hex(),
            "ciphertext": ct.hex(),
            "aead_accepted": accepted,
            "aead_tested": 255
        }
    return recovered == secret_message


def rc4_keystream(key, n):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = []
    for _ in range(n):
        i = (i + 1) & 255
        j = (j + S[i]) & 255
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 255])
    return out


def attack_rc4(secret: bytes, n_sessions: int, verbose: bool = True, as_dict: bool = False):
    if verbose:
        print_attack_model("rc4")
        banner("Stage 2b: Attack - RC4 keystream bias")
    ks = rc4_keystream(b"Key", 9)
    ct = bytes(a ^ b for a, b in zip(b"Plaintext", ks))
    assert ct.hex().upper() == "BBF316E8D940AF0AD3", "RC4 self-test failed"
    if verbose:
        print("RC4 implementation self-test against published test vector: OK")

    if len(secret) < 2:
        secret = (secret + b"XX")[:2]
    if verbose:
        print(f"Simulating {n_sessions} sessions, each with a fresh random 128-bit RC4 key ...")
    keys = os.urandom(16 * n_sessions)
    z2_counts, c2_counts = Counter(), Counter()
    t0 = time.time()
    for s in range(n_sessions):
        key = keys[16 * s:16 * s + 16]
        z2 = rc4_keystream(key, 2)[1]
        z2_counts[z2] += 1
        c2_counts[secret[1] ^ z2] += 1
    dt_sec = time.time() - t0

    p0 = z2_counts[0] / n_sessions
    top = c2_counts.most_common(1)[0]
    guess = top[0]
    ok = guess == secret[1]

    if verbose:
        print(f"Done in {dt_sec:.1f} s")
        print(f"P(2nd keystream byte = 0): measured {p0 * 100:.3f}%  "
              f"(ideal {100/256:.3f}%, known RC4 bias {200/256:.3f}%)")
        print(f"Attacker's guess for secret[1] = {chr(guess)!r}  "
              f"(seen {top[1]} times)   real value = {chr(secret[1])!r}  -> "
              f"{'RECOVERED' if ok else 'not enough samples yet'}")

    if HAVE_PLOT and verbose:
        plt.figure(figsize=(8, 3.5))
        plt.bar(range(256), [z2_counts[v] / n_sessions for v in range(256)], width=1.0)
        plt.axhline(1 / 256, color="red", linestyle="--", label="ideal 1/256")
        plt.xlabel("2nd RC4 keystream byte value"); plt.ylabel("probability")
        plt.title(f"RC4 Z2 distribution over {n_sessions} random keys"); plt.legend()
        plt.tight_layout(); plt.savefig("rc4_bias.png", dpi=130); plt.close()
        print("Saved graph: rc4_bias.png")

    if verbose:
        print("\n--- Countermeasure ---")
        print("RC4 is removed from TLS entirely (RFC 7465). AES-GCM / ChaCha20-Poly1305")
        print("keystreams are cryptographically indistinguishable from random, so this")
        print("statistical attack has no equivalent against them.")

    if as_dict:
        return {
            "success": ok,
            "sessions": n_sessions,
            "z2_counts": [z2_counts[v] for v in range(256)],
            "measured_p0_pct": round(p0 * 100, 3),
            "ideal_p0_pct": round(100 / 256, 3),
            "bias_p0_pct": round(200 / 256, 3),
            "guess_char": chr(guess) if 32 <= guess < 127 else f"0x{guess:02x}",
            "guess_byte": guess,
            "target_char": chr(secret[1]) if 32 <= secret[1] < 127 else f"0x{secret[1]:02x}",
            "target_byte": secret[1],
            "time_sec": round(dt_sec, 2),
            "top_candidates": [{"byte": k, "char": chr(k) if 32 <= k < 127 else f"0x{k:02x}", "count": v}
                               for k, v in c2_counts.most_common(5)]
        }
    return ok


def is_probable_prime(n, rounds=20):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits):
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(c):
            return c


def bsgs(g, h, p):
    m = math.isqrt(p) + 1
    table, cur = {}, 1
    for j in range(m):
        table.setdefault(cur, j)
        cur = cur * g % p
    factor = pow(g, -m, p)
    gamma = h
    for i in range(m + 1):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma * factor % p
    return None


def attack_weak_dh(message: bytes, bits: int, verbose: bool = True, as_dict: bool = False):
    if verbose:
        print_attack_model("weak_dh")
        banner("Stage 2c: Attack - Weak Diffie-Hellman (Logjam-class)")
    bits = max(12, min(bits, 44))
    p, g = gen_prime(bits), 2
    a = secrets.randbelow(p - 3) + 2
    b = secrets.randbelow(p - 3) + 2
    A, B = pow(g, a, p), pow(g, b, p)
    if verbose:
        print(f"Public parameters (sent in clear): p={p} ({bits}-bit), g={g}")
        print(f"Alice sends A = {A}   Bob sends B = {B}")

    shared = pow(B, a, p)
    assert shared == pow(A, b, p)
    key = derive_key(shared.to_bytes(8, "big"))
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, message, None)
    if verbose:
        print(f"Session key agreed, message encrypted: {ct.hex()}")
        print("\nEve recorded p, g, A, B and the ciphertext. Solving g^x = A (mod p) ...")

    t0 = time.time()
    x = bsgs(g, A, p)
    dt_sec = time.time() - t0
    eve_key = derive_key(pow(B, x, p).to_bytes(8, "big"))
    try:
        plain = AESGCM(eve_key).decrypt(nonce, ct, None)
        if verbose:
            print(f"Found x in {dt_sec:.3f}s (~2^{bits//2} steps). Eve decrypts: {plain.decode()!r}")
            print("=> Key exchange broken; AES itself was never attacked.")
        ok = plain == message
    except InvalidTag:
        if verbose:
            print("Decryption failed (unexpected).")
        ok = False

    if verbose:
        print("\n--- Countermeasure ---")
        print("Use >= 2048-bit DH groups or ECDHE (TLS 1.3 removes export/weak DH groups")
        print("entirely and fixes strong named groups), so discrete-log attacks become")
        print("computationally infeasible (sub-exponential NFS still needs months per prime).")

    if as_dict:
        return {
            "success": ok,
            "bits": bits,
            "prime_p": str(p),
            "base_g": g,
            "alice_pub_A": str(A),
            "bob_pub_B": str(B),
            "ciphertext": ct.hex(),
            "solved_x": str(x),
            "time_sec": round(dt_sec, 4),
            "recovered": plain.decode(errors="replace") if ok else ""
        }
    return ok


def attack_forward_secrecy(message: bytes, verbose: bool = True, as_dict: bool = False):
    if verbose:
        print_attack_model("forward_secrecy")
        banner("Stage 2d: Attack - retroactive decryption (no forward secrecy)")
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    premaster = os.urandom(32)
    enc_pm = server_key.public_key().encrypt(premaster, apad.PKCS1v15())
    nonce_a = os.urandom(12)
    ct_a = AESGCM(derive_key(premaster)).encrypt(nonce_a, message, None)
    if verbose:
        print(f"Session A (static RSA): recorded enc_premaster={enc_pm.hex()[:32]}..., ct={ct_a.hex()[:24]}...")

    srv_eph = x25519.X25519PrivateKey.generate()
    cli_eph = x25519.X25519PrivateKey.generate()
    raw = lambda k: k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    srv_pub, cli_pub = raw(srv_eph), raw(cli_eph)
    shared = cli_eph.exchange(srv_eph.public_key())
    nonce_b = os.urandom(12)
    ct_b = AESGCM(derive_key(shared)).encrypt(nonce_b, message, None)
    del srv_eph, cli_eph, shared
    if verbose:
        print(f"Session B (ECDHE): ephemeral keys used then destroyed, ct={ct_b.hex()[:24]}...")
        print("\n>>> Server's long-term RSA key is later stolen / leaked / subpoenaed <<<")

    pm = server_key.decrypt(enc_pm, apad.PKCS1v15())
    plain_a = AESGCM(derive_key(pm)).decrypt(nonce_a, ct_a, None)
    if verbose:
        print(f"Session A decrypted retroactively: {plain_a.decode()!r}   [BROKEN]")

    numbers = server_key.private_numbers()
    guess = numbers.d.to_bytes(256, "big")[:32]
    try:
        AESGCM(derive_key(guess)).decrypt(nonce_b, ct_b, None)
        if verbose:
            print("Session B: decrypted (unexpected)")
        b_safe = False
    except InvalidTag:
        if verbose:
            print("Session B: stolen RSA key is useless -> InvalidTag   [SAFE]")
        b_safe = True

    if verbose:
        print("\n--- Countermeasure ---")
        print("TLS 1.3 removes static-RSA key exchange entirely; ephemeral (EC)DHE is")
        print("mandatory, so every session is forward secret by default.")

    if as_dict:
        return {
            "success": plain_a == message and b_safe,
            "session_a_decrypted": plain_a.decode(errors="replace"),
            "session_a_ct": ct_a.hex(),
            "session_b_ct": ct_b.hex(),
            "session_b_safe": b_safe,
            "recovered": plain_a.decode(errors="replace")
        }
    return plain_a == message and b_safe


def demo_tls13_summary():
    banner("Stage 3: What TLS 1.3 (RFC 8446) fixes")
    rows = [
        ("Failure / attack", "TLS 1.2 and earlier", "TLS 1.3"),
        ("-" * 22, "-" * 30, "-" * 28),
        ("Padding oracle (POODLE, Lucky13)", "CBC, MAC-then-encrypt", "AEAD only (GCM/ChaCha20)"),
        ("RC4 biases", "RC4 allowed", "RC4 removed"),
        ("Sweet32", "3DES (64-bit block)", "3DES removed"),
        ("FREAK / Logjam", "Export RSA/DH suites", "Export suites removed"),
        ("No forward secrecy", "Static RSA key transport", "Ephemeral (EC)DHE mandatory"),
        ("ROBOT / Bleichenbacher", "RSA PKCS#1 v1.5 encryption", "RSA encryption removed"),
        ("Downgrade attacks", "Weak negotiation", "Downgrade sentinel in Random"),
        ("Handshake privacy", "Certificates in clear", "Encrypted after ServerHello"),
    ]
    for r in rows:
        print(f"  {r[0]:<34}{r[1]:<32}{r[2]}")


def run_full(args):
    results = {}
    results["audit"] = audit_lab(verbose=True)
    if args.host:
        banner(f"Stage 1b: Vulnerability identification - real host {args.host}:{args.port}")
        try:
            info, f = audit(args.host, args.port, args.cafile)
            print_audit_report(args.host, args.port, info, f)
        except Exception as e:
            print(f"[!] Real-host audit error: {e}")
            print("Skipping the real-host audit and continuing with the demos.")

    results["padding_oracle"] = attack_padding_oracle(b"Cookie: session=Sup3rS3cretToken", verbose=True)
    results["rc4"] = attack_rc4(b"Password123", args.rc4_sessions, verbose=True)
    results["weak_dh"] = attack_weak_dh(b"Transfer 100 rupees to Alice", args.dh_bits, verbose=True)
    results["forward_secrecy"] = attack_forward_secrecy(b"Account PIN is 4821", verbose=True)
    demo_tls13_summary()

    banner("Final summary")
    print(f"Lab audit grades : vulnerable={results['audit']['VULNERABLE']}, "
          f"hardened={results['audit']['HARDENED']}")
    for key in ("padding_oracle", "rc4", "weak_dh", "forward_secrecy"):
        print(f"{ATTACK_MODELS[key]['name']:<55} attack succeeded: {results[key]}")
    print("\nEach demo above simulates the attack on the weak design and shows the modern")
    print("countermeasure that removes it (TLS 1.2 AEAD+ECDHE, or TLS 1.3).")


def launch_web_ui(port=8080):
    """Launch the modern HTML/CSS/JS web demonstration server and open in browser."""
    import subprocess
    import webbrowser
    server_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web_server.py")
    print(f"\n[+] Starting TLS Web UI Dashboard at http://localhost:{port} ...")
    try:
        proc = subprocess.Popen([sys.executable, server_path, "--port", str(port)])
        time.sleep(1.2)
        webbrowser.open(f"http://localhost:{port}")
        print(f"[+] Web UI running! Opened http://localhost:{port} in your browser.")
        print("[+] Press Ctrl+C in this terminal when finished to return to the menu.\n")
        proc.wait()
    except KeyboardInterrupt:
        print("\n[+] Stopping Web UI server...")
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            pass


def interactive_menu(args):
    while True:
        print("\n" + "=" * 74)
        print("  23CSE331 Cryptography - Cryptographic Failures in TLS (Topic 3)")
        print("  Case Study & Live Exploit Demonstration System")
        print("=" * 74)
        print("  [1]  Audit Lab (Simultaneous Vulnerable vs Hardened Server on 127.0.0.1)")
        print("  [2]  Audit Remote Host (Scan real domain or badssl.com e.g. rc4.badssl.com)")
        print("  [3]  Attack 1: CBC Padding Oracle Attack (POODLE / Lucky13 simulation)")
        print("  [4]  Attack 2: RC4 Keystream Bias Attack (Mantin-Shamir / RFC 7465)")
        print("  [5]  Attack 3: Weak Diffie-Hellman / Logjam (BSGS Discrete Log Solving)")
        print("  [6]  Attack 4: Loss of Forward Secrecy (Static RSA Theft vs ECDHE)")
        print("  [7]  TLS 1.3 Security Protections & RFC 8446 Comparison Matrix")
        print("  [8]  Threat Models & Historical Incidents (POODLE, Logjam, Heartbleed...)")
        print("  [9]  Run Full Automated Benchmark Pipeline (All Stages End-to-End)")
        print("  [10] Launch Modern HTML/CSS/JS Web UI Dashboard (Opens in Browser)")
        print("  [0]  Exit")
        print("=" * 74)
        choice = input("Enter your choice [0-10]: ").strip().lower()

        if choice in ("0", "q", "exit", "quit"):
            print("\nExiting TLS Case Study demonstration. Goodbye!\n")
            break
        elif choice == "1":
            audit_lab(verbose=True)
            input("\n[Press Enter to return to menu]")
        elif choice == "2":
            h = ask("Target hostname", args.host or "badssl.com")
            p = int(ask("Port", str(args.port or 443)))
            try:
                info, f = audit(h, p, args.cafile)
                print_audit_report(h, p, info, f)
            except Exception as e:
                print(f"[!] Audit failed for {h}:{p}: {e}")
            input("\n[Press Enter to return to menu]")
        elif choice == "3":
            msg = ask("Secret message to recover", "Cookie: session=Sup3rS3cretToken").encode()
            attack_padding_oracle(msg, verbose=True)
            input("\n[Press Enter to return to menu]")
        elif choice == "4":
            sec = ask("Repeated secret string", "Password123").encode()
            sess = int(ask("Number of sessions", str(args.rc4_sessions or 50000)))
            attack_rc4(sec, sess, verbose=True)
            input("\n[Press Enter to return to menu]")
        elif choice == "5":
            msg = ask("Confidential message", "Transfer 100 rupees to Alice").encode()
            bits = int(ask("DH prime bits (16-40)", str(args.dh_bits or 28)))
            attack_weak_dh(msg, bits, verbose=True)
            input("\n[Press Enter to return to menu]")
        elif choice == "6":
            msg = ask("Confidential message", "Account PIN is 4821").encode()
            attack_forward_secrecy(msg, verbose=True)
            input("\n[Press Enter to return to menu]")
        elif choice == "7":
            demo_tls13_summary()
            input("\n[Press Enter to return to menu]")
        elif choice == "8":
            banner("Threat Models & Historical Incident Catalog")
            for k in ATTACK_MODELS:
                print_attack_model(k)
            input("\n[Press Enter to return to menu]")
        elif choice in ("9", "a"):
            run_full(args)
            input("\n[Press Enter to return to menu]")
        elif choice in ("10", "w", "web", "ui"):
            launch_web_ui()
            input("\n[Press Enter to return to menu]")
        else:
            print("[!] Invalid option. Please enter a number between 0 and 10.")


def main():
    ap = argparse.ArgumentParser(description="TLS cryptographic failures - full case study")
    ap.add_argument("--host", help="also audit a real host (only hosts you're permitted to test)")
    ap.add_argument("-p", "--port", type=int, default=443)
    ap.add_argument("--cafile")
    ap.add_argument("--rc4-sessions", type=int, default=50000)
    ap.add_argument("--dh-bits", type=int, default=28)
    ap.add_argument("--menu", action="store_true", help="interactive step-through menu")
    ap.add_argument("--batch", "--all", action="store_true", help="run all tests automatically in batch mode")
    ap.add_argument("--web", action="store_true", help="launch HTML/CSS/JS web dashboard directly")
    args = ap.parse_args()

    if args.web:
        launch_web_ui()
    elif args.batch or (args.host and not args.menu):
        run_full(args)
    else:
        # Default behavior is the interactive menu!
        interactive_menu(args)


if __name__ == "__main__":
    main()