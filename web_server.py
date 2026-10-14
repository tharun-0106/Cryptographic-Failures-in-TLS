#!/usr/bin/env python3
"""
web_server.py  -  Web UI Server for Cryptographic Failures in TLS
23CSE331 Cryptography - Case Study Demonstration System

Serves the modern HTML/CSS/JS frontend and provides a REST API
backed by tls.py cryptographic audit & attack simulation engines.
"""
import argparse
import json
import mimetypes
import os
import sys
import threading
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Ensure current directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tls

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


class TLSWebHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Keep console output clean
        pass

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/info":
            summary_rows = [
                {"attack": "Padding oracle (POODLE, Lucky13)", "tls12": "CBC, MAC-then-encrypt", "tls13": "AEAD only (GCM/ChaCha20)", "cve": "CVE-2014-3566 / CVE-2013-0169"},
                {"attack": "RC4 keystream biases", "tls12": "RC4 allowed", "tls13": "RC4 permanently removed", "cve": "RFC 7465 / NOMORE 2015"},
                {"attack": "Sweet32 birthday attack", "tls12": "3DES (64-bit block)", "tls13": "3DES removed", "cve": "CVE-2016-2183"},
                {"attack": "Logjam / FREAK (Weak DH)", "tls12": "Export 512-bit / custom DH", "tls13": "Named groups >= 2048-bit or ECDHE", "cve": "CVE-2015-4000"},
                {"attack": "Loss of forward secrecy", "tls12": "Static RSA key exchange allowed", "tls13": "Ephemeral (EC)DHE mandatory", "cve": "Heartbleed compromise"},
                {"attack": "ROBOT / Bleichenbacher", "tls12": "RSA PKCS#1 v1.5 encryption", "tls13": "RSA encryption removed", "cve": "CVE-2017-13099"},
                {"attack": "Downgrade attacks", "tls12": "Weak version negotiation", "tls13": "Downgrade sentinel in ServerHello", "cve": "RFC 8446 Section 4.1.3"},
                {"attack": "Cleartext handshake", "tls12": "Certificates sent in clear", "tls13": "Handshake encrypted after ServerHello", "cve": "Eavesdropping protection"},
            ]
            return self.send_json({
                "models": tls.ATTACK_MODELS,
                "incidents": tls.INCIDENTS,
                "ciphers": tls.WEAK_CIPHERS,
                "matrix": summary_rows,
                "project": {
                    "course": "23CSE331 - Cryptography",
                    "title": "Cryptographic Failures in TLS",
                    "institution": "Amrita Vishwa Vidyapeetham, Coimbatore",
                    "authors": [
                        {"name": "Tharun D", "roll": "CB.SC.U4CSE24053"},
                        {"name": "Rishikeshwar V T", "roll": "CB.SC.U4CSE24041"},
                        {"name": "Vidhyadharan R P", "roll": "CB.SC.U4CSE24058"},
                        {"name": "Prithesh S", "roll": "CB.SC.U4CSE24038"}
                    ]
                }
            })

        # Static files
        if path == "/" or path == "/index.html":
            file_path = os.path.join(WEB_DIR, "index.html")
        else:
            rel = path.lstrip("/")
            file_path = os.path.join(WEB_DIR, rel)

        # Allow serving generated charts like rc4_bias.png
        if not os.path.isfile(file_path):
            alt = os.path.join(os.path.dirname(os.path.abspath(__file__)), path.lstrip("/"))
            if os.path.isfile(alt):
                file_path = alt

        if os.path.isfile(file_path):
            mime_type, _ = mimetypes.guess_type(file_path)
            mime_type = mime_type or "application/octet-stream"
            try:
                with open(file_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", mime_type)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            except Exception as e:
                return self.send_json({"error": f"Failed reading file: {e}"}, 500)

        self.send_json({"error": "Not Found"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            req_data = json.loads(raw_body)
        except json.JSONDecodeError:
            req_data = {}

        try:
            if path == "/api/audit-lab":
                details = tls.audit_lab(verbose=False, as_dict=True)
                return self.send_json({"success": True, "details": details})

            elif path == "/api/audit-host":
                host = req_data.get("host", "badssl.com").strip()
                port = int(req_data.get("port", 443))
                try:
                    info, findings = tls.audit(host, port)
                    g = tls.grade(findings)
                    return self.send_json({
                        "success": True,
                        "host": host,
                        "port": port,
                        "grade": g,
                        "info": info,
                        "findings": findings
                    })
                except Exception as e:
                    return self.send_json({"success": False, "error": str(e)}, 400)

            elif path == "/api/attack/padding-oracle":
                msg = req_data.get("message", "Cookie: session=Sup3rS3cretToken").encode("utf-8")
                res = tls.attack_padding_oracle(msg, verbose=False, as_dict=True)
                return self.send_json(res)

            elif path == "/api/attack/rc4":
                secret = req_data.get("secret", "Password123").encode("utf-8")
                sessions = int(req_data.get("sessions", 50000))
                sessions = max(1000, min(sessions, 200000))
                res = tls.attack_rc4(secret, sessions, verbose=False, as_dict=True)
                return self.send_json(res)

            elif path == "/api/attack/weak-dh":
                msg = req_data.get("message", "Transfer 100 rupees to Alice").encode("utf-8")
                bits = int(req_data.get("bits", 28))
                bits = max(12, min(bits, 40))
                res = tls.attack_weak_dh(msg, bits, verbose=False, as_dict=True)
                return self.send_json(res)

            elif path == "/api/attack/forward-secrecy":
                msg = req_data.get("message", "Account PIN is 4821").encode("utf-8")
                res = tls.attack_forward_secrecy(msg, verbose=False, as_dict=True)
                return self.send_json(res)

            else:
                return self.send_json({"error": "Unknown API endpoint"}, 404)

        except Exception as e:
            return self.send_json({"success": False, "error": f"Internal execution error: {e}"}, 500)


def run_server(port=8080, open_browser=True):
    for p in range(port, port + 10):
        try:
            server = HTTPServer(("127.0.0.1", p), TLSWebHandler)
            actual_port = p
            break
        except OSError:
            continue
    else:
        print("[!] Error: Could not bind to any port between 8080 and 8090.")
        return

    url = f"http://127.0.0.1:{actual_port}"
    print("=" * 68)
    print("  TLS Cryptographic Failures Demonstration - Web Dashboard")
    print(f"  Server running locally at: {url}")
    print("=" * 68)

    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Shutting down web server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web UI Server for TLS Cryptographic Failures")
    parser.add_argument("--port", type=int, default=8080, help="Port to serve on (default: 8080)")
    parser.add_argument("--no-browser", action="store_true", help="Don't automatically open web browser")
    args = parser.parse_args()
    run_server(port=args.port, open_browser=not args.no_browser)
