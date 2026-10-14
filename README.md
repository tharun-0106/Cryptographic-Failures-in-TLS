# Cryptographic Failures in TLS — Case Study Demonstration System

**23CSE331 - Cryptography (Semester V)**  
**Case Study, Topic 3:** Cryptographic Failures in TLS  
**Institution:** Amrita Vishwa Vidyapeetham, Coimbatore  

---

## 👥 Authors / Team Members

* **Tharun D** — `CB.SC.U4CSE24053`
* **Rishikeshwar V T** — `CB.SC.U4CSE24041`
* **Vidhyadharan R P** — `CB.SC.U4CSE24058`
* **Prithesh S** — `CB.SC.U4CSE24038`

---

## 📌 Project Overview

This project provides an interactive audit engine and live cryptographic attack simulation suite demonstrating historical failure classes in the Transport Layer Security (TLS) protocol, as well as the cryptographic architecture of **TLS 1.3 (RFC 8446)** designed to eliminate them.

### Covered Cryptographic Failures & Demonstrations

1. **Stage 1: Vulnerability Identification & Server Auditing**
   * Inspects protocol versions (TLS 1.0, 1.1, 1.2, 1.3), cipher suites (RC4, 3DES, Export, kRSA), key exchange forward secrecy, certificate chain validation, and HSTS headers against NIST & RFC 8996 criteria.
   * Compares a deliberately vulnerable local server with an ephemeral-only, AEAD-hardened server.
   * Supports live network auditing of authorized external targets (e.g., `badssl.com`).

2. **Stage 2a: CBC Padding-Oracle Attack**
   * **Adversary Model:** Active, chosen-ciphertext attacker.
   * **Mechanism:** Exploits TLS MAC-then-encrypt CBC mode (Vaudenay 2002 / POODLE CVE-2014-3566 / Lucky13 CVE-2013-0169). Recovers plaintext bytes by observing padding validity feedback.
   * **TLS 1.3 Countermeasure:** AEAD modes (AES-GCM / ChaCha20-Poly1305) authenticate ciphertext *before* decryption.

3. **Stage 2b: RC4 Keystream Biases**
   * **Adversary Model:** Passive eavesdropper collecting ciphertexts across sessions.
   * **Mechanism:** Mantin-Shamir bias (2001) and AlFardan et al. (2013). Exploits non-uniform keystream bias $P(Z_2 = 0) \approx 2/256$, enabling secret recovery without key factorization.
   * **TLS 1.3 Countermeasure:** RC4 permanently banned by RFC 7465.

4. **Stage 2c: Weak / Export Diffie-Hellman (Logjam-Class)**
   * **Adversary Model:** Passive network eavesdropper.
   * **Mechanism:** Solves Discrete Logarithm Problem on weak/export primes via Baby-Step Giant-Step (BSGS) to derive the shared AES session key.
   * **TLS 1.3 Countermeasure:** Ephemeral named groups $\ge 2048$-bit and ECDHE (X25519) mandatory.

5. **Stage 2d: Loss of Forward Secrecy & Retroactive Decryption**
   * **Adversary Model:** Passive traffic recorder who later steals the long-term private key (e.g., Heartbleed).
   * **Mechanism:** In static RSA key transport (`TLS_RSA_*`), compromise of the server's RSA private key decrypts past recorded traffic retroactively. In ephemeral ECDHE, traffic remains impenetrable.

6. **Stage 3: Architectural Comparison Matrix & Threat Models**
   * Exhaustive feature-by-feature mapping between TLS 1.2 and TLS 1.3 with associated CVE references.

---

## 🚀 Getting Started

### Prerequisites

* Python 3.9+
* Required packages:
  ```bash
  pip install -r requirements.txt
  ```

### Running the Web Dashboard (Recommended)

To start the full graphical interface and interactive simulation dashboard:

```bash
python web_server.py
```

The web server will automatically open your default browser at `http://127.0.0.1:8080` (or the next available port).

### Running via CLI

You can also run the demonstrations directly from the command line:

```bash
# Automated run with local test servers
python tls.py

# Interactive menu
python tls.py --menu

# Audit a remote server
python tls.py --host badssl.com

# Custom parameters
python tls.py --rc4-sessions 100000 --dh-bits 28
```

---

## 📂 Project Structure

```text
├── tls.py              # Core cryptographic auditing and attack simulation engines
├── web_server.py       # REST API server backing the frontend dashboard
├── web/
│   ├── index.html      # Responsive dashboard interface
│   ├── style.css       # Custom dark-theme styling, responsive layouts & typography
│   └── app.js          # Client-side controller, Chart.js integrations & API handlers
├── rc4_bias.png        # Generated RC4 distribution plot
├── requirements.txt    # Project Python dependencies
└── .gitignore          # Git exclusion rules
```

---

## ⚖️ License & Academic Disclaimer

Developed for academic demonstration and research purposes under the **23CSE331 Cryptography** curriculum at Amrita Vishwa Vidyapeetham. Only audit systems and networks that you own or have explicit authorization to evaluate.
