# HEXSSL-CLI

Official HEXSSL command-line toolkit for trust, TLS, certificate, DNS, and mail security diagnostics.

## 🚀 Overview

HEXSSL-CLI provides fast, automation-friendly diagnostics for:

* TLS certificate inspection
* DNS validation
* mail trust validation
* HSTS header correctness
* Chrome preload eligibility
* HTTP → HTTPS redirect enforcement
* subdomain consistency
* multi-path HSTS scanning
* full audit with grading (A–F)

Designed for sysadmins, DevOps/SRE, security engineers, hosting providers, MSPs, and CI/CD usage.

---

## 📦 Installation

### From PyPI

```bash
pip install hexssl-cli
```

### From source

```bash
git clone https://github.com/hexssl/hexssl-cli.git
cd hexssl-cli
pip install .
```

---

## 🔧 Usage Examples

### Certificate check

```bash
hexssl-cli cert check example.com
```

### Certificate check as JSON

```bash
hexssl-cli cert check example.com --json
```

### DNS check

```bash
hexssl-cli dns check example.com
```

### DNS check as JSON

```bash
hexssl-cli dns check example.com --json
```

### Mail trust check

```bash
hexssl-cli mail check example.com --selector default
```

### Mail trust check as JSON

```bash
hexssl-cli mail check example.com --selector default --json
```

### HSTS header check

```bash
hexssl-cli hsts check example.com
```

### Preload analysis

```bash
hexssl-cli hsts preload example.com
```

### Redirect chain evaluation

```bash
hexssl-cli hsts redirects example.com
```

### Multi-path scan

```bash
hexssl-cli hsts scan example.com --paths "/,/login,/api,/admin"
```

### Full audit

```bash
hexssl-cli hsts audit example.com
```

---

## 📊 Output Preview

### Certificate check

```text
HEXSSL-CLI certificate check for: example.com
Status : OK
Summary: Certificate is valid for the requested host.
```

### DNS check

```text
HEXSSL-CLI DNS check for: example.com
Status : WARNING
Summary: DNS records are present, but there are hardening gaps.
```

### Mail trust check

```text
HEXSSL-CLI mail check for: example.com
Status : FAIL
Summary: Mail trust records need corrective action.
```

---

## ⚙️ Exit Codes

| Code | Meaning                              |
| ---- | ------------------------------------ |
| 0    | OK                                   |
| 1    | Warning / issues detected            |
| 2    | Failure / corrective action required |
| 10   | Input or usage error                 |
| 11   | Network or timeout error             |
| 12   | Parsing or validation error          |

> If your current implementation uses a different exit-code mapping for legacy HSTS commands, document those differences explicitly here or align them in a future cleanup.

---

## 🧱 Project Structure

```text
hexssl-cli/
└── src/hexssl_cli/
    ├── cli.py
    ├── core/
    └── modules/
        ├── cert/
        ├── dns/
        ├── hsts/
        ├── mail/
        └── report/
```

---

## 📘 Documentation

Full documentation is available in the `docs/` directory.

---

## 🌐 Links

* Website: https://www.hexssl.com
* GitHub: https://github.com/hexssl/hexssl-cli
* Contact: [sales@hexssl.com](mailto:sales@hexssl.com)

---

## 📄 License

MIT License © 2025 HEXSSL
