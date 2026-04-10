# HEXSSL-CLI

Official HEXSSL command-line toolkit for advanced web security diagnostics.


## 🚀 Overview

HEXSSL-CLI provides fast, automation-friendly diagnostics for:

- TLS certificate inspection
- HSTS header correctness
- Chrome preload eligibility
- HTTP → HTTPS redirect enforcement
- Subdomain consistency
- Multi-path HSTS scanning
- Full audit with grading (A–F)

Designed for sysadmins, DevOps/SRE, security engineers and CI/CD usage.

---

## 📦 Installation

### From PyPI

    pip install hexssl-cli

### From source

    git clone https://github.com/hexssl/hexssl-cli.git
    cd hexssl-cli
    pip install .

---

## 🔧 Usage Examples

### Certificate check

    hexssl-cli cert check example.com

### Certificate check as JSON

    hexssl-cli cert check example.com --json

### Mail trust check

    hexssl-cli mail check example.com --selector default

### Mail trust check as JSON

    hexssl-cli mail check example.com --selector default --json

### HSTS header check

    hexssl-cli hsts check example.com

### Preload analysis

    hexssl-cli hsts preload example.com

### Redirect chain evaluation

    hexssl-cli hsts redirects example.com

### Multi-path scan

    hexssl-cli hsts scan example.com --paths "/,/login,/api,/admin"

### Full audit

    hexssl-cli hsts audit example.com

---

## 📊 Output Preview

    HEXSSL-CLI full HSTS audit for: example.com

    Grade : B
    Status: ok

    HSTS header:
      - max-age OK
      - includeSubDomains OK
      - preload missing

---

## ⚙️ Exit Codes

| Code | Meaning |
|------|---------|
| 0    | OK |
| 1    | TLS or connection error |
| 2    | Validation issues detected |
| 3    | Audit warnings |
| 4    | Fatal error |

---

## 🧱 Project Structure

    hexssl-cli/
    └── src/hexssl_cli/
        ├── cli.py
        ├── core/
        └── modules/
            ├── cert/
            ├── dns/
            └── hsts/

---

## 📘 Documentation

Full documentation is available in the `docs/` directory (MkDocs Material).

---

## 🌐 Links

- Website: https://www.hexssl.com
- GitHub: https://github.com/hexssl/hexssl-cli
- Contact: sales@hexssl.com

---

## 📄 License

MIT License © 2025 HEXSSL
