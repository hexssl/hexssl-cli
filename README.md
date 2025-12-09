# HEXSSL-CLI

Official HEXSSL command-line toolkit for advanced web security diagnostics.


## 🚀 Overview

HEXSSL-CLI provides fast, automation-friendly diagnostics for:

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
| 2    | HSTS issues detected |
| 3    | Audit warnings |
| 4    | Fatal error |

---

## 🧱 Project Structure

    hexssl-cli/
    └── src/hexssl_cli/
        ├── cli.py
        └── modules/
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
