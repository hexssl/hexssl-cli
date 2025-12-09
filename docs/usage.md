# Usage

HEXSSL-CLI uses a modular structure:

    hexssl-cli <module> <command> [options]

Currently available module:  
- 'hsts'

---

# 🔧 Global Help

    hexssl-cli --help
    hexssl-cli hsts --help
    hexssl-cli hsts audit --help

---

# 🔍 Example Workflows

## 1. Validate HSTS header

    hexssl-cli hsts check example.com

## 2. Analyze preload readiness

    hexssl-cli hsts preload example.com

## 3. Check redirect consistency (HTTP → HTTPS)

    hexssl-cli hsts redirects example.com

## 4. Multi-path HSTS analysis

    hexssl-cli hsts scan example.com --paths "/,/login,/api,/admin"

## 5. Full audit (recommended)

    hexssl-cli hsts audit example.com

---

# ⛑ Exit Codes

| Code | Meaning                |
|------|------------------------|
| 0    | OK / no issues         |
| 1    | TLS or connection error|
| 2    | HSTS issues detected   |
| 3    | Audit warnings         |
| 4    | Fatal error            |

---

# 🧪 Example Audit Output

    HEXSSL-CLI full HSTS audit for: example.com

    Grade : B
    Status: ok

    HSTS header:
     - max-age OK
     - includeSubDomains OK
     - preload missing
