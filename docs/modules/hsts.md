# HSTS Module

The HSTS module validates strict transport security configuration.

---

# Commands Overview

## 🔹 hsts check

    hexssl-cli hsts check example.com

Checks correctness of the 'Strict-Transport-Security' header.

---

## 🔹 hsts preload

    hexssl-cli hsts preload example.com

Evaluates Chrome preload readiness and reports list status.

---

## 🔹 hsts redirects

    hexssl-cli hsts redirects example.com

Analyzes HTTP → HTTPS redirects, status codes, and final protocol.

---

## 🔹 hsts scan

    hexssl-cli hsts scan example.com --paths "/,/login,/api"

Checks HSTS consistency across multiple endpoints.

---

## 🔹 hsts subdomains

    hexssl-cli hsts subdomains example.com

Verifies DNS, HTTPS, and HSTS presence on common subdomains.

---

## 🔹 hsts audit

    hexssl-cli hsts audit example.com

Full combined report including:

- header validation  
- preload eligibility  
- redirect hygiene  
- subdomain consistency  
- multi-path scan  
- final grade (A–F)
