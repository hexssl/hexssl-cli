# FAQ

### ❓ Does HEXSSL-CLI modify or change anything on the server?  

No. HEXSSL-CLI is read-only. It does not send any data beyond standard HTTP requests.

---

### ❓ Is it safe to run in production?  

Yes — the tool only performs outbound HTTPS requests.

---

### ❓ How often is the preload list updated?  

The tool downloads the freshest Chromium preload list on every run.

---

### ❓ Which Python versions are supported?  

Python 3.9+.

---

### ❓ Can I use it in CI/CD pipelines?  

Yes. Exit codes are designed exactly for that purpose.
