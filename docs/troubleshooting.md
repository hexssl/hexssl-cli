# Troubleshooting

### ❌ Connection error  

Possible reasons:

- target domain offline  
- firewall blocks outgoing connections  
- DNS issues  

Try increasing timeout:

    hexssl-cli hsts audit example.com --timeout 10

---

### ❌ Invalid certificate  

The domain returns an expired/misconfigured SSL certificate.  
HSTS cannot be validated.

---

### ❌ Timeout  

Network slowdown or server rate-limiting.  
Increase timeout or retry.

---

### ❌ No DNS  

Subdomain does not exist.  
This is normal for development or unused zones.

---

### ❌ HTTPS error  

The domain may redirect incorrectly or block TLS probes.
