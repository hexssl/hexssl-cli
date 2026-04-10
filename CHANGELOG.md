# Changelog

## 0.2.0 - 2026-04-10

### Added

* shared core for reusable result models, formatters, and exit-code handling
* 'cert check <target>' for certificate inspection
* 'dns check <domain>' for DNS validation
* 'mail check <domain> --selector <selector>' for mail trust validation

### Notes

* added human-readable and JSON output for the new modules
* added initial CLI tests for cert, dns, and mail checks
* expanded 'hexssl-cli' beyond HSTS-only checks
