import re
import typer
import idna

DEFAULT_TIMEOUT = 5.0

DEFAULT_HEADERS = {
    "User-Agent": "HEXSSL-CLI/0.1.0 (+https://www.hexssl.com)"
}

# Basic domain validation: 1–253 chars, no starting/ending hyphens,
# allows subdomains and punycode ("xn--...").
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9.-]+(?<!-)$")


def validate_domain(domain: str) -> str:
    """
    Normalizes and validates a domain string:
    - strips whitespace,
    - removes trailing dots,
    - converts to lowercase,
    - converts Unicode → IDNA (Punycode),
    - applies regex validation.
    
    Returns a safe, normalized domain string.
    """
    domain = domain.strip()

    # remove optional trailing dot (valid in DNS, confusing in URLs)
    if domain.endswith("."):
        domain = domain[:-1]

    # lowercase domain
    domain = domain.lower()

    # convert internationalized domain names (IDN) to punycode:
    # ąćę.pl → xn--...
    try:
        domain = idna.encode(domain).decode()
    except Exception:
        raise typer.BadParameter("Invalid domain (IDN encoding failed)")

    # final validation
    if not DOMAIN_RE.match(domain):
        raise typer.BadParameter("Invalid domain format")

    return domain
