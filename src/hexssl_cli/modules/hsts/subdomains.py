import socket
import requests

from .utils import DEFAULT_TIMEOUT, DEFAULT_HEADERS
from .parser import validate_hsts

COMMON_SUBS = ["www", "api", "m", "dev", "static", "cdn"]


def _resolve(host: str) -> bool:
    """
    Resolves host using IPv4 or IPv6.
    Returns True if DNS resolution succeeds, False otherwise.
    """
    try:
        socket.getaddrinfo(host, None)
        return True
    except Exception:
        return False


def check_subdomains(domain: str, timeout=DEFAULT_TIMEOUT):
    """
    Checks common subdomains for:
    - DNS availability (A/AAAA)
    - HTTPS availability
    - HSTS header presence
    """
    results = []

    for sub in COMMON_SUBS:
        host = f"{sub}.{domain}"

        # DNS check
        if not _resolve(host):
            results.append((host, "no_dns", None))
            continue

        # HTTPS + HSTS check
        try:
            resp = requests.get(
                f"https://{host}",
                timeout=timeout,
                headers=DEFAULT_HEADERS
            )
            results.append((host, "https", validate_hsts(resp.headers)))

        except Exception as e:
            results.append((host, "error", str(e)))

    return results
