import json
import base64
import requests
from typing import Any, Dict, Optional, Tuple

from .parser import validate_hsts, HSTSResult
from .utils import DEFAULT_TIMEOUT, DEFAULT_HEADERS

PRELOAD_LIST_URL = (
    "https://chromium.googlesource.com/chromium/src/+/main/"
    "net/http/transport_security_state_static.json?format=TEXT"
)


def download_preload_list(timeout=DEFAULT_TIMEOUT):
    """
    Downloads the Chromium HSTS preload list in base64-encoded JSON format.
    Returns parsed JSON or None on failure.
    """
    try:
        resp = requests.get(
            PRELOAD_LIST_URL,
            timeout=timeout,
            headers=DEFAULT_HEADERS
        )
        resp.raise_for_status()

        decoded = base64.b64decode(resp.text)
        return json.loads(decoded)

    except Exception:
        return None


def check_in_preload_list(data, domain: str) -> str:
    """
    Checks whether a domain exists in the downloaded preload list.
    Returns: "preloaded", "not_preloaded", or "unknown".
    """
    if data is None:
        return "unknown"

    for entry in data.get("entries", []):
        if entry.get("name") == domain:
            return "preloaded"

    return "not_preloaded"


def get_preload_info(domain: str, timeout=DEFAULT_TIMEOUT):
    """
    Performs a preload eligibility check:
    1. Fetch HSTS header from the domain.
    2. Download Chromium preload list.
    3. Assess eligibility.

    On connection error → return safe fallback.
    """

    # Try fetching header from the domain
    try:
        resp = requests.get(
            f"https://{domain}",
            timeout=timeout,
            headers=DEFAULT_HEADERS,
        )
    except Exception as e:
        # Return fallback HSTSResult with error info
        hsts = HSTSResult(
            present=False,
            max_age=None,
            include_subdomains=False,
            preload=False,
            issues=["connection_error"],
            ok=False
        )
        return hsts, {"status": "unknown", "eligible": False}

    # Parse HSTS header
    hsts = validate_hsts(resp.headers)

    # Load preload list
    preload_data = download_preload_list(timeout)
    status = check_in_preload_list(preload_data, domain)

    # Preload eligibility (Chrome spec)
    eligible = (
        hsts.present
        and hsts.max_age is not None
        and hsts.max_age >= 31536000
        and hsts.include_subdomains
        and hsts.preload
        and not hsts.issues
    )

    return hsts, {"status": status, "eligible": eligible}
