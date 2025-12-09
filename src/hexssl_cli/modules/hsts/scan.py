import requests
from typing import List, Tuple, Union

from .parser import validate_hsts
from .utils import DEFAULT_TIMEOUT, DEFAULT_HEADERS

def scan_paths(domain: str, paths: List[str], timeout=DEFAULT_TIMEOUT):
    results = []
    for p in paths:
        url = f"https://{domain}{p}"
        try:
            resp = requests.get(url, timeout=timeout, headers=DEFAULT_HEADERS)
            results.append((p, validate_hsts(resp.headers)))
        except Exception as e:
            results.append((p, f"error: {e}"))
    return results
