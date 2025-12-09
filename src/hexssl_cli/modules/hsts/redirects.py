import requests
from .utils import DEFAULT_TIMEOUT, DEFAULT_HEADERS

def _follow(url: str, timeout=DEFAULT_TIMEOUT):
    history = []
    resp = requests.get(
        url,
        allow_redirects=True,
        timeout=timeout,
        headers=DEFAULT_HEADERS,
    )
    for h in resp.history:
        history.append((h.status_code, h.url))
    return resp.url, resp.status_code, history

def check_redirect_scenarios(domain: str, timeout=DEFAULT_TIMEOUT):
    scenarios = {
        "http_root": f"http://{domain}/",
        "http_www": f"http://www.{domain}/",
    }

    result = {}
    for name, url in scenarios.items():
        try:
            final_url, status, history = _follow(url, timeout)
            result[name] = {
                "start": url,
                "final_url": final_url,
                "status": status,
                "history": history,
                "https_enforced": final_url.startswith("https://"),
                "error": None,
            }
        except Exception as e:
            result[name] = {
                "start": url,
                "final_url": None,
                "status": None,
                "history": [],
                "https_enforced": False,
                "error": str(e),
            }

    return result
