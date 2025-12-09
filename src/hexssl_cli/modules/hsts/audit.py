from .parser import validate_hsts
from .preload import get_preload_info
from .redirects import check_redirect_scenarios
from .subdomains import check_subdomains
from .scan import scan_paths
from .utils import DEFAULT_TIMEOUT

DEFAULT_PATHS = ["/", "/login", "/api", "/admin"]

def run_full_audit(domain: str, timeout=DEFAULT_TIMEOUT):
    try:
        hsts_info, preload_info = get_preload_info(domain, timeout)
    except Exception as e:
        return {"error": f"HSTS error: {e}"}

    redirects = check_redirect_scenarios(domain, timeout)
    subs = check_subdomains(domain, timeout)
    paths = scan_paths(domain, DEFAULT_PATHS, timeout)

    grade = "A"
    if not hsts_info.ok:
        grade = "B"
    if preload_info["status"] != "preloaded":
        grade = "C"
    if any(not r["https_enforced"] for r in redirects.values()):
        grade = "D"
   if any("error" in str(s[1]).lower() for s in subs):
        grade = "D"
    if any(isinstance(p[1], str) for p in paths):
        grade = "E"

    return {
        "hsts": hsts_info,
        "preload": preload_info,
        "redirects": redirects,
        "subdomains": subs,
        "paths": paths,
        "grade": grade,
        "overall_status": "ok" if grade in ["A", "B"] else "warning",
    }
