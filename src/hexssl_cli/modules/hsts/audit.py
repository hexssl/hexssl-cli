from typing import List, Tuple, Dict, Any
from .parser import validate_hsts, HSTSResult
from .redirects import check_redirect_scenarios
from .subdomains import check_subdomains


def run_full_audit(domain: str) -> Dict[str, Any]:
    """
    Perform a complete HSTS audit:
    - Validate HSTS header on root path
    - Check redirect scenarios
    - Evaluate subdomains for HSTS coverage
    """

    result: Dict[str, Any] = {}

    # -----------------------------------------
    # 1. Root-level HSTS header
    # -----------------------------------------
    try:
        import requests
        response = requests.get(f"https://{domain}", timeout=5)
        hsts = validate_hsts(response.headers)
        result["hsts"] = hsts
    except Exception as e:
        return {"error": f"HSTS root check failed: {str(e)}"}

    # -----------------------------------------
    # 2. Redirect scenarios
    # -----------------------------------------
    try:
        redirects = check_redirect_scenarios(domain)
        result["redirects"] = redirects
    except Exception as e:
        return {"error": f"Redirect analysis failed: {str(e)}"}

    # -----------------------------------------
    # 3. Subdomains HSTS evaluation
    # -----------------------------------------
    try:
        subs = check_subdomains(domain)
        result["subdomains"] = subs
    except Exception as e:
        return {"error": f"Subdomain analysis failed: {str(e)}"}

    # -----------------------------------------
    # Overall scoring
    # -----------------------------------------

    # Grade logic (simplified)
    grade = "A"
    issues = []

    # HSTS issues
    if isinstance(hsts, HSTSResult) and not hsts.ok:
        grade = "C"
        issues.extend(hsts.issues)

    # Redirect issues
    if any(not r.get("https_enforced", False) for r in redirects):
        grade = "B"
        issues.append("redirect_not_enforced")

    # Subdomain issues
    if any("error" in str(s[1]).lower() for s in subs):
        grade = "B"
        issues.append("subdomain_error")

    result["grade"] = grade
    result["overall_status"] = "ok" if grade == "A" else "issues"
    result["issues"] = issues

    return result
