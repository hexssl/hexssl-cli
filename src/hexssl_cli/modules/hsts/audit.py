from typing import List, Tuple, Dict, Any
from .parser import validate_hsts, HSTSResult
from .redirects import check_redirect_scenarios
from .subdomains import check_subdomains


def run_full_audit(domain: str) -> Dict[str, Any]:
    """
    Perform a complete HSTS audit:
    - Validate HSTS header on the root domain
    - Evaluate redirect policy strictness
    - Inspect subdomains for HSTS chain consistency
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
    # 3. Subdomains
    # -----------------------------------------
    try:
        subs = check_subdomains(domain)
        result["subdomains"] = subs
    except Exception as e:
        return {"error": f"Subdomain analysis failed: {str(e)}"}

    # -----------------------------------------
    # 4. Scoring model
    # -----------------------------------------

    grade = "A"
    issues = []

    # HSTS header score
    if isinstance(hsts, HSTSResult) and not hsts.ok:
        issues.extend(hsts.issues)
        grade = "C"

    # Redirect enforcement check
    if any(not r.get("https_enforced", False) for r in redirects.values()):
        issues.append("redirect_not_enforced")
        grade = "B"

    # Subdomain issues
    if any(s[1] == "error" for s in subs):
        issues.append("subdomain_error")
        grade = "B"

    result["grade"] = grade
    result["overall_status"] = "ok" if grade == "A" else "issues"
    result["issues"] = issues

    return result
