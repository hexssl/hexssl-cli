from typing import List, Optional
from dataclasses import dataclass

@dataclass
class HSTSResult:
    present: bool
    max_age: Optional[int]
    include_subdomains: bool
    preload: bool
    issues: List[str]
    ok: bool

def validate_hsts(headers) -> HSTSResult:
    raw = headers.get("Strict-Transport-Security")
    if not raw:
        return HSTSResult(False, None, False, False, ["no_hsts_header"], False)

    parts = [p.strip() for p in raw.split(";")]
    issues = []
    max_age = None
    include_subdomains = False
    preload = False

    for part in parts:
        if part.startswith("max-age"):
            try:
                max_age = int(part.split("=")[1])
            except:
                issues.append("invalid_max_age")
        elif part.strip().lower() == "includesubdomains":
   	   include_subdomains = True
        elif part.lower() == "preload":
            preload = True

    if max_age is None:
        issues.append("missing_max_age")
    if preload and not include_subdomains:
        issues.append("preload_without_subdomains")

    ok = len(issues) == 0
    return HSTSResult(True, max_age, include_subdomains, preload, issues, ok)
