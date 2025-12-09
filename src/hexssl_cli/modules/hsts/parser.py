from typing import List, Optional, Dict
from dataclasses import dataclass


@dataclass
class HSTSResult:
    present: bool
    max_age: Optional[int]
    include_subdomains: bool
    preload: bool
    issues: List[str]
    ok: bool


def validate_hsts(headers: Dict[str, str]) -> HSTSResult:
    raw = headers.get("Strict-Transport-Security") or headers.get("strict-transport-security")

    # No HSTS header
    if not raw:
        return HSTSResult(
            present=False,
            max_age=None,
            include_subdomains=False,
            preload=False,
            issues=["no_hsts_header"],
            ok=False
        )

    parts = [p.strip() for p in raw.split(";")]
    issues = []

    max_age = None
    include_subdomains = False
    preload = False

    for part in parts:
        lower = part.lower()

        if part.startswith("max-age"):
            try:
                max_age = int(part.split("=")[1])
            except Exception:
                issues.append("invalid_max_age")

        elif lower == "includesubdomains":
            include_subdomains = True

        elif lower == "preload":
            preload = True

        else:
            issues.append(f"unknown_directive:{part}")

    # Missing required directive
    if max_age is None:
        issues.append("missing_max_age")

    # Preload requires includeSubDomains
    if preload and not include_subdomains:
        issues.append("preload_without_subdomains")

    ok = len(issues) == 0

    return HSTSResult(
        present=True,
        max_age=max_age,
        include_subdomains=include_subdomains,
        preload=preload,
        issues=issues,
        ok=ok
    )
