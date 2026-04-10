from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ResultSeverity(str, Enum):
    info = "info"
    warning = "warning"
    error = "error"


class ResultStatus(str, Enum):
    ok = "ok"
    warning = "warning"
    fail = "fail"
    error = "error"


@dataclass
class ResultIssue:
    code: str
    message: str
    severity: ResultSeverity


@dataclass
class ResultField:
    label: str
    value: Any


@dataclass
class ModuleResult:
    target: str
    status: ResultStatus
    summary: str
    fields: List[ResultField] = field(default_factory=list)
    issues: List[ResultIssue] = field(default_factory=list)
    data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        payload["fields"] = [
            {"label": field.label, "value": field.value} for field in self.fields
        ]
        payload["issues"] = [
            {
                "code": issue.code,
                "message": issue.message,
                "severity": issue.severity.value,
            }
            for issue in self.issues
        ]
        return payload
