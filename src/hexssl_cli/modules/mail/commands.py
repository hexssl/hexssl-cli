import requests
import typer
from rich.console import Console

from ...core import (
    ExitCode,
    ModuleResult,
    ResultField,
    ResultIssue,
    ResultSeverity,
    ResultStatus,
    emit_result,
    status_to_exit_code,
)
from ..hsts.utils import validate_domain
from .check import inspect_mail

mail_app = typer.Typer(help="Mail diagnostics for HEXSSL-CLI")
console = Console()


@mail_app.command("check")
def check(
    domain: str = typer.Argument(..., callback=validate_domain),
    selector: str = typer.Option(..., "--selector", help="DKIM selector to query"),
    timeout: float = typer.Option(5.0, help="DNS query timeout in seconds"),
    output: str = typer.Option("text", "--format", help="Output format: text or json"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON output"),
):
    output = "json" if json_output else output.lower()
    if output not in {"text", "json"}:
        raise typer.BadParameter("Output format must be 'text' or 'json'")

    try:
        details = inspect_mail(domain=domain, selector=selector, timeout=timeout)
    except requests.RequestException as exc:
        console.print("[red]Mail DNS lookup error:[/]", exc)
        raise typer.Exit(int(ExitCode.CONNECTION_ERROR))
    except Exception as exc:
        console.print("[bold red]Fatal error:[/]", exc)
        raise typer.Exit(int(ExitCode.FATAL_ERROR))

    issues = []
    status = ResultStatus.ok
    summary = "Mail trust records look operational."

    if not details.spf_valid:
        status = ResultStatus.fail
        summary = "Mail trust records need corrective action."
        issues.append(_build_spf_issue(details.spf_issue))

    if not details.dmarc_record:
        status = ResultStatus.fail
        summary = "Mail trust records need corrective action."
        issues.append(
            ResultIssue(
                code="missing_dmarc",
                message="Publish a DMARC record at _dmarc with an enforcing policy such as p=quarantine or p=reject.",
                severity=ResultSeverity.error,
            )
        )
    elif not details.dmarc_valid:
        status = ResultStatus.fail
        summary = "Mail trust records need corrective action."
        issues.append(
            ResultIssue(
                code="malformed_dmarc",
                message="Fix the DMARC record so it includes a valid p= policy tag.",
                severity=ResultSeverity.error,
            )
        )
    elif details.dmarc_issue == "weak_policy":
        if status == ResultStatus.ok:
            status = ResultStatus.warning
            summary = "Mail trust records are present, but enforcement is weak."
        issues.append(
            ResultIssue(
                code="weak_dmarc_policy",
                message="Move DMARC from p=none to p=quarantine or p=reject after monitoring alignment.",
                severity=ResultSeverity.warning,
            )
        )

    if not details.dkim_record:
        status = ResultStatus.fail
        summary = "Mail trust records need corrective action."
        issues.append(
            ResultIssue(
                code="missing_dkim",
                message="Publish a DKIM TXT record for the selected selector before enabling signed mail.",
                severity=ResultSeverity.error,
            )
        )
    elif not details.dkim_valid:
        status = ResultStatus.fail
        summary = "Mail trust records need corrective action."
        issues.append(
            ResultIssue(
                code="malformed_dkim",
                message="Fix the DKIM TXT record so it includes v=DKIM1 and a non-empty p= public key.",
                severity=ResultSeverity.error,
            )
        )

    result = ModuleResult(
        target=domain,
        status=status,
        summary=summary,
        fields=[
            ResultField("Selector", details.selector),
            ResultField("SPF", details.spf_records),
            ResultField("DMARC Policy", details.dmarc_policy),
            ResultField("DMARC Record", details.dmarc_record),
            ResultField("DKIM Record", details.dkim_record),
        ],
        issues=issues,
        data={
            "selector": details.selector,
            "spf": {
                "records": details.spf_records,
                "valid": details.spf_valid,
                "issue": details.spf_issue,
            },
            "dmarc": {
                "record": details.dmarc_record,
                "valid": details.dmarc_valid,
                "policy": details.dmarc_policy,
                "issue": details.dmarc_issue,
            },
            "dkim": {
                "record": details.dkim_record,
                "valid": details.dkim_valid,
                "issue": details.dkim_issue,
            },
        },
    )

    emit_result(
        result=result,
        output_format=output,
        console=console,
        title="HEXSSL-CLI mail check for:",
    )
    raise typer.Exit(status_to_exit_code(result.status))


def _build_spf_issue(issue: str) -> ResultIssue:
    if issue == "multiple":
        return ResultIssue(
            code="multiple_spf",
            message="Collapse SPF into a single TXT record to avoid unpredictable receiver behavior.",
            severity=ResultSeverity.error,
        )
    if issue == "malformed":
        return ResultIssue(
            code="malformed_spf",
            message="Fix the SPF syntax so it starts with v=spf1 and contains valid mechanisms.",
            severity=ResultSeverity.error,
        )
    return ResultIssue(
        code="missing_spf",
        message="Publish a single SPF TXT record that authorizes your sending infrastructure.",
        severity=ResultSeverity.error,
    )
