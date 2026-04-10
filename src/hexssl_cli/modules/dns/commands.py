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
from .check import inspect_dns

dns_app = typer.Typer(help="DNS diagnostics for HEXSSL-CLI")
console = Console()


@dns_app.command("check")
def check(
    domain: str = typer.Argument(..., callback=validate_domain),
    timeout: float = typer.Option(5.0, help="DNS query timeout in seconds"),
    output: str = typer.Option("text", "--format", help="Output format: text or json"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON output"),
):
    output = "json" if json_output else output.lower()
    if output not in {"text", "json"}:
        raise typer.BadParameter("Output format must be 'text' or 'json'")

    try:
        details = inspect_dns(domain=domain, timeout=timeout)
    except requests.RequestException as exc:
        console.print("[red]DNS lookup error:[/]", exc)
        raise typer.Exit(int(ExitCode.CONNECTION_ERROR))
    except Exception as exc:
        console.print("[bold red]Fatal error:[/]", exc)
        raise typer.Exit(int(ExitCode.FATAL_ERROR))

    issues = []
    status = ResultStatus.ok
    summary = "DNS records look operational."

    if not details.a_records and not details.aaaa_records and not details.cname:
        status = ResultStatus.fail
        summary = "No usable apex DNS records were found."
        issues.append(
            ResultIssue(
                code="apex_unresolved",
                message="Add an A or AAAA record for the apex domain, or point it with a supported alias.",
                severity=ResultSeverity.error,
            )
        )

    if not details.caa_records:
        if status == ResultStatus.ok:
            status = ResultStatus.warning
            summary = "DNS records are present, but there are hardening gaps."
        issues.append(
            ResultIssue(
                code="missing_caa",
                message="Add a CAA record to limit which certificate authorities may issue certificates for this domain.",
                severity=ResultSeverity.warning,
            )
        )

    if not details.apex_www_consistent:
        if status == ResultStatus.ok:
            status = ResultStatus.warning
            summary = "DNS records are present, but apex/www are not aligned."
        issues.append(
            ResultIssue(
                code="www_inconsistent",
                message="Align the www host with the apex domain using matching A/AAAA records or a CNAME.",
                severity=ResultSeverity.warning,
            )
        )

    result = ModuleResult(
        target=domain,
        status=status,
        summary=summary,
        fields=[
            ResultField("A Records", details.a_records),
            ResultField("AAAA Records", details.aaaa_records),
            ResultField("CNAME", details.cname),
            ResultField("CAA", details.caa_records),
            ResultField("www A Records", details.www_a_records),
            ResultField("www AAAA Records", details.www_aaaa_records),
            ResultField("www CNAME", details.www_cname),
            ResultField("Apex/www Consistency", details.consistency_note),
        ],
        issues=issues,
        data={
            "apex": {
                "a_records": details.a_records,
                "aaaa_records": details.aaaa_records,
                "cname": details.cname,
                "caa_records": details.caa_records,
            },
            "www": {
                "a_records": details.www_a_records,
                "aaaa_records": details.www_aaaa_records,
                "cname": details.www_cname,
            },
            "apex_www_consistent": details.apex_www_consistent,
            "consistency_note": details.consistency_note,
        },
    )

    emit_result(
        result=result,
        output_format=output,
        console=console,
        title="HEXSSL-CLI DNS check for:",
    )
    raise typer.Exit(status_to_exit_code(result.status))
