import socket
import ssl

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
from .check import inspect_certificate

cert_app = typer.Typer(help="Certificate diagnostics for HEXSSL-CLI")
console = Console()


@cert_app.command("check")
def check(
    target: str = typer.Argument(..., callback=validate_domain),
    timeout: float = typer.Option(5.0, help="Socket timeout in seconds"),
    output: str = typer.Option("text", "--format", help="Output format: text or json"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON output"),
):
    output = "json" if json_output else output.lower()
    if output not in {"text", "json"}:
        raise typer.BadParameter("Output format must be 'text' or 'json'")

    try:
        details = inspect_certificate(hostname=target, timeout=timeout)
    except (socket.gaierror, socket.timeout, ConnectionError, OSError) as exc:
        console.print("[red]Connection error:[/]", exc)
        raise typer.Exit(int(ExitCode.CONNECTION_ERROR))
    except ssl.SSLError as exc:
        console.print("[red]TLS error:[/]", exc)
        raise typer.Exit(int(ExitCode.CONNECTION_ERROR))
    except Exception as exc:
        console.print("[bold red]Fatal error:[/]", exc)
        raise typer.Exit(int(ExitCode.FATAL_ERROR))

    issues = []
    status = ResultStatus.ok
    summary = "Certificate is valid for the requested host."

    if details.days_remaining is not None and details.days_remaining < 0:
        status = ResultStatus.fail
        summary = "Certificate has expired."
        issues.append(
            ResultIssue(
                code="certificate_expired",
                message=f"Certificate expired {abs(details.days_remaining)} day(s) ago.",
                severity=ResultSeverity.error,
            )
        )
    elif details.days_remaining is not None and details.days_remaining <= 30:
        status = ResultStatus.warning
        summary = "Certificate is approaching expiry."
        issues.append(
            ResultIssue(
                code="certificate_expiring_soon",
                message=f"Certificate expires in {details.days_remaining} day(s).",
                severity=ResultSeverity.warning,
            )
        )

    if not details.hostname_valid:
        status = ResultStatus.fail
        summary = "Certificate does not match the requested hostname."
        issues.append(
            ResultIssue(
                code="hostname_mismatch",
                message=details.hostname_error or "Hostname validation failed.",
                severity=ResultSeverity.error,
            )
        )

    if not details.chain_ok:
        status = ResultStatus.fail
        summary = "Certificate chain could not be verified."
        issues.append(
            ResultIssue(
                code="chain_verification_failed",
                message=details.chain_error or "The peer certificate chain is not trusted.",
                severity=ResultSeverity.error,
            )
        )

    result = ModuleResult(
        target=target,
        status=status,
        summary=summary,
        fields=[
            ResultField("Issuer", details.issuer),
            ResultField("Expires", details.not_after),
            ResultField("Days Remaining", details.days_remaining),
            ResultField("Hostname Validation", "ok" if details.hostname_valid else "failed"),
            ResultField("Chain Verdict", details.chain_verdict),
            ResultField("SANs", details.sans),
        ],
        issues=issues,
        data={
            "issuer": details.issuer,
            "sans": details.sans,
            "expires": details.not_after,
            "days_remaining": details.days_remaining,
            "hostname_valid": details.hostname_valid,
            "chain_verdict": details.chain_verdict,
        },
    )

    emit_result(
        result=result,
        output_format=output,
        console=console,
        title="HEXSSL-CLI certificate check for:",
    )
    raise typer.Exit(status_to_exit_code(result.status))
