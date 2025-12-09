import typer
from rich.console import Console
from rich.table import Table

from .parser import validate_hsts, HSTSResult
from .preload import get_preload_info
from .redirects import check_redirect_scenarios
from .scan import scan_paths
from .subdomains import check_subdomains
from .audit import run_full_audit
from .utils import validate_domain

hsts_app = typer.Typer(help="HSTS diagnostics for HEXSSL-CLI")
console = Console()

@hsts_app.command("check")
def check(
    domain: str = typer.Argument(..., callback=validate_domain),
    timeout: float = 5.0
):
    console.print(f"[cyan]HEXSSL-CLI HSTS check for:[/] {domain}")
    import requests

    try:
        resp = requests.get(f"https://{domain}", timeout=timeout)
    except Exception as e:
        console.print("[red]TLS/connection error:[/]", e)
        raise typer.Exit(1)

    result = validate_hsts(resp.headers)

    if not result.present:
        console.print("[bold red]FAIL — no HSTS header[/]")
        raise typer.Exit(1)

    if result.ok:
        console.print("[green]HSTS OK[/]")
    else:
        console.print("[yellow]Issues detected:[/]")
        for issue in result.issues:
            console.print(f" - {issue}")
        raise typer.Exit(2)

@hsts_app.command("preload")
def preload(domain: str = typer.Argument(..., callback=validate_domain)):
    console.print(f"[cyan]HEXSSL-CLI preload analysis for:[/] {domain}")
    hsts, info = get_preload_info(domain)

    table = Table(title="HEXSSL-CLI HSTS Preload Report", show_lines=True)
    table.add_column("Check")
    table.add_column("Result")

    table.add_row("HSTS OK", str(hsts.ok))
    table.add_row("includeSubDomains", str(hsts.include_subdomains))
    table.add_row("preload flag", str(hsts.preload))
    table.add_row("Preload list", info["status"])
    table.add_row("Eligible", str(info["eligible"]))

    console.print(table)

@hsts_app.command("redirects")
def redirects(domain: str = typer.Argument(..., callback=validate_domain)):
    console.print(f"[cyan]HEXSSL-CLI redirect analysis for:[/] {domain}")
    data = check_redirect_scenarios(domain)

    table = Table(title="HEXSSL-CLI Redirect Report", show_lines=True)
    table.add_column("Scenario")
    table.add_column("Start")
    table.add_column("Final")
    table.add_column("Status")
    table.add_column("HTTPS Enforced")

    for name, info in data.items():
        table.add_row(
            name,
            info["start"],
            info["final_url"] or "-",
            str(info["status"]),
            "yes" if info["https_enforced"] else "no"
        )

    console.print(table)

@hsts_app.command("scan")
def scan(
    domain: str = typer.Argument(..., callback=validate_domain),
    paths: str = typer.Option("/", help="Comma separated paths")
):
    console.print(f"[cyan]HEXSSL-CLI HSTS multi-path scan for:[/] {domain}")

    paths_list = [p.strip() for p in paths.split(",") if p.strip()]
    results = scan_paths(domain, paths_list)

    table = Table(title="HEXSSL-CLI HSTS Path Scan", show_lines=True)
    table.add_column("Path")
    table.add_column("Status")

    for path, res in results:
        if isinstance(res, str):
            table.add_row(path, f"[red]{res}")
        elif isinstance(res, HSTSResult) and res.ok:
            table.add_row(path, "[green]OK[/]")
        else:
            table.add_row(path, f"[yellow]{', '.join(res.issues)}")

    console.print(table)

@hsts_app.command("subdomains")
def subdomains(domain: str = typer.Argument(..., callback=validate_domain)):
    console.print(f"[cyan]HEXSSL-CLI subdomain analysis for:[/] {domain}")

    subs = check_subdomains(domain)

    table = Table(title="HEXSSL-CLI Subdomain Analysis", show_lines=True)
    table.add_column("Host")
    table.add_column("Status")
    table.add_column("Details")

    for host, status, res in subs:
        if status == "no_dns":
            table.add_row(host, "no_dns", "-")
        elif status == "error":
            table.add_row(host, "error", str(res))
        elif isinstance(res, HSTSResult) and res.ok:
            table.add_row(host, "ok", "")
        else:
            table.add_row(host, "issues", ", ".join(res.issues))

    console.print(table)

@hsts_app.command("audit")
def audit(domain: str = typer.Argument(..., callback=validate_domain)):
    console.print(f"[cyan]HEXSSL-CLI full HSTS audit for:[/] {domain}")

result = run_full_audit(domain)

    if "error" in audit:
        console.print(f"[red]{audit['error']}[/]")
        raise typer.Exit(1)

    console.print("\n[bold cyan]HEXSSL-CLI HSTS Audit Summary[/]")
    console.print(f"Grade : {audit['grade']}")
    console.print(f"Status: {audit['overall_status']}")

    console.print("\n[bold]HSTS header:[/]")
    hsts = audit["hsts"]
    if hsts.ok:
        console.print("[green]OK[/]")
    else:
        for issue in hsts.issues:
            console.print(f" - {issue}")
