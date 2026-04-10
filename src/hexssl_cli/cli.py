import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .modules.cert import cert_app
from .modules.dns import dns_app
from .modules.hsts import hsts_app
from .modules.mail import mail_app
from .modules.report import report_app

app = typer.Typer(
    help="HEXSSL-CLI • Official HEXSSL command line toolkit",
    invoke_without_command=True
)

console = Console()

ASCII_LOGO = r"""
 _   _  _______   __ _____ _____ _     
| | | ||  ___\ \ / //  ___/  ___| |    
| |_| || |__  \ V / \ `--.\ `--.| |    
|  _  ||  __| /   \  `--. \`--. \ |    
| | | || |___/ /^\ \/\__/ /\__/ / |____
\_| |_/\____/\/   \/\____/\____/\_____/
"""

def print_banner():
    panel = Panel(
        Text(ASCII_LOGO, justify="center"),
        title="HEXSSL-CLI",
        border_style="cyan",
    )
    console.print(panel)

@app.callback()
def main(ctx: typer.Context):
    # Show banner only when no subcommand is invoked
    if ctx.invoked_subcommand is None:
        print_banner()
        typer.echo(ctx.get_help())
        raise typer.Exit()

# Attach modules
app.add_typer(cert_app, name="cert", help="Certificate diagnostics for HEXSSL-CLI")
app.add_typer(dns_app, name="dns", help="DNS diagnostics for HEXSSL-CLI")
app.add_typer(hsts_app, name="hsts", help="HSTS diagnostics for HEXSSL-CLI")
app.add_typer(mail_app, name="mail", help="Mail diagnostics for HEXSSL-CLI")
app.add_typer(report_app, name="report", help="Reporting utilities for HEXSSL-CLI")
