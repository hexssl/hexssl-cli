import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .modules.hsts import hsts_app

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
app.add_typer(hsts_app, name="hsts", help="HSTS diagnostics for HEXSSL-CLI")
