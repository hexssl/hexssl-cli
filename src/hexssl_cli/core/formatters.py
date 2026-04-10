from typing import Literal, Optional

from rich.console import Console
from rich.table import Table

from .models import ModuleResult, ResultSeverity


def emit_result(
    result: ModuleResult,
    output_format: Literal["text", "json"] = "text",
    console: Optional[Console] = None,
    title: Optional[str] = None,
) -> None:
    active_console = console or Console()

    if output_format == "json":
        active_console.print_json(data=result.to_dict())
        return

    render_text_result(result=result, console=active_console, title=title)


def render_text_result(
    result: ModuleResult,
    console: Console,
    title: Optional[str] = None,
) -> None:
    if title:
        console.print(f"[cyan]{title}[/] {result.target}")

    status_style = {
        "ok": "green",
        "warning": "yellow",
        "fail": "red",
        "error": "bold red",
    }[result.status.value]

    console.print(f"Status : [{status_style}]{result.status.value.upper()}[/]")
    console.print(f"Summary: {result.summary}")

    if result.fields:
        table = Table(title="Details", show_lines=True)
        table.add_column("Field")
        table.add_column("Value")

        for field in result.fields:
            table.add_row(field.label, _stringify_value(field.value))

        console.print(table)

    if result.issues:
        console.print("[bold]Findings:[/]")
        for issue in result.issues:
            style = {
                ResultSeverity.info: "cyan",
                ResultSeverity.warning: "yellow",
                ResultSeverity.error: "red",
            }[issue.severity]
            console.print(f" - [{style}]{issue.code}[/]: {issue.message}")


def _stringify_value(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) if value else "-"
    if value is None or value == "":
        return "-"
    return str(value)
