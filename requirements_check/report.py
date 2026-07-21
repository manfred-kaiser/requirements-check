from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from .models import AnalysisResult, UpdateLevel

_LEVEL_STYLE = {
    UpdateLevel.NONE: "green",
    UpdateLevel.PATCH: "cyan",
    UpdateLevel.MINOR: "yellow",
    UpdateLevel.MAJOR: "red",
    UpdateLevel.UNPINNED: "magenta",
    UpdateLevel.UNSUPPORTED: "dim",
    UpdateLevel.NOT_FOUND: "red",
}

_LEVEL_LABEL = {
    UpdateLevel.NONE: "up to date",
    UpdateLevel.PATCH: "patch update",
    UpdateLevel.MINOR: "minor update",
    UpdateLevel.MAJOR: "major update",
    UpdateLevel.UNPINNED: "unpinned",
    UpdateLevel.UNSUPPORTED: "unsupported",
    UpdateLevel.NOT_FOUND: "not found",
}


def render_table(result: AnalysisResult, console: Console | None = None) -> None:
    console = console or Console()
    table = Table(title="requirements-check")
    table.add_column("Package")
    table.add_column("Pinned")
    table.add_column("Patch")
    table.add_column("Minor")
    table.add_column("Major")
    table.add_column("Status")
    table.add_column("Vulnerabilities")

    for dep in result.dependencies:
        style = _LEVEL_STYLE.get(dep.update_level, "")
        status = _LEVEL_LABEL.get(dep.update_level, dep.update_level.value)
        if dep.error:
            status = f"{status} ({dep.error})"

        vulns = (
            f"[red]{len(dep.vulnerabilities)} known[/red]"
            if dep.vulnerabilities
            else "-"
        )

        table.add_row(
            dep.name,
            dep.pinned_version or "-",
            dep.latest_patch or "-",
            dep.latest_minor or "-",
            dep.latest_major or "-",
            f"[{style}]{status}[/{style}]" if style else status,
            vulns,
        )

    console.print(table)


def render_json(result: AnalysisResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
