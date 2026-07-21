"""Table and JSON rendering of an AnalysisResult."""

from __future__ import annotations

import io
import json
from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table

from .models import AnalysisResult, UpdateLevel

if TYPE_CHECKING:
    from .models import Dependency

_LEVEL_STYLE = {
    UpdateLevel.PATCH: "cyan",
    UpdateLevel.MINOR: "yellow",
    UpdateLevel.MAJOR: "red",
    UpdateLevel.UNPINNED: "magenta",
    UpdateLevel.UNSUPPORTED: "dim",
    UpdateLevel.NOT_FOUND: "red",
}

# Only exceptional states get a Note; NONE/PATCH/MINOR/MAJOR are already
# fully conveyed by the Patch/Minor/Major columns and would just repeat them.
_NOTE_LABEL = {
    UpdateLevel.UNPINNED: "unpinned",
    UpdateLevel.UNSUPPORTED: "unsupported",
    UpdateLevel.NOT_FOUND: "not found",
}

_FIX_LABEL = {
    UpdateLevel.PATCH: "patch fixes",
    UpdateLevel.MINOR: "minor needed",
    UpdateLevel.MAJOR: "major needed",
    UpdateLevel.NO_FIX: "no fix yet",
}

_FIX_STYLE = {
    UpdateLevel.PATCH: "green",
    UpdateLevel.MINOR: "yellow",
    UpdateLevel.MAJOR: "red",
    UpdateLevel.NO_FIX: "red",
}


def _dedupe_update_columns(
    dep: Dependency,
) -> tuple[str, str, str]:
    """Blank out a wider-scope column when it repeats the value shown to its left.

    `latest_minor` is always within `latest_major`'s scope and `latest_patch`
    within `latest_minor`'s, so identical values just mean "no further update
    at that scope" — repeating the same version three times reads as a typo
    to compare rather than a signal that there's nothing more to gain.
    """
    columns = (dep.latest_patch, dep.latest_minor, dep.latest_major)
    displayed = []
    last_shown = None
    for version in columns:
        if version is not None and version == last_shown:
            displayed.append("-")
        else:
            displayed.append(version or "-")
            if version is not None:
                last_shown = version
    return displayed[0], displayed[1], displayed[2]


def _build_note(dep: Dependency) -> str:
    parts = []
    label = _NOTE_LABEL.get(dep.update_level)
    if label:
        parts.append(label)
    if dep.error:
        parts.append(f"({dep.error})")
    if (
        dep.constraint
        and dep.best_within_constraint
        and dep.latest_major
        and dep.best_within_constraint != dep.latest_major
    ):
        parts.append(
            f"capped by constraint {dep.constraint} (max: {dep.best_within_constraint})",
        )
    if dep.locked_to and dep.locked_by:
        parts.append(f"locked to {dep.locked_to} by {dep.locked_by}")
    return " ".join(parts) or "-"


def _build_source_cell(dep: Dependency) -> str:
    """Build a bulleted list, one item per source, with its own range in parens."""
    if not dep.sources:
        return "-"
    lines = []
    for source in dep.sources:
        specifier = dep.source_specifiers.get(source)
        label = f"{source} ({specifier})" if specifier else source
        lines.append(f"• {label}")
    return "\n".join(lines)


def render_table(result: AnalysisResult, console: Console | None = None) -> None:
    """Print `result` as a Rich table."""
    console = console or Console()
    table = Table(title="requirements-check", show_lines=True)
    table.add_column("Package")
    table.add_column("Pinned")
    table.add_column("Patch")
    table.add_column("Minor")
    table.add_column("Major")
    show_sources = any(dep.sources for dep in result.dependencies)
    if show_sources:
        table.add_column("Source")
    table.add_column("Note")
    table.add_column("Vulnerabilities")

    for dep in result.dependencies:
        style = _LEVEL_STYLE.get(dep.update_level, "")
        note = _build_note(dep)

        if dep.vulnerabilities:
            fix_level = dep.vulnerability_fix_level
            fix_style = _FIX_STYLE.get(fix_level, "red") if fix_level else "red"
            fix_label = _FIX_LABEL.get(fix_level, "unknown") if fix_level else "unknown"
            vulns = f"[red]{len(dep.vulnerabilities)} known[/red] [{fix_style}]({fix_label})[/{fix_style}]"
        elif dep.pinned_version is None and not dep.error:
            # An empty vulnerabilities list here doesn't mean "checked, clean" —
            # OSV needs an exact version, so this dependency was never queried.
            # Showing a bare "-" would look identical to an actually-clean one.
            vulns = "[dim]not checked (no pinned version)[/dim]"
        else:
            vulns = "-"

        patch, minor, major = _dedupe_update_columns(dep)
        row = [
            dep.name,
            dep.pinned_version or "-",
            patch,
            minor,
            major,
        ]
        if show_sources:
            row.append(_build_source_cell(dep))
        row.append(f"[{style}]{note}[/{style}]" if style else note)
        row.append(vulns)
        table.add_row(*row)

    console.print(table)

    if result.missing_transitive_dependencies:
        names = ", ".join(result.missing_transitive_dependencies)
        console.print(
            f"[yellow]⚠ {len(result.missing_transitive_dependencies)} "
            f"dependencies declared by your pinned packages aren't listed in "
            f"this file: {names}[/yellow]\n"
            "[yellow]  This requirements.txt may not be fully resolved — "
            "consider generating it with pip-compile or a similar tool "
            "(see --no-transitive-check to silence this).[/yellow]",
        )


def render_vulnerability_details(
    result: AnalysisResult,
    console: Console | None = None,
) -> None:
    """Print one row per known vulnerability, with ID, severity, and fix info."""
    console = console or Console()
    table = Table(title="Vulnerability details", show_lines=True)
    table.add_column("Package")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Fix")
    table.add_column("Summary")
    table.add_column("Aliases")

    for dep in result.dependencies:
        for vuln in dep.vulnerabilities:
            fix_style = (
                _FIX_STYLE.get(vuln.fix_level, "red") if vuln.fix_level else "red"
            )
            fix_label = (
                _FIX_LABEL.get(vuln.fix_level, "unknown")
                if vuln.fix_level
                else "no fix yet"
            )
            fix = f"[{fix_style}]{fix_label}[/{fix_style}]"
            if vuln.fixed_version:
                fix += f" ({vuln.fixed_version})"

            table.add_row(
                dep.name,
                vuln.id,
                vuln.severity or "-",
                fix,
                vuln.summary,
                ", ".join(vuln.aliases) or "-",
            )

    if table.row_count == 0:
        console.print("No known vulnerabilities.")
        return

    console.print(table)


def render_html(result: AnalysisResult, *, list_vulnerabilities: bool = False) -> str:
    """Render `result` as a self-contained HTML report."""
    # file=io.StringIO() keeps console.print() from also writing to real
    # stdout — record=True alone only adds recording, it doesn't silence it.
    console = Console(record=True, width=120, file=io.StringIO())
    render_table(result, console=console)
    if list_vulnerabilities:
        render_vulnerability_details(result, console=console)
    return console.export_html(inline_styles=True)


def render_json(result: AnalysisResult) -> str:
    """Render `result` as an indented JSON string."""
    return json.dumps(result.to_dict(), indent=2)
