"""Command-line interface for requirements-check."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console

from .analyzer import Analyzer
from .report import render_html, render_json, render_table, render_vulnerability_details
from .sbom import render_cyclonedx

if TYPE_CHECKING:
    from .models import AnalysisResult

EXIT_VULNERABILITY_FOUND = 1
EXIT_USAGE_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="requirements-check",
        description="Check a requirements.txt file for outdated dependencies and known vulnerabilities.",
    )
    parser.add_argument(
        "file",
        nargs="?",
        default="requirements.txt",
        help="Path to requirements.txt",
    )
    output_format = parser.add_mutually_exclusive_group()
    output_format.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON",
    )
    output_format.add_argument(
        "--sbom",
        action="store_true",
        help="Output a CycloneDX 1.6 JSON SBOM instead of a table",
    )
    output_format.add_argument(
        "--html",
        action="store_true",
        help="Output a self-contained HTML report instead of a table",
    )
    parser.add_argument(
        "--no-security",
        action="store_true",
        help="Skip the OSV.dev vulnerability check",
    )
    parser.add_argument(
        "--no-transitive-check",
        action="store_true",
        help="Skip warning about dependencies declared by your pinned packages "
        "that aren't listed in this file",
    )
    parser.add_argument(
        "--list-vulnerabilities",
        action="store_true",
        help="List each known vulnerability individually (ID, severity, fix, summary)",
    )
    parser.add_argument(
        "--fail-on-vulnerability",
        action="store_true",
        help="Exit with status 1 if any known vulnerability is found",
    )
    parser.add_argument(
        "--constraints",
        help="Path to a loose, unresolved requirements file (e.g. a pip-compile "
        ".in source) to cross-check suggestions against your own version "
        "ceilings; defaults to FILE with a .in extension, if present",
    )
    parser.add_argument(
        "--python-version",
        help="Target Python version (e.g. 3.11) for requires-python compatibility "
        "checks; defaults to the running interpreter's version",
    )
    parser.add_argument(
        "--proxy",
        help="HTTP(S) proxy URL to use for PyPI/OSV requests "
        "(overrides HTTP_PROXY/HTTPS_PROXY env vars)",
    )
    parser.add_argument(
        "--ca-bundle",
        help="Path to a custom CA bundle file for TLS verification "
        "(e.g. for corporate TLS-intercepting proxies)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored/styled table output (also honors the NO_COLOR env var)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Write the report to this file instead of stdout",
    )
    return parser


def _render_content(result: AnalysisResult, args: argparse.Namespace) -> str | None:
    """Render json/sbom/html to a string, or None if the table format applies."""
    if args.json:
        return render_json(result)
    if args.sbom:
        return render_cyclonedx(result)
    if args.html:
        return render_html(result, list_vulnerabilities=args.list_vulnerabilities)
    return None


def _render_table_to_console(
    result: AnalysisResult,
    args: argparse.Namespace,
    console: Console,
) -> None:
    render_table(result, console=console)
    if args.list_vulnerabilities:
        render_vulnerability_details(result, console=console)


def _write_output(
    result: AnalysisResult,
    args: argparse.Namespace,
    output_path: Path | None,
) -> None:
    content = _render_content(result, args)

    if content is not None:
        if output_path:
            output_path.write_text(content, encoding="utf-8")
        else:
            print(content)
    elif output_path:
        with output_path.open("w", encoding="utf-8") as handle:
            _render_table_to_console(
                result,
                args,
                Console(no_color=args.no_color, file=handle),
            )
    else:
        _render_table_to_console(result, args, Console(no_color=args.no_color))

    if output_path:
        print(f"Wrote report to {output_path}", file=sys.stderr)


def main(argv: list[str] | None = None) -> None:
    """Parse CLI arguments, run the analysis, and print the report."""
    args = _build_parser().parse_args(argv)

    analyzer = Analyzer(
        args.file,
        check_security=not args.no_security,
        check_transitive=not args.no_transitive_check,
        constraints_path=args.constraints,
        python_version=args.python_version,
        proxy=args.proxy,
        ca_bundle=args.ca_bundle,
    )
    try:
        result = analyzer.analyze_sync()
    except FileNotFoundError:
        print(f"error: {args.file} not found", file=sys.stderr)
        raise SystemExit(EXIT_USAGE_ERROR) from None

    output_path = Path(args.output) if args.output else None
    _write_output(result, args, output_path)

    if args.fail_on_vulnerability and result.has_vulnerabilities:
        raise SystemExit(EXIT_VULNERABILITY_FOUND)


if __name__ == "__main__":
    main()
