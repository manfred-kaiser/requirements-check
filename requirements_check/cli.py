from __future__ import annotations

import argparse
import sys

from .analyzer import Analyzer
from .report import render_json, render_table


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="requirements-check",
        description="Check a requirements.txt file for outdated dependencies and known vulnerabilities.",
    )
    parser.add_argument(
        "file", nargs="?", default="requirements.txt", help="Path to requirements.txt"
    )
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    parser.add_argument(
        "--no-security", action="store_true", help="Skip the OSV.dev vulnerability check"
    )
    parser.add_argument(
        "--fail-on-vulnerability",
        action="store_true",
        help="Exit with status 1 if any known vulnerability is found",
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
    args = parser.parse_args(argv)

    analyzer = Analyzer(
        args.file,
        check_security=not args.no_security,
        python_version=args.python_version,
        proxy=args.proxy,
        ca_bundle=args.ca_bundle,
    )
    try:
        result = analyzer.analyze_sync()
    except FileNotFoundError:
        print(f"error: {args.file} not found", file=sys.stderr)
        raise SystemExit(1)

    if args.json:
        print(render_json(result))
    else:
        render_table(result)

    if args.fail_on_vulnerability and result.has_vulnerabilities:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
