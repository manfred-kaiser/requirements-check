"""SARIF 2.1.0 output for known vulnerabilities, for GitHub/Azure code scanning."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from . import __version__
from .models import UpdateLevel

if TYPE_CHECKING:
    from .models import AnalysisResult, Dependency, Vulnerability

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"

# No known fix (`None`) is treated as at least as severe as a major-only fix.
_LEVEL_BY_FIX_LEVEL = {
    UpdateLevel.PATCH: "note",
    UpdateLevel.MINOR: "warning",
    UpdateLevel.MAJOR: "error",
    UpdateLevel.NO_FIX: "error",
}


def _rule(vuln: Vulnerability) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": vuln.id,
        "shortDescription": {"text": vuln.summary or vuln.id},
        "helpUri": f"https://osv.dev/vulnerability/{vuln.id}",
    }
    if vuln.aliases:
        rule["properties"] = {"aliases": vuln.aliases}
    return rule


def _result(dep: Dependency, vuln: Vulnerability, source_path: str) -> dict[str, Any]:
    message = f"{dep.name} {dep.pinned_version}: {vuln.summary or vuln.id}"
    message += (
        f" (fixed in {vuln.fixed_version})"
        if vuln.fixed_version
        else " (no fix available yet)"
    )

    physical_location: dict[str, Any] = {"artifactLocation": {"uri": source_path}}
    if dep.line_number is not None:
        physical_location["region"] = {"startLine": dep.line_number}

    level = (
        _LEVEL_BY_FIX_LEVEL.get(vuln.fix_level, "error") if vuln.fix_level else "error"
    )

    return {
        "ruleId": vuln.id,
        "level": level,
        "message": {"text": message},
        "locations": [{"physicalLocation": physical_location}],
    }


def render_sarif(result: AnalysisResult, source_path: str) -> str:
    """Render known vulnerabilities as a SARIF 2.1.0 log.

    One result per vulnerability, with a location pointing at the line in
    `source_path` where the affected dependency is pinned (when known).
    Dependencies without vulnerabilities aren't represented — SARIF is for
    actionable findings, not a full inventory (use `--json` or `--sbom` for
    that).
    """
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for dep in result.dependencies:
        for vuln in dep.vulnerabilities:
            rules.setdefault(vuln.id, _rule(vuln))
            results.append(_result(dep, vuln, source_path))

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "requirements-check",
                        "informationUri": "https://github.com/manfred-kaiser/requirements-check",
                        "version": __version__,
                        "rules": list(rules.values()),
                    },
                },
                "results": results,
            },
        ],
    }
    return json.dumps(sarif, indent=2)
