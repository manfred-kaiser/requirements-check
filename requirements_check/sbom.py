"""CycloneDX SBOM (Software Bill of Materials) export."""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from . import __version__

if TYPE_CHECKING:
    from .models import AnalysisResult, Dependency, Vulnerability

CYCLONEDX_SPEC_VERSION = "1.6"


def _purl(name: str, version: str) -> str:
    normalized = re.sub(r"[-_.]+", "-", name).lower()
    return f"pkg:pypi/{normalized}@{version}"


def _component(dep: Dependency) -> dict[str, Any]:
    purl = _purl(dep.name, dep.pinned_version or "")
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": purl,
        "purl": purl,
        "name": dep.name,
        "version": dep.pinned_version,
    }
    if dep.license:
        component["licenses"] = [{"license": {"name": dep.license}}]
    return component


def _vulnerability(dep: Dependency, vuln: Vulnerability) -> dict[str, Any]:
    purl = _purl(dep.name, dep.pinned_version or "")
    entry: dict[str, Any] = {
        "id": vuln.id,
        "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vuln.id}"},
        "description": vuln.summary,
        "affects": [{"ref": purl}],
    }
    if vuln.aliases:
        entry["references"] = [
            {"id": alias, "source": {"name": "OSV"}} for alias in vuln.aliases
        ]

    properties = []
    if vuln.severity:
        properties.append(
            {"name": "requirements-check:osv_severity", "value": vuln.severity},
        )
    if vuln.fixed_version:
        properties.append(
            {"name": "requirements-check:fixed_version", "value": vuln.fixed_version},
        )
    if properties:
        entry["properties"] = properties

    return entry


def render_cyclonedx(result: AnalysisResult) -> str:
    """Render `result` as a CycloneDX 1.6 JSON SBOM.

    Only dependencies with a pinned version become components — an SBOM
    describes a concrete build, so unpinned or unresolvable entries (which
    have no single "version actually in use") are excluded.
    """
    pinned = [dep for dep in result.dependencies if dep.pinned_version]

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "requirements-check",
                        "version": __version__,
                    },
                ],
            },
        },
        "components": [_component(dep) for dep in pinned],
    }

    vulnerabilities = [
        _vulnerability(dep, vuln) for dep in pinned for vuln in dep.vulnerabilities
    ]
    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities

    return json.dumps(bom, indent=2)
