"""Async client for the OSV.dev vulnerability database."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version

from .models import Dependency, UpdateLevel, Vulnerability

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"


def _event_bounds(
    events: list[dict[str, Any]],
) -> tuple[Version | None, Version | None]:
    introduced: Version | None = None
    fixed: Version | None = None
    for event in events:
        try:
            if "introduced" in event and event["introduced"] != "0":
                introduced = Version(event["introduced"])
            elif "fixed" in event:
                fixed = Version(event["fixed"])
        except InvalidVersion:
            continue
    return introduced, fixed


def _fixed_version_in_range(
    version_range: dict[str, Any],
    pinned: Version,
) -> str | None:
    if version_range.get("type") != "ECOSYSTEM":
        return None

    introduced, fixed = _event_bounds(version_range.get("events", []))
    if introduced is not None and pinned < introduced:
        return None
    if fixed is not None and pinned >= fixed:
        return None
    return str(fixed) if fixed is not None else None


def _fixed_version_for(data: dict[str, Any], pinned: Version) -> str | None:
    """Find the 'fixed' version of the affected range that actually covers `pinned`."""
    for affected in data.get("affected", []):
        if affected.get("package", {}).get("ecosystem") != "PyPI":
            continue
        for version_range in affected.get("ranges", []):
            fixed_version = _fixed_version_in_range(version_range, pinned)
            if fixed_version is not None:
                return fixed_version
    return None


def _fix_level_for(pinned: Version, fixed_version: str | None) -> UpdateLevel | None:
    if fixed_version is None:
        return None
    fixed = Version(fixed_version)
    if fixed.major != pinned.major:
        return UpdateLevel.MAJOR
    if fixed.minor != pinned.minor:
        return UpdateLevel.MINOR
    return UpdateLevel.PATCH


def _find_root(parent: dict[str, str], node: str) -> str:
    while parent.get(node, node) != node:
        node = parent[node]
    return node


def _dedupe_by_alias(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """Merge records that alias each other.

    OSV lists the same advisory under multiple IDs, e.g. a GHSA-* and a
    PYSEC-* entry for the same issue.
    """
    known_ids = {vuln.id for vuln in vulns}
    parent: dict[str, str] = {}
    for vuln in vulns:
        for alias in vuln.aliases:
            if alias in known_ids:
                parent[_find_root(parent, vuln.id)] = _find_root(parent, alias)

    groups: dict[str, list[Vulnerability]] = {}
    for vuln in vulns:
        groups.setdefault(_find_root(parent, vuln.id), []).append(vuln)

    deduped = []
    for group in groups.values():
        canonical = next((v for v in group if v.id.startswith("GHSA-")), group[0])
        merged_aliases = sorted(
            {alias for v in group for alias in (*v.aliases, v.id)} - {canonical.id},
        )
        deduped.append(replace(canonical, aliases=merged_aliases))
    return deduped


async def _fetch_vuln_detail(
    client: httpx.AsyncClient,
    vuln_id: str,
    pinned: Version,
) -> Vulnerability | None:
    try:
        response = await client.get(OSV_VULN_URL.format(id=vuln_id), timeout=10.0)
        response.raise_for_status()
    except httpx.HTTPError:
        return None

    data = response.json()
    severity = None
    severities = data.get("severity") or []
    if severities:
        severity = severities[0].get("score")

    fixed_version = _fixed_version_for(data, pinned)

    return Vulnerability(
        id=data.get("id", vuln_id),
        summary=(data.get("summary") or data.get("details") or "")[:200],
        severity=severity,
        aliases=data.get("aliases", []),
        fixed_version=fixed_version,
        fix_level=_fix_level_for(pinned, fixed_version),
    )


async def check_vulnerabilities(
    client: httpx.AsyncClient,
    dependencies: list[Dependency],
) -> dict[str, list[Vulnerability]]:
    """Look up known vulnerabilities for each dependency's pinned version via OSV.dev."""
    eligible = [dep for dep in dependencies if dep.pinned_version]
    if not eligible:
        return {}

    queries = [
        {
            "package": {"name": dep.name, "ecosystem": "PyPI"},
            "version": dep.pinned_version,
        }
        for dep in eligible
    ]

    try:
        response = await client.post(
            OSV_BATCH_URL,
            json={"queries": queries},
            timeout=15.0,
        )
        response.raise_for_status()
    except httpx.HTTPError:
        return {}

    results = response.json().get("results", [])

    per_dep_ids: dict[str, list[str]] = {}
    id_to_pinned: dict[str, Version] = {}
    for dep, result in zip(eligible, results, strict=True):
        if dep.pinned_version is None:
            continue
        ids = [vuln["id"] for vuln in result.get("vulns", [])]
        if not ids:
            continue
        per_dep_ids[dep.name] = ids
        pinned = Version(dep.pinned_version)
        for vuln_id in ids:
            id_to_pinned[vuln_id] = pinned

    if not id_to_pinned:
        return {}

    details = await asyncio.gather(
        *(
            _fetch_vuln_detail(client, vuln_id, pinned)
            for vuln_id, pinned in id_to_pinned.items()
        ),
    )
    detail_map = {detail.id: detail for detail in details if detail is not None}

    return {
        name: _dedupe_by_alias(
            [detail_map[vuln_id] for vuln_id in ids if vuln_id in detail_map],
        )
        for name, ids in per_dep_ids.items()
    }
