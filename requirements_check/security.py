from __future__ import annotations

import asyncio

import httpx

from .models import Dependency, Vulnerability

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"


async def _fetch_vuln_detail(client: httpx.AsyncClient, vuln_id: str) -> Vulnerability | None:
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

    return Vulnerability(
        id=data.get("id", vuln_id),
        summary=(data.get("summary") or data.get("details") or "")[:200],
        severity=severity,
        aliases=data.get("aliases", []),
    )


async def check_vulnerabilities(
    client: httpx.AsyncClient, dependencies: list[Dependency]
) -> dict[str, list[Vulnerability]]:
    eligible = [dep for dep in dependencies if dep.pinned_version]
    if not eligible:
        return {}

    queries = [
        {"package": {"name": dep.name, "ecosystem": "PyPI"}, "version": dep.pinned_version}
        for dep in eligible
    ]

    try:
        response = await client.post(
            OSV_BATCH_URL, json={"queries": queries}, timeout=15.0
        )
        response.raise_for_status()
    except httpx.HTTPError:
        return {}

    results = response.json().get("results", [])

    per_dep_ids: dict[str, list[str]] = {}
    vuln_ids: set[str] = set()
    for dep, result in zip(eligible, results):
        ids = [vuln["id"] for vuln in result.get("vulns", [])]
        if ids:
            per_dep_ids[dep.name] = ids
            vuln_ids.update(ids)

    if not vuln_ids:
        return {}

    details = await asyncio.gather(
        *(_fetch_vuln_detail(client, vuln_id) for vuln_id in vuln_ids)
    )
    detail_map = {detail.id: detail for detail in details if detail is not None}

    return {
        name: [detail_map[vuln_id] for vuln_id in ids if vuln_id in detail_map]
        for name, ids in per_dep_ids.items()
    }
