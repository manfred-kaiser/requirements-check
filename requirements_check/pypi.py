from __future__ import annotations

from dataclasses import dataclass, field

import httpx
from packaging.version import InvalidVersion, Version

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"


@dataclass
class ReleaseInfo:
    version: Version
    requires_python: str | None


@dataclass
class PackageInfo:
    name: str
    releases: list[ReleaseInfo] = field(default_factory=list)
    error: str | None = None


def _is_available(files: list[dict]) -> bool:
    return bool(files) and any(not file.get("yanked", False) for file in files)


def _requires_python(files: list[dict]) -> str | None:
    return next((file["requires_python"] for file in files if file.get("requires_python")), None)


async def fetch_versions(client: httpx.AsyncClient, name: str) -> PackageInfo:
    try:
        response = await client.get(PYPI_JSON_URL.format(name=name), timeout=10.0)
    except httpx.HTTPError as exc:
        return PackageInfo(name=name, error=str(exc))

    if response.status_code == 404:
        return PackageInfo(name=name, error="Package not found on PyPI")
    if response.status_code != 200:
        return PackageInfo(name=name, error=f"PyPI returned HTTP {response.status_code}")

    data = response.json()
    releases: list[ReleaseInfo] = []
    for version_str, files in data.get("releases", {}).items():
        if not _is_available(files):
            continue
        try:
            version = Version(version_str)
        except InvalidVersion:
            continue
        if version.is_prerelease or version.is_devrelease:
            continue
        releases.append(ReleaseInfo(version=version, requires_python=_requires_python(files)))

    return PackageInfo(name=name, releases=releases)
