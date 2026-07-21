"""Async client for the PyPI JSON API."""

from __future__ import annotations

from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any

import httpx
from packaging.version import InvalidVersion, Version

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
PYPI_JSON_VERSION_URL = "https://pypi.org/pypi/{name}/{version}/json"
_MAX_INLINE_LICENSE_LENGTH = 100


@dataclass
class ReleaseInfo:
    """A single available release of a package."""

    version: Version
    requires_python: str | None


@dataclass
class PackageInfo:
    """All available, non-yanked, non-prerelease releases of a package."""

    name: str
    releases: list[ReleaseInfo] = field(default_factory=list)
    license: str | None = None
    requires_dist: list[str] = field(default_factory=list)
    error: str | None = None


def _is_available(files: list[dict[str, Any]]) -> bool:
    return bool(files) and any(not file.get("yanked", False) for file in files)


def _requires_python(files: list[dict[str, Any]]) -> str | None:
    return next(
        (file["requires_python"] for file in files if file.get("requires_python")),
        None,
    )


def _extract_license(info: dict[str, Any]) -> str | None:
    # PyPI's `license` field is inconsistently populated: sometimes a short
    # SPDX-like identifier ("MIT"), sometimes the full license text, sometimes
    # empty. Fall back to the "License ::" trove classifier when it's unusable.
    raw_license = info.get("license")
    if (
        isinstance(raw_license, str)
        and raw_license
        and len(raw_license) < _MAX_INLINE_LICENSE_LENGTH
        and "\n" not in raw_license
    ):
        return raw_license.strip()
    for classifier in info.get("classifiers", []):
        if isinstance(classifier, str) and classifier.startswith("License :: "):
            return classifier.rsplit(" :: ", 1)[-1]
    return None


async def _fetch_pinned_info(
    client: httpx.AsyncClient,
    name: str,
    version: str,
) -> dict[str, Any] | None:
    """Fetch the `info` object for one exact release (not the latest)."""
    try:
        response = await client.get(
            PYPI_JSON_VERSION_URL.format(name=name, version=version),
            timeout=10.0,
        )
    except httpx.HTTPError:
        return None
    if response.status_code != HTTPStatus.OK:
        return None
    result: dict[str, Any] = response.json().get("info", {})
    return result


async def fetch_versions(
    client: httpx.AsyncClient,
    name: str,
    pinned_version: str | None = None,
) -> PackageInfo:
    """Fetch all available releases of `name` from the PyPI JSON API.

    `license` and `requires_dist` describe `pinned_version` specifically when
    given (a separate request, since PyPI's unversioned endpoint always
    reflects the *latest* release, not the one actually in use) — falling
    back to the latest release's metadata otherwise.
    """
    try:
        response = await client.get(PYPI_JSON_URL.format(name=name), timeout=10.0)
    except httpx.HTTPError as exc:
        return PackageInfo(name=name, error=str(exc))

    if response.status_code == HTTPStatus.NOT_FOUND:
        return PackageInfo(name=name, error="Package not found on PyPI")
    if response.status_code != HTTPStatus.OK:
        return PackageInfo(
            name=name,
            error=f"PyPI returned HTTP {response.status_code}",
        )

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
        releases.append(
            ReleaseInfo(version=version, requires_python=_requires_python(files)),
        )

    info = data.get("info", {})
    if pinned_version:
        pinned_info = await _fetch_pinned_info(client, name, pinned_version)
        if pinned_info is not None:
            info = pinned_info

    return PackageInfo(
        name=name,
        releases=releases,
        license=_extract_license(info),
        requires_dist=info.get("requires_dist") or [],
    )
