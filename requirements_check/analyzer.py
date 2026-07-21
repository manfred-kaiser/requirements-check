from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .models import AnalysisResult, Dependency, UpdateLevel
from .parser import parse_requirements
from .pypi import fetch_versions
from .security import check_vulnerabilities


def _is_compatible(requires_python: str | None, target: Version) -> bool:
    if not requires_python:
        return True
    try:
        return target in SpecifierSet(requires_python)
    except InvalidSpecifier:
        return True


def _best_suggestions(
    pinned_version: str, versions: list[Version]
) -> tuple[str | None, str | None, str | None, UpdateLevel]:
    try:
        current = Version(pinned_version)
    except InvalidVersion:
        return None, None, None, UpdateLevel.NONE

    newer = [version for version in versions if version > current]
    if not newer:
        return None, None, None, UpdateLevel.NONE

    same_minor = [v for v in newer if v.major == current.major and v.minor == current.minor]
    same_major = [v for v in newer if v.major == current.major]
    latest_overall = max(newer)

    latest_patch = str(max(same_minor)) if same_minor else None
    latest_minor = str(max(same_major)) if same_major else None
    latest_major = str(latest_overall)

    if latest_overall.major != current.major:
        level = UpdateLevel.MAJOR
    elif latest_overall.minor != current.minor:
        level = UpdateLevel.MINOR
    else:
        level = UpdateLevel.PATCH

    return latest_patch, latest_minor, latest_major, level


async def _empty_vuln_map() -> dict[str, list]:
    return {}


class Analyzer:
    def __init__(
        self,
        requirements_path: str | Path,
        check_security: bool = True,
        python_version: str | None = None,
        proxy: str | None = None,
        ca_bundle: str | None = None,
    ):
        self.requirements_path = requirements_path
        self.check_security = check_security
        self.target_python = Version(
            python_version or f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        )
        self.proxy = proxy
        self.verify: str | bool = ca_bundle or True

    async def analyze(self) -> AnalysisResult:
        dependencies: list[Dependency] = parse_requirements(self.requirements_path)
        checkable = [dep for dep in dependencies if dep.update_level != UpdateLevel.UNSUPPORTED]

        async with httpx.AsyncClient(proxy=self.proxy, verify=self.verify) as client:
            pypi_coro = asyncio.gather(
                *(fetch_versions(client, dep.name) for dep in checkable)
            )
            security_coro = (
                check_vulnerabilities(client, checkable)
                if self.check_security
                else _empty_vuln_map()
            )
            package_infos, vuln_map = await asyncio.gather(pypi_coro, security_coro)

        info_by_name = {info.name: info for info in package_infos}
        for dep in checkable:
            info = info_by_name.get(dep.name)
            if info is not None:
                if info.error:
                    dep.error = info.error
                    dep.update_level = UpdateLevel.NOT_FOUND
                else:
                    compatible = [
                        release.version
                        for release in info.releases
                        if _is_compatible(release.requires_python, self.target_python)
                    ]
                    if dep.pinned_version is None:
                        dep.latest_major = str(max(compatible)) if compatible else None
                        dep.update_level = UpdateLevel.UNPINNED
                    else:
                        patch, minor, major, level = _best_suggestions(
                            dep.pinned_version, compatible
                        )
                        dep.latest_patch = patch
                        dep.latest_minor = minor
                        dep.latest_major = major
                        dep.update_level = level
            dep.vulnerabilities = vuln_map.get(dep.name, [])

        return AnalysisResult(dependencies=dependencies)

    def analyze_sync(self) -> AnalysisResult:
        return asyncio.run(self.analyze())
