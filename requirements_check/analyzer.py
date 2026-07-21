"""Orchestrates parsing, PyPI version checks, and OSV.dev vulnerability checks."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import TYPE_CHECKING, cast

import httpx
from packaging.markers import Marker, default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .models import AnalysisResult, Dependency, UpdateLevel, Vulnerability
from .parser import parse_constraints, parse_requirements
from .pypi import fetch_versions
from .security import check_vulnerabilities

if TYPE_CHECKING:
    from .pypi import PackageInfo


def _is_compatible(requires_python: str | None, target: Version) -> bool:
    if not requires_python:
        return True
    try:
        return target in SpecifierSet(requires_python)
    except InvalidSpecifier:
        return True


def _best_suggestions(
    pinned_version: str,
    versions: list[Version],
) -> tuple[str | None, str | None, str | None, UpdateLevel]:
    try:
        current = Version(pinned_version)
    except InvalidVersion:
        return None, None, None, UpdateLevel.NONE

    newer = [version for version in versions if version > current]
    if not newer:
        return None, None, None, UpdateLevel.NONE

    same_minor = [
        v for v in newer if v.major == current.major and v.minor == current.minor
    ]
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


async def _empty_vuln_map() -> dict[str, list[Vulnerability]]:
    return {}


def _marker_environment(target_python: Version) -> dict[str, str]:
    env: dict[str, str] = cast("dict[str, str]", dict(default_environment()))
    env["python_version"] = f"{target_python.major}.{target_python.minor}"
    env["python_full_version"] = str(target_python)
    env["extra"] = ""  # base install, no optional extras requested
    return env


def _marker_applies(marker: Marker | None, environment: dict[str, str]) -> bool:
    if marker is None:
        return True
    try:
        return marker.evaluate(environment=environment)
    except Exception:  # noqa: BLE001  # pylint: disable=broad-exception-caught
        return True  # unevaluable marker: assume it applies rather than crash


def _declared_runtime_dependencies(
    requires_dist: list[str],
    target_python: Version,
) -> dict[str, str]:
    """Map canonicalized name -> original name for dependencies that apply.

    Only includes dependencies that actually apply on `target_python` with no
    optional extras selected.
    """
    environment = _marker_environment(target_python)
    declared = {}
    for req_str in requires_dist:
        try:
            req = Requirement(req_str)
        except InvalidRequirement:
            continue
        if _marker_applies(req.marker, environment):
            declared[str(canonicalize_name(req.name))] = req.name
    return declared


def _find_missing_transitive_dependencies(
    dependencies: list[Dependency],
    info_by_name: dict[str, PackageInfo],
    target_python: Version,
) -> list[str]:
    known = {canonicalize_name(dep.name) for dep in dependencies}
    missing: dict[str, str] = {}

    for dep in dependencies:
        info = info_by_name.get(dep.name)
        if info is None or info.error:
            continue
        for normalized, original in _declared_runtime_dependencies(
            info.requires_dist,
            target_python,
        ).items():
            if normalized not in known:
                missing.setdefault(normalized, original)

    return sorted(missing.values(), key=str.lower)


def _apply_constraint(
    dep: Dependency,
    constraint: SpecifierSet | None,
    compatible: list[Version],
) -> None:
    if constraint is None:
        return
    dep.constraint = str(constraint)
    within_constraint = [
        version for version in compatible if constraint.contains(version)
    ]
    if within_constraint:
        dep.best_within_constraint = str(max(within_constraint))


def _summarize_vulnerabilities(dep: Dependency) -> None:
    if not dep.vulnerabilities or dep.pinned_version is None:
        return

    if any(vuln.fixed_version is None for vuln in dep.vulnerabilities):
        dep.vulnerability_fix_level = UpdateLevel.NO_FIX
        return

    pinned = Version(dep.pinned_version)
    fixed_versions = [
        Version(vuln.fixed_version)
        for vuln in dep.vulnerabilities
        if vuln.fixed_version is not None
    ]
    minimum_safe = max(fixed_versions)
    dep.minimum_safe_version = str(minimum_safe)

    if minimum_safe.major != pinned.major:
        dep.vulnerability_fix_level = UpdateLevel.MAJOR
    elif minimum_safe.minor != pinned.minor:
        dep.vulnerability_fix_level = UpdateLevel.MINOR
    else:
        dep.vulnerability_fix_level = UpdateLevel.PATCH


class Analyzer:
    """Checks a requirements.txt file for outdated dependencies and vulnerabilities."""

    def __init__(
        self,
        requirements_path: str | Path,
        *,
        check_security: bool = True,
        check_transitive: bool = True,
        constraints_path: str | Path | None = None,
        python_version: str | None = None,
        proxy: str | None = None,
        ca_bundle: str | None = None,
    ) -> None:
        """Configure the analyzer; nothing is fetched until analyze() runs.

        `constraints_path` points at a loose, unresolved requirements file
        (e.g. a pip-compile `.in` source) to cross-check suggestions against
        your own version ceilings. If not given, a file with the same name
        but a `.in` extension next to `requirements_path` is used when present.
        """
        self.requirements_path = requirements_path
        self.check_security = check_security
        self.check_transitive = check_transitive
        self.constraints_path = constraints_path
        self.target_python = Version(
            python_version
            or f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        )
        self.proxy = proxy
        self.verify: str | bool = ca_bundle or True

    def _load_constraints(self) -> dict[str, SpecifierSet]:
        path = (
            Path(self.constraints_path)
            if self.constraints_path
            else Path(self.requirements_path).with_suffix(".in")
        )
        if not path.exists():
            return {}
        return parse_constraints(path)

    async def analyze(self) -> AnalysisResult:
        """Parse the requirements file and check it against PyPI and OSV.dev."""
        dependencies: list[Dependency] = parse_requirements(self.requirements_path)
        constraints = self._load_constraints()
        checkable = [
            dep for dep in dependencies if dep.update_level != UpdateLevel.UNSUPPORTED
        ]

        async with httpx.AsyncClient(proxy=self.proxy, verify=self.verify) as client:
            pypi_coro = asyncio.gather(
                *(
                    fetch_versions(client, dep.name, dep.pinned_version)
                    for dep in checkable
                ),
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
                dep.license = info.license
                if info.error:
                    dep.error = info.error
                    dep.update_level = UpdateLevel.NOT_FOUND
                else:
                    compatible = [
                        release.version
                        for release in info.releases
                        if _is_compatible(release.requires_python, self.target_python)
                    ]
                    _apply_constraint(
                        dep,
                        constraints.get(canonicalize_name(dep.name)),
                        compatible,
                    )
                    if dep.pinned_version is None:
                        dep.latest_major = str(max(compatible)) if compatible else None
                        dep.update_level = UpdateLevel.UNPINNED
                    else:
                        patch, minor, major, level = _best_suggestions(
                            dep.pinned_version,
                            compatible,
                        )
                        dep.latest_patch = patch
                        dep.latest_minor = minor
                        dep.latest_major = major
                        dep.update_level = level
            dep.vulnerabilities = vuln_map.get(dep.name, [])
            _summarize_vulnerabilities(dep)

        missing_transitive = (
            _find_missing_transitive_dependencies(
                dependencies,
                info_by_name,
                self.target_python,
            )
            if self.check_transitive
            else []
        )

        return AnalysisResult(
            dependencies=dependencies,
            missing_transitive_dependencies=missing_transitive,
        )

    def analyze_sync(self) -> AnalysisResult:
        """Run analyze() synchronously, for callers without an event loop."""
        return asyncio.run(self.analyze())
