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
from .parser import (
    is_pyproject_toml,
    parse_constraints,
    parse_dependencies,
    parse_pyproject_extra,
)
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


def _applicable_requirements(
    requires_dist: list[str],
    target_python: Version,
) -> list[Requirement]:
    """Parse `requires_dist` entries that apply on `target_python`.

    Only entries with no optional extras selected apply; unparsable or
    non-applicable ones are skipped.
    """
    environment = _marker_environment(target_python)
    applicable = []
    for req_str in requires_dist:
        try:
            req = Requirement(req_str)
        except InvalidRequirement:
            continue
        if _marker_applies(req.marker, environment):
            applicable.append(req)
    return applicable


def _declared_runtime_dependencies(
    requires_dist: list[str],
    target_python: Version,
) -> dict[str, str]:
    """Map canonicalized name -> original name for dependencies that apply."""
    return {
        str(canonicalize_name(req.name)): req.name
        for req in _applicable_requirements(requires_dist, target_python)
    }


def _sibling_version_locks(
    dependencies: list[Dependency],
    info_by_name: dict[str, PackageInfo],
    target_python: Version,
) -> dict[str, tuple[str, str]]:
    """Map canonicalized name -> (locked-to version, "pkg==version" source).

    A package is "locked" when another checked, pinned dependency's own
    pinned release hard-requires (`==`) an exact version of it — e.g. a
    compiled extension like pydantic-core that its pure-Python wrapper
    pins in lockstep. A newer release existing on PyPI doesn't mean it's
    actually installable without that sibling also releasing a compatible
    update first.
    """
    locks: dict[str, tuple[str, str]] = {}
    for dep in dependencies:
        info = info_by_name.get(dep.name)
        if info is None or info.error or dep.pinned_version is None:
            continue
        for req in _applicable_requirements(info.requires_dist, target_python):
            pins = [spec.version for spec in req.specifier if spec.operator == "=="]
            if len(pins) != 1:
                continue
            locks[str(canonicalize_name(req.name))] = (
                pins[0],
                f"{dep.name}=={dep.pinned_version}",
            )
    return locks


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


def _merge_conflict_dependency(
    name: str,
    sources: list[str],
    entries: list[Dependency],
    message: str,
) -> Dependency:
    return Dependency(
        name=name,
        raw_line=" / ".join(dep.raw_line for dep in entries),
        pinned_version=None,
        update_level=UpdateLevel.UNSUPPORTED,
        error=message,
        sources=sources,
    )


def _dependency_specifier(dep: Dependency) -> SpecifierSet | None:
    """Return the specifier a (non-UNSUPPORTED) dependency's raw_line declares."""
    if dep.update_level == UpdateLevel.UNSUPPORTED:
        return None
    try:
        return Requirement(dep.raw_line).specifier
    except InvalidRequirement:  # pragma: no cover
        # unreachable: non-UNSUPPORTED deps already parsed their raw_line fine
        return None


def _is_bare_pin(specifier: SpecifierSet, pinned_version: str | None) -> bool:
    """Whether `specifier` says nothing beyond the exact pin already shown.

    The Pinned column already shows a single `==` clause matching that same
    version. A range that happens to be satisfied by a pin from another
    group (e.g. `>=4.0,<6.0` alongside a sibling `==5.0.0`) is real,
    relevant information and isn't considered bare.
    """
    if pinned_version is None:
        return False
    clauses = list(specifier)
    return (
        len(clauses) == 1
        and clauses[0].operator == "=="
        and clauses[0].version == pinned_version
    )


def _merge_dependency_group(
    sources: list[str],
    deps_only: list[Dependency],
) -> tuple[Dependency, SpecifierSet | None]:
    """Merge one package's entries from multiple groups into a single row.

    Returns the merged Dependency plus its combined specifier (for a later
    satisfiability check against real PyPI releases), or None if there's
    nothing to check (a conflict was already found, or every entry was
    unconstrained).
    """
    name = deps_only[0].name

    if any(dep.update_level == UpdateLevel.UNSUPPORTED for dep in deps_only):
        message = f"unparsable requirement in one of: {', '.join(sources)}"
        return _merge_conflict_dependency(name, sources, deps_only, message), None

    pins = {dep.pinned_version for dep in deps_only if dep.pinned_version is not None}
    if len(pins) > 1:
        message = (
            f"conflicting pinned versions across {', '.join(sources)}: "
            + ", ".join(
                sorted(pins),
            )
        )
        return _merge_conflict_dependency(name, sources, deps_only, message), None

    pinned_version = next(iter(pins)) if pins else None

    source_specifiers: dict[str, str] = {}
    specifiers: list[SpecifierSet] = []
    for group_name, dep in zip(sources, deps_only, strict=True):
        specifier = _dependency_specifier(dep)
        if specifier is None:  # pragma: no cover
            continue  # unreachable: UNSUPPORTED deps already excluded above
        specifiers.append(specifier)
        if str(specifier) and not _is_bare_pin(specifier, pinned_version):
            source_specifiers[group_name] = str(specifier)

    combined = SpecifierSet(",".join(str(spec) for spec in specifiers if str(spec)))
    combined_str = str(combined) or None

    merged_dep = Dependency(
        name=name,
        raw_line=" / ".join(dep.raw_line for dep in deps_only),
        pinned_version=pinned_version,
        sources=sources,
        source_specifiers=source_specifiers,
    )
    return merged_dep, (combined if combined_str else None)


def _merge_grouped_dependencies(
    grouped: dict[str, list[Dependency]],
) -> tuple[list[Dependency], dict[str, SpecifierSet]]:
    """Merge dependency lists from multiple pyproject.toml groups into one row per package.

    `grouped` maps a group label (`"dependencies"` for the core list, or an
    extra's name) to that group's parsed dependencies. A package declared in
    only one group passes through unchanged, tagged with that group. A
    package declared in several has its groups' specifiers intersected into
    one combined range for a later satisfiability check against real PyPI
    releases (returned separately, since that needs data this function
    doesn't have) — two different exact pins are caught immediately here,
    since they can never both be true regardless of what's on PyPI.
    """
    by_name: dict[str, list[tuple[str, Dependency]]] = {}
    order: list[str] = []
    for group_name, deps in grouped.items():
        for dep in deps:
            key = str(canonicalize_name(dep.name))
            if key not in by_name:
                order.append(key)
            by_name.setdefault(key, []).append((group_name, dep))

    merged: list[Dependency] = []
    group_specifiers: dict[str, SpecifierSet] = {}

    for key in order:
        entries = by_name[key]
        sources = [group_name for group_name, _ in entries]

        if len(entries) == 1:
            group_name, dep = entries[0]
            dep.sources = sources
            specifier = _dependency_specifier(dep)
            if (
                specifier is not None
                and str(specifier)
                and not _is_bare_pin(specifier, dep.pinned_version)
            ):
                dep.source_specifiers = {group_name: str(specifier)}
            merged.append(dep)
            continue

        merged_dep, specifier = _merge_dependency_group(
            sources,
            [dep for _, dep in entries],
        )
        merged.append(merged_dep)
        if specifier is not None:
            group_specifiers[key] = specifier

    return merged, group_specifiers


def _apply_group_conflict(
    dep: Dependency,
    compatible: list[Version],
    group_specifiers: dict[str, SpecifierSet],
) -> None:
    group_specifier = group_specifiers.get(canonicalize_name(dep.name))
    if (
        group_specifier is not None
        and compatible
        and not any(group_specifier.contains(v) for v in compatible)
    ):
        dep.error = (
            "conflicting version requirements across "
            f"{', '.join(dep.sources)} — no available release satisfies all of them"
        )


def _apply_pypi_info(
    dep: Dependency,
    info: PackageInfo,
    constraints: dict[str, SpecifierSet],
    group_specifiers: dict[str, SpecifierSet],
    target_python: Version,
) -> None:
    dep.license = info.license
    if info.error:
        dep.error = info.error
        dep.update_level = UpdateLevel.NOT_FOUND
        return

    compatible = [
        release.version
        for release in info.releases
        if _is_compatible(release.requires_python, target_python)
    ]
    _apply_constraint(dep, constraints.get(canonicalize_name(dep.name)), compatible)
    _apply_group_conflict(dep, compatible, group_specifiers)

    if dep.pinned_version is None:
        dep.latest_major = str(max(compatible)) if compatible else None
        dep.update_level = UpdateLevel.UNPINNED
    else:
        patch, minor, major, level = _best_suggestions(dep.pinned_version, compatible)
        dep.latest_patch = patch
        dep.latest_minor = minor
        dep.latest_major = major
        dep.update_level = level


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
        extras: list[str] | None = None,
    ) -> None:
        """Configure the analyzer; nothing is fetched until analyze() runs.

        `constraints_path` points at a loose, unresolved requirements file
        (e.g. a pip-compile `.in` source) to cross-check suggestions against
        your own version ceilings. If not given, a file with the same name
        but a `.in` extension next to `requirements_path` is used when present.

        `extras` names `[project.optional-dependencies]` extras (from a
        `requirements_path` that's a pyproject.toml) to check alongside the
        core dependencies. A package declared in multiple groups is merged
        into one row; conflicting requirements across groups are reported
        as an error on that row rather than silently picking one.
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
        self.extras = extras or []

    def _load_constraints(self) -> dict[str, SpecifierSet]:
        if self.constraints_path:
            path = Path(self.constraints_path)
        elif is_pyproject_toml(self.requirements_path):
            # A pyproject.toml given directly is itself the constraints
            # source: its declared ranges cap its own suggested updates.
            path = Path(self.requirements_path)
        else:
            # Prefer a sibling `.in` source (the more specific, deliberate
            # signal) over a sibling pyproject.toml if both happen to exist.
            in_path = Path(self.requirements_path).with_suffix(".in")
            path = (
                in_path
                if in_path.exists()
                else Path(self.requirements_path).parent / "pyproject.toml"
            )
        if not path.exists():
            return {}
        return parse_constraints(path)

    async def analyze(self) -> AnalysisResult:
        """Parse the requirements file and check it against PyPI and OSV.dev."""
        dependencies: list[Dependency] = parse_dependencies(self.requirements_path)
        group_specifiers: dict[str, SpecifierSet] = {}
        if self.extras:
            grouped = {"dependencies": dependencies}
            for extra_name in self.extras:
                grouped[extra_name] = parse_pyproject_extra(
                    self.requirements_path,
                    extra_name,
                )
            dependencies, group_specifiers = _merge_grouped_dependencies(grouped)

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
                _apply_pypi_info(
                    dep,
                    info,
                    constraints,
                    group_specifiers,
                    self.target_python,
                )
            dep.vulnerabilities = vuln_map.get(dep.name, [])
            _summarize_vulnerabilities(dep)

        locks = _sibling_version_locks(checkable, info_by_name, self.target_python)
        for dep in checkable:
            lock = locks.get(canonicalize_name(dep.name))
            if lock is None:
                continue
            locked_version, locked_by = lock
            suggested = (dep.latest_patch, dep.latest_minor, dep.latest_major)
            if any(v and Version(v) > Version(locked_version) for v in suggested):
                dep.locked_to = locked_version
                dep.locked_by = locked_by

        # A pyproject.toml's [project.dependencies] is intentionally not an
        # exhaustive, fully-resolved list (unlike a pip-compile'd
        # requirements.txt) — the transitive-completeness check would just
        # produce false positives against it.
        missing_transitive = (
            _find_missing_transitive_dependencies(
                dependencies,
                info_by_name,
                self.target_python,
            )
            if self.check_transitive and not is_pyproject_toml(self.requirements_path)
            else []
        )

        return AnalysisResult(
            dependencies=dependencies,
            missing_transitive_dependencies=missing_transitive,
        )

    def analyze_sync(self) -> AnalysisResult:
        """Run analyze() synchronously, for callers without an event loop."""
        return asyncio.run(self.analyze())
