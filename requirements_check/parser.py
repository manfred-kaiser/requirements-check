"""Parsing of requirements.txt, pyproject.toml, and CycloneDX SBOMs into Dependency records."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING, cast

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from .models import Dependency, UpdateLevel

if TYPE_CHECKING:
    from packaging.specifiers import SpecifierSet


class PyprojectTomlError(ValueError):
    """Base class for pyproject.toml parsing errors that need a clear CLI message."""


class DynamicDependenciesError(PyprojectTomlError):
    """pyproject.toml declares `dependencies` as dynamic (build-hook computed)."""


class UnknownExtraError(PyprojectTomlError):
    """The requested `[project.optional-dependencies]` extra isn't declared."""


def _strip_comment(line: str) -> str:
    for i, ch in enumerate(line):
        if ch == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i]
    return line


def _dependency_from_requirement(
    requirement_str: str,
    *,
    raw_line: str,
    line_number: int | None,
) -> Dependency:
    """Build a Dependency from one already-cleaned PEP 508 requirement string."""
    try:
        requirement = Requirement(requirement_str)
    except InvalidRequirement:
        return Dependency(
            name=raw_line.strip(),
            raw_line=raw_line,
            pinned_version=None,
            line_number=line_number,
            update_level=UpdateLevel.UNSUPPORTED,
            error="Could not parse requirement line",
        )

    if requirement.url:
        return Dependency(
            name=requirement.name,
            raw_line=raw_line,
            pinned_version=None,
            line_number=line_number,
            update_level=UpdateLevel.UNSUPPORTED,
            error="URL/VCS requirements are not version-checkable",
        )

    pins = [spec.version for spec in requirement.specifier if spec.operator == "=="]
    pinned_version = pins[0] if len(pins) == 1 else None

    return Dependency(
        name=requirement.name,
        raw_line=raw_line,
        pinned_version=pinned_version,
        line_number=line_number,
    )


def _constraints_from_requirement_strings(
    requirement_strings: list[str],
) -> dict[str, SpecifierSet]:
    constraints: dict[str, SpecifierSet] = {}
    for req_str in requirement_strings:
        try:
            requirement = Requirement(req_str)
        except InvalidRequirement:
            continue
        if requirement.url or not requirement.specifier:
            continue
        constraints[canonicalize_name(requirement.name)] = requirement.specifier
    return constraints


def is_pyproject_toml(path: str | Path) -> bool:
    """Whether `path` looks like a PEP 621 pyproject.toml rather than a requirements.txt."""
    try:
        with Path(path).open("rb") as handle:
            data = tomllib.load(handle)
    except (tomllib.TOMLDecodeError, OSError):
        return False
    return isinstance(data.get("project"), dict)


def _requirement_lines_from_file(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    lines = []
    for raw_line in text.splitlines():
        line = _strip_comment(raw_line).strip()
        if not line or line.startswith("-"):
            continue
        lines.append(line)
    return lines


def _hatch_requirements_txt_hook_config(
    data: dict[str, object],
) -> dict[str, object] | None:
    """Read the `hatch-requirements-txt` plugin's hook config, if present.

    `[tool.hatch.metadata.hooks.requirements_txt]` is the only common way to
    declare dynamic dependencies that's statically resolvable without running
    the project's own build backend.
    """
    tool = data.get("tool")
    if not isinstance(tool, dict):
        return None
    hook_config = (
        tool.get("hatch", {})
        .get("metadata", {})
        .get("hooks", {})
        .get(
            "requirements_txt",
        )
    )
    return hook_config if isinstance(hook_config, dict) else None


def _dynamic_dependency_strings(
    pyproject_path: Path,
    data: dict[str, object],
) -> list[str]:
    """Resolve `dynamic = ["dependencies"]` via the hatch-requirements-txt hook."""
    hook_config = _hatch_requirements_txt_hook_config(data)
    if hook_config is None or not hook_config.get("files"):
        message = (
            "dependencies are dynamically computed by a build hook and can't be "
            "read statically from pyproject.toml (no recognized "
            "[tool.hatch.metadata.hooks.requirements_txt] config found)"
        )
        raise DynamicDependenciesError(message)

    lines: list[str] = []
    for filename in cast("list[str]", hook_config["files"]):
        lines.extend(
            _requirement_lines_from_file(pyproject_path.parent / str(filename)),
        )
    return lines


def _dynamic_extra_dependency_strings(
    pyproject_path: Path,
    data: dict[str, object],
    extra_name: str,
) -> list[str]:
    """Resolve one dynamic `[project.optional-dependencies]` extra.

    Uses the hatch-requirements-txt hook's `optional-dependencies` sub-table.
    """
    hook_config = _hatch_requirements_txt_hook_config(data)
    extra_files = (
        cast(
            "dict[str, list[str]]",
            hook_config.get("optional-dependencies", {}),
        ).get(extra_name)
        if hook_config is not None
        else None
    )
    if not extra_files:
        message = (
            f"no [project.optional-dependencies] extra named {extra_name!r} found "
            "(checked the hatch-requirements-txt hook config)"
        )
        raise UnknownExtraError(message)

    lines: list[str] = []
    for filename in extra_files:
        lines.extend(
            _requirement_lines_from_file(pyproject_path.parent / str(filename)),
        )
    return lines


def _pyproject_dependency_strings(path: str | Path) -> list[str]:
    """Read `[project.dependencies]` from a PEP 621 pyproject.toml.

    Raises DynamicDependenciesError if dependencies are computed by a build
    hook (`dynamic = ["dependencies"]`) that can't be statically resolved.
    """
    pyproject_path = Path(path)
    with pyproject_path.open("rb") as handle:
        data = tomllib.load(handle)

    project = data.get("project", {})
    if "dependencies" in project.get("dynamic", []):
        return _dynamic_dependency_strings(pyproject_path, data)
    return cast("list[str]", project.get("dependencies", []))


def _pyproject_extra_dependency_strings(path: str | Path, extra_name: str) -> list[str]:
    """Read one named `[project.optional-dependencies]` extra.

    Raises UnknownExtraError if the extra isn't declared, or
    DynamicDependenciesError if extras are dynamic and unresolvable.
    """
    pyproject_path = Path(path)
    with pyproject_path.open("rb") as handle:
        data = tomllib.load(handle)

    project = data.get("project", {})
    if "optional-dependencies" in project.get("dynamic", []):
        return _dynamic_extra_dependency_strings(pyproject_path, data, extra_name)

    optional_dependencies = project.get("optional-dependencies", {})
    if extra_name not in optional_dependencies:
        message = f"no [project.optional-dependencies] extra named {extra_name!r} in pyproject.toml"
        raise UnknownExtraError(message)
    return cast("list[str]", optional_dependencies[extra_name])


def parse_pyproject_toml(path: str | Path) -> list[Dependency]:
    """Parse a PEP 621 pyproject.toml's direct `[project.dependencies]`.

    Optional extras and tool-specific dependency tables (e.g. hatch
    environments) aren't included by default — only the standard,
    backend-agnostic direct dependencies; see parse_pyproject_extra() for
    extras. These are typically abstract version ranges rather than exact
    pins, so most entries come back unpinned (update-checkable, but not
    vulnerability-checkable — that needs an exact installed version).
    """
    return [
        _dependency_from_requirement(req_str, raw_line=req_str, line_number=None)
        for req_str in _pyproject_dependency_strings(path)
    ]


def parse_pyproject_extra(path: str | Path, extra_name: str) -> list[Dependency]:
    """Parse one named `[project.optional-dependencies]` extra."""
    return [
        _dependency_from_requirement(req_str, raw_line=req_str, line_number=None)
        for req_str in _pyproject_extra_dependency_strings(path, extra_name)
    ]


def parse_requirements(path: str | Path) -> list[Dependency]:
    """Parse a requirements.txt file into a list of Dependency records."""
    text = Path(path).read_text(encoding="utf-8")
    dependencies: list[Dependency] = []

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw_line).strip()
        if not line or line.startswith("-"):
            continue
        dependencies.append(
            _dependency_from_requirement(
                line,
                raw_line=raw_line,
                line_number=line_number,
            ),
        )

    return dependencies


def parse_constraints(path: str | Path) -> dict[str, SpecifierSet]:
    """Parse a loose requirements source into name -> allowed version range.

    Accepts either a pip-compile `.in`-style requirements file or a PEP 621
    pyproject.toml (using its `[project.dependencies]`), auto-detected.
    Entries without a version specifier (fully unconstrained) are omitted.
    """
    if is_pyproject_toml(path):
        return _constraints_from_requirement_strings(
            _pyproject_dependency_strings(path),
        )
    return _constraints_from_requirement_strings(
        _requirement_lines_from_file(Path(path)),
    )


def _load_json(path: str | Path) -> object:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None


def is_cyclonedx_sbom(path: str | Path) -> bool:
    """Whether `path` looks like a CycloneDX JSON SBOM rather than a requirements.txt."""
    data = _load_json(path)
    return isinstance(data, dict) and data.get("bomFormat") == "CycloneDX"


def parse_cyclonedx_sbom(path: str | Path) -> list[Dependency]:
    """Parse a CycloneDX JSON SBOM's PyPI components into Dependency records.

    Components use a PURL to identify the package; only `pkg:pypi/...` PURLs
    are Python packages, so anything else (other ecosystems in the same SBOM)
    is silently skipped. Since an SBOM records what's actually in a build,
    every component here counts as pinned — there's no unpinned/URL case.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    dependencies: list[Dependency] = []

    for component in data.get("components", []):
        purl = component.get("purl") or ""
        if not purl.startswith("pkg:pypi/"):
            continue
        name = component.get("name")
        version = component.get("version")
        if not name or not version:
            continue
        dependencies.append(
            Dependency(
                name=name,
                raw_line=purl,
                pinned_version=version,
            ),
        )

    return dependencies


def parse_dependencies(path: str | Path) -> list[Dependency]:
    """Parse `path` as a CycloneDX SBOM, a pyproject.toml, or a plain requirements.txt."""
    if is_cyclonedx_sbom(path):
        return parse_cyclonedx_sbom(path)
    if is_pyproject_toml(path):
        return parse_pyproject_toml(path)
    return parse_requirements(path)
