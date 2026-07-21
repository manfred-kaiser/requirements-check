"""Parsing of requirements.txt files and CycloneDX SBOMs into Dependency records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from .models import Dependency, UpdateLevel

if TYPE_CHECKING:
    from packaging.specifiers import SpecifierSet


def _strip_comment(line: str) -> str:
    for i, ch in enumerate(line):
        if ch == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i]
    return line


def parse_requirements(path: str | Path) -> list[Dependency]:
    """Parse a requirements.txt file into a list of Dependency records."""
    text = Path(path).read_text(encoding="utf-8")
    dependencies: list[Dependency] = []

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw_line).strip()
        if not line or line.startswith("-"):
            continue

        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            dependencies.append(
                Dependency(
                    name=raw_line.strip(),
                    raw_line=raw_line,
                    pinned_version=None,
                    line_number=line_number,
                    update_level=UpdateLevel.UNSUPPORTED,
                    error="Could not parse requirement line",
                ),
            )
            continue

        if requirement.url:
            dependencies.append(
                Dependency(
                    name=requirement.name,
                    raw_line=raw_line,
                    pinned_version=None,
                    line_number=line_number,
                    update_level=UpdateLevel.UNSUPPORTED,
                    error="URL/VCS requirements are not version-checkable",
                ),
            )
            continue

        pinned_version = None
        pins = [spec.version for spec in requirement.specifier if spec.operator == "=="]
        if len(pins) == 1:
            pinned_version = pins[0]

        dependencies.append(
            Dependency(
                name=requirement.name,
                raw_line=raw_line,
                pinned_version=pinned_version,
                line_number=line_number,
            ),
        )

    return dependencies


def parse_constraints(path: str | Path) -> dict[str, SpecifierSet]:
    """Parse a loose requirements file into name -> allowed version range.

    E.g. a pip-compile `.in` source. Lines without a version specifier
    (fully unconstrained) are omitted.
    """
    text = Path(path).read_text(encoding="utf-8")
    constraints: dict[str, SpecifierSet] = {}

    for raw_line in text.splitlines():
        line = _strip_comment(raw_line).strip()
        if not line or line.startswith("-"):
            continue
        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            continue
        if requirement.url or not requirement.specifier:
            continue
        constraints[canonicalize_name(requirement.name)] = requirement.specifier

    return constraints


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
    """Parse `path` as a CycloneDX SBOM or a plain requirements.txt, auto-detected."""
    if is_cyclonedx_sbom(path):
        return parse_cyclonedx_sbom(path)
    return parse_requirements(path)
