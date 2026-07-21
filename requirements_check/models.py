"""Data models for requirements-check: dependencies, vulnerabilities, and results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class UpdateLevel(StrEnum):
    """How far a dependency (or a fix for one of its vulnerabilities) is behind."""

    NONE = "none"
    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"
    UNPINNED = "unpinned"
    UNSUPPORTED = "unsupported"
    NOT_FOUND = "not_found"
    NO_FIX = "no_fix"


@dataclass
class Vulnerability:
    """A single known vulnerability affecting a dependency's pinned version."""

    id: str
    summary: str
    severity: str | None
    aliases: list[str] = field(default_factory=list)
    fixed_version: str | None = None
    fix_level: UpdateLevel | None = None


@dataclass
class Dependency:
    """One requirements.txt entry, with its update and vulnerability status."""

    name: str
    raw_line: str
    pinned_version: str | None
    license: str | None = None
    latest_patch: str | None = None
    latest_minor: str | None = None
    latest_major: str | None = None
    update_level: UpdateLevel = UpdateLevel.NONE
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    minimum_safe_version: str | None = None
    vulnerability_fix_level: UpdateLevel | None = None
    constraint: str | None = None
    best_within_constraint: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of this dependency."""
        return {
            "name": self.name,
            "pinned_version": self.pinned_version,
            "license": self.license,
            "latest_patch": self.latest_patch,
            "latest_minor": self.latest_minor,
            "latest_major": self.latest_major,
            "constraint": self.constraint,
            "best_within_constraint": self.best_within_constraint,
            "update_level": self.update_level.value,
            "vulnerabilities": [
                {
                    "id": vuln.id,
                    "summary": vuln.summary,
                    "severity": vuln.severity,
                    "aliases": vuln.aliases,
                    "fixed_version": vuln.fixed_version,
                    "fix_level": vuln.fix_level.value if vuln.fix_level else None,
                }
                for vuln in self.vulnerabilities
            ],
            "minimum_safe_version": self.minimum_safe_version,
            "vulnerability_fix_level": (
                self.vulnerability_fix_level.value
                if self.vulnerability_fix_level
                else None
            ),
            "error": self.error,
        }


@dataclass
class AnalysisResult:
    """The full result of analyzing a requirements.txt file."""

    dependencies: list[Dependency]
    missing_transitive_dependencies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of this result."""
        return {
            "dependencies": [dep.to_dict() for dep in self.dependencies],
            "missing_transitive_dependencies": self.missing_transitive_dependencies,
        }

    @property
    def has_vulnerabilities(self) -> bool:
        """Whether any dependency has at least one known vulnerability."""
        return any(dep.vulnerabilities for dep in self.dependencies)
