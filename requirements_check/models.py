from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class UpdateLevel(str, Enum):
    NONE = "none"
    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"
    UNPINNED = "unpinned"
    UNSUPPORTED = "unsupported"
    NOT_FOUND = "not_found"


@dataclass
class Vulnerability:
    id: str
    summary: str
    severity: str | None
    aliases: list[str] = field(default_factory=list)


@dataclass
class Dependency:
    name: str
    raw_line: str
    pinned_version: str | None
    latest_patch: str | None = None
    latest_minor: str | None = None
    latest_major: str | None = None
    update_level: UpdateLevel = UpdateLevel.NONE
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "pinned_version": self.pinned_version,
            "latest_patch": self.latest_patch,
            "latest_minor": self.latest_minor,
            "latest_major": self.latest_major,
            "update_level": self.update_level.value,
            "vulnerabilities": [
                {
                    "id": vuln.id,
                    "summary": vuln.summary,
                    "severity": vuln.severity,
                    "aliases": vuln.aliases,
                }
                for vuln in self.vulnerabilities
            ],
            "error": self.error,
        }


@dataclass
class AnalysisResult:
    dependencies: list[Dependency]

    def to_dict(self) -> dict:
        return {"dependencies": [dep.to_dict() for dep in self.dependencies]}

    @property
    def has_vulnerabilities(self) -> bool:
        return any(dep.vulnerabilities for dep in self.dependencies)
