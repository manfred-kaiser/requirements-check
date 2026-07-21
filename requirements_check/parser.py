from __future__ import annotations

from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from .models import Dependency, UpdateLevel


def _strip_comment(line: str) -> str:
    for i, ch in enumerate(line):
        if ch == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i]
    return line


def parse_requirements(path: str | Path) -> list[Dependency]:
    text = Path(path).read_text()
    dependencies: list[Dependency] = []

    for raw_line in text.splitlines():
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
                    update_level=UpdateLevel.UNSUPPORTED,
                    error="Could not parse requirement line",
                )
            )
            continue

        if requirement.url:
            dependencies.append(
                Dependency(
                    name=requirement.name,
                    raw_line=raw_line,
                    pinned_version=None,
                    update_level=UpdateLevel.UNSUPPORTED,
                    error="URL/VCS requirements are not version-checkable",
                )
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
            )
        )

    return dependencies
