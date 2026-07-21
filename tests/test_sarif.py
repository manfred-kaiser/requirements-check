"""Unit tests for requirements_check.sarif."""

import json

from requirements_check.models import (
    AnalysisResult,
    Dependency,
    UpdateLevel,
    Vulnerability,
)
from requirements_check.sarif import render_sarif


def _result():
    return AnalysisResult(
        dependencies=[
            Dependency(
                name="foo",
                raw_line="foo==1.0.0",
                pinned_version="1.0.0",
                line_number=3,
                update_level=UpdateLevel.MAJOR,
                vulnerabilities=[
                    Vulnerability(
                        id="GHSA-xxxx",
                        summary="bad thing happens",
                        severity="HIGH",
                        aliases=["CVE-2026-0001"],
                        fixed_version="1.0.1",
                        fix_level=UpdateLevel.PATCH,
                    ),
                    Vulnerability(
                        id="GHSA-yyyy",
                        summary="still unpatched",
                        severity=None,
                        fixed_version=None,
                        fix_level=None,
                    ),
                ],
            ),
            Dependency(
                name="bar",
                raw_line="bar==2.0.0",
                pinned_version="2.0.0",
                line_number=4,
                update_level=UpdateLevel.NONE,
            ),
        ],
    )


def test_render_sarif_has_valid_envelope():
    sarif = json.loads(render_sarif(_result(), "requirements.txt"))

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "requirements-check"


def test_render_sarif_only_includes_vulnerable_dependencies():
    sarif = json.loads(render_sarif(_result(), "requirements.txt"))
    results = sarif["runs"][0]["results"]

    assert len(results) == 2  # foo has 2 vulns, bar (clean) contributes nothing
    assert {r["ruleId"] for r in results} == {"GHSA-xxxx", "GHSA-yyyy"}


def test_render_sarif_result_points_at_the_pinned_line():
    sarif = json.loads(render_sarif(_result(), "requirements.txt"))
    result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "GHSA-xxxx")

    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "requirements.txt"
    assert location["region"]["startLine"] == 3


def test_render_sarif_severity_levels():
    sarif = json.loads(render_sarif(_result(), "requirements.txt"))
    results = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}

    assert results["GHSA-xxxx"] == "note"  # patch-fixable
    assert results["GHSA-yyyy"] == "error"  # no known fix


def test_render_sarif_rules_are_deduplicated_and_include_aliases():
    sarif = json.loads(render_sarif(_result(), "requirements.txt"))
    rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}

    assert set(rules) == {"GHSA-xxxx", "GHSA-yyyy"}
    assert rules["GHSA-xxxx"]["properties"]["aliases"] == ["CVE-2026-0001"]


def test_render_sarif_omits_region_when_no_line_number():
    result = AnalysisResult(
        dependencies=[
            Dependency(
                name="foo",
                raw_line="pkg:pypi/foo@1.0.0",
                pinned_version="1.0.0",
                line_number=None,
                vulnerabilities=[
                    Vulnerability(id="GHSA-zzzz", summary="x", severity=None),
                ],
            ),
        ],
    )
    sarif = json.loads(render_sarif(result, "sbom.json"))
    location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]

    assert "region" not in location
    assert location["artifactLocation"]["uri"] == "sbom.json"
