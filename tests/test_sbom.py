"""Unit tests for requirements_check.sbom."""

import json

from requirements_check import __version__
from requirements_check.models import (
    AnalysisResult,
    Dependency,
    UpdateLevel,
    Vulnerability,
)
from requirements_check.sbom import render_cyclonedx


def _result():
    return AnalysisResult(
        dependencies=[
            Dependency(
                name="foo",
                raw_line="foo==1.0.0",
                pinned_version="1.0.0",
                license="MIT",
                update_level=UpdateLevel.NONE,
                vulnerabilities=[
                    Vulnerability(
                        id="GHSA-x",
                        summary="bad thing",
                        severity="HIGH",
                        aliases=["CVE-2026-0001"],
                        fixed_version="1.0.1",
                        fix_level=UpdateLevel.PATCH,
                    ),
                ],
            ),
            Dependency(
                name="bar",
                raw_line="bar>=2.0.0",
                pinned_version=None,
                update_level=UpdateLevel.UNPINNED,
            ),
        ],
    )


def test_render_cyclonedx_has_valid_envelope():
    bom = json.loads(render_cyclonedx(_result()))

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["serialNumber"].startswith("urn:uuid:")
    tool = bom["metadata"]["tools"]["components"][0]
    assert tool["name"] == "requirements-check"
    assert tool["version"] == __version__


def test_render_cyclonedx_only_includes_pinned_dependencies():
    bom = json.loads(render_cyclonedx(_result()))

    names = {component["name"] for component in bom["components"]}
    assert names == {"foo"}


def test_render_cyclonedx_component_has_purl_and_license():
    bom = json.loads(render_cyclonedx(_result()))
    component = bom["components"][0]

    assert component["purl"] == "pkg:pypi/foo@1.0.0"
    assert component["bom-ref"] == "pkg:pypi/foo@1.0.0"
    assert component["licenses"][0]["license"]["name"] == "MIT"


def test_render_cyclonedx_includes_vulnerability_with_affects_and_aliases():
    bom = json.loads(render_cyclonedx(_result()))
    vuln = bom["vulnerabilities"][0]

    assert vuln["id"] == "GHSA-x"
    assert vuln["affects"] == [{"ref": "pkg:pypi/foo@1.0.0"}]
    assert vuln["references"][0]["id"] == "CVE-2026-0001"


def test_render_cyclonedx_omits_vulnerabilities_key_when_none_found():
    clean_result = AnalysisResult(
        dependencies=[
            Dependency(
                name="foo",
                raw_line="foo==1.0.0",
                pinned_version="1.0.0",
                update_level=UpdateLevel.NONE,
            ),
        ],
    )
    bom = json.loads(render_cyclonedx(clean_result))

    assert "vulnerabilities" not in bom
