"""Unit tests for requirements_check.security."""

import httpx

from requirements_check.models import Vulnerability
from requirements_check.parser import parse_requirements
from requirements_check.security import _dedupe_by_alias, check_vulnerabilities


def _write(tmp_path, content):
    path = tmp_path / "requirements.txt"
    path.write_text(content)
    return path


def test_dedupe_by_alias_merges_ghsa_and_pysec_entries_for_the_same_issue():
    ghsa = Vulnerability(
        id="GHSA-aaaa-bbbb-cccc",
        summary="same issue via GHSA",
        severity="HIGH",
        aliases=["CVE-2026-1234", "PYSEC-2026-1"],
    )
    pysec = Vulnerability(
        id="PYSEC-2026-1",
        summary="same issue via PYSEC",
        severity=None,
        aliases=["CVE-2026-1234", "GHSA-aaaa-bbbb-cccc"],
    )

    deduped = _dedupe_by_alias([ghsa, pysec])

    assert len(deduped) == 1
    assert deduped[0].id == "GHSA-aaaa-bbbb-cccc"
    assert set(deduped[0].aliases) == {"CVE-2026-1234", "PYSEC-2026-1"}


def test_dedupe_by_alias_keeps_unrelated_vulnerabilities_separate():
    first = Vulnerability(id="GHSA-1", summary="a", severity=None)
    second = Vulnerability(id="GHSA-2", summary="b", severity=None)

    deduped = _dedupe_by_alias([first, second])

    assert {vuln.id for vuln in deduped} == {"GHSA-1", "GHSA-2"}


async def test_check_vulnerabilities_deduplicates_aliased_osv_results(
    tmp_path,
    httpx_mock,
):
    path = _write(tmp_path, "foo==1.0.0\n")
    dependencies = parse_requirements(path)

    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": [{"id": "GHSA-x"}, {"id": "PYSEC-2026-9"}]}]},
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/GHSA-x",
        json={
            "id": "GHSA-x",
            "summary": "dup issue",
            "aliases": ["PYSEC-2026-9"],
        },
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/PYSEC-2026-9",
        json={
            "id": "PYSEC-2026-9",
            "summary": "dup issue",
            "aliases": ["GHSA-x"],
        },
    )

    async with httpx.AsyncClient() as client:
        result = await check_vulnerabilities(client, dependencies)

    assert len(result["foo"]) == 1
    assert result["foo"][0].id == "GHSA-x"
    assert result["foo"][0].fix_level is None
