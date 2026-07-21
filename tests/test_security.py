"""Unit tests for requirements_check.security."""

import httpx
from packaging.version import Version

from requirements_check.models import UpdateLevel, Vulnerability
from requirements_check.parser import parse_requirements
from requirements_check.security import (
    _dedupe_by_alias,
    _event_bounds,
    _fix_level_for,
    _fixed_version_for,
    _fixed_version_in_range,
    check_vulnerabilities,
)


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


async def test_check_vulnerabilities_returns_empty_when_batch_request_fails(
    tmp_path,
    httpx_mock,
):
    path = _write(tmp_path, "foo==1.0.0\n")
    dependencies = parse_requirements(path)

    httpx_mock.add_response(url="https://api.osv.dev/v1/querybatch", status_code=500)

    async with httpx.AsyncClient() as client:
        result = await check_vulnerabilities(client, dependencies)

    assert result == {}


async def test_check_vulnerabilities_skips_a_detail_that_fails_to_fetch(
    tmp_path,
    httpx_mock,
):
    path = _write(tmp_path, "foo==1.0.0\n")
    dependencies = parse_requirements(path)

    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": [{"id": "GHSA-x"}]}]},
    )
    httpx_mock.add_response(url="https://api.osv.dev/v1/vulns/GHSA-x", status_code=500)

    async with httpx.AsyncClient() as client:
        result = await check_vulnerabilities(client, dependencies)

    assert result == {"foo": []}


def test_event_bounds_records_a_real_introduced_version():
    introduced, fixed = _event_bounds([{"introduced": "1.0.0"}, {"fixed": "2.0.0"}])
    assert introduced == Version("1.0.0")
    assert fixed == Version("2.0.0")


def test_event_bounds_skips_unparsable_versions():
    introduced, fixed = _event_bounds(
        [{"introduced": "not-a-version"}, {"fixed": "also-not-a-version"}],
    )
    assert introduced is None
    assert fixed is None


def test_fixed_version_in_range_ignores_non_ecosystem_ranges():
    assert _fixed_version_in_range({"type": "SEMVER"}, Version("1.0.0")) is None


def test_fixed_version_in_range_is_none_when_pinned_predates_the_introduced_version():
    version_range = {
        "type": "ECOSYSTEM",
        "events": [{"introduced": "2.0.0"}, {"fixed": "3.0.0"}],
    }
    assert _fixed_version_in_range(version_range, Version("1.0.0")) is None


def test_fixed_version_in_range_is_none_when_pinned_already_meets_the_fixed_version():
    version_range = {
        "type": "ECOSYSTEM",
        "events": [{"introduced": "0"}, {"fixed": "1.0.0"}],
    }
    assert _fixed_version_in_range(version_range, Version("1.0.0")) is None


def test_fixed_version_for_skips_ranges_for_other_ecosystems():
    data = {
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "foo"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "9.9.9"}],
                    },
                ],
            },
        ],
    }
    assert _fixed_version_for(data, Version("1.0.0")) is None


def test_fix_level_for_minor_bump():
    assert _fix_level_for(Version("1.0.0"), "1.1.0") == UpdateLevel.MINOR
