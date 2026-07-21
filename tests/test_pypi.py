"""Unit tests for requirements_check.pypi."""

import httpx

from requirements_check.pypi import _extract_license, fetch_versions


async def test_fetch_versions_skips_yanked_and_prerelease_releases(httpx_mock):
    httpx_mock.add_response(
        url="https://pypi.org/pypi/foo/json",
        json={
            "info": {"license": "MIT"},
            "releases": {
                "1.0.0": [{"yanked": False, "requires_python": None}],
                "1.0.1": [{"yanked": True, "requires_python": None}],
                "2.0.0rc1": [{"yanked": False, "requires_python": None}],
                "2.0.0.dev0": [{"yanked": False, "requires_python": None}],
                "not-a-version": [{"yanked": False, "requires_python": None}],
                "1.5.0": [],
            },
        },
    )

    async with httpx.AsyncClient() as client:
        info = await fetch_versions(client, "foo")

    assert [str(release.version) for release in info.releases] == ["1.0.0"]
    assert info.license == "MIT"
    assert info.error is None


async def test_fetch_versions_reports_404_as_not_found(httpx_mock):
    httpx_mock.add_response(url="https://pypi.org/pypi/doesnotexist/json", status_code=404)

    async with httpx.AsyncClient() as client:
        info = await fetch_versions(client, "doesnotexist")

    assert info.error == "Package not found on PyPI"
    assert info.releases == []


async def test_fetch_versions_reports_other_http_errors(httpx_mock):
    httpx_mock.add_response(url="https://pypi.org/pypi/foo/json", status_code=500)

    async with httpx.AsyncClient() as client:
        info = await fetch_versions(client, "foo")

    assert info.error == "PyPI returned HTTP 500"


async def test_fetch_versions_reports_network_errors(httpx_mock):
    httpx_mock.add_exception(httpx.ConnectError("boom"))

    async with httpx.AsyncClient() as client:
        info = await fetch_versions(client, "foo")

    assert info.error == "boom"


async def test_fetch_versions_falls_back_to_latest_info_when_pinned_lookup_fails(
    httpx_mock,
):
    httpx_mock.add_response(
        url="https://pypi.org/pypi/foo/json",
        json={
            "info": {"license": "MIT", "requires_dist": ["bar"]},
            "releases": {"1.0.0": [{"yanked": False, "requires_python": None}]},
        },
    )
    httpx_mock.add_response(
        url="https://pypi.org/pypi/foo/1.0.0/json",
        status_code=404,
    )

    async with httpx.AsyncClient() as client:
        info = await fetch_versions(client, "foo", pinned_version="1.0.0")

    assert info.license == "MIT"
    assert info.requires_dist == ["bar"]


async def test_fetch_versions_ignores_network_error_on_pinned_lookup(httpx_mock):
    httpx_mock.add_response(
        url="https://pypi.org/pypi/foo/json",
        json={
            "info": {"license": "MIT"},
            "releases": {"1.0.0": [{"yanked": False, "requires_python": None}]},
        },
    )
    httpx_mock.add_exception(
        httpx.ConnectError("boom"),
        url="https://pypi.org/pypi/foo/1.0.0/json",
    )

    async with httpx.AsyncClient() as client:
        info = await fetch_versions(client, "foo", pinned_version="1.0.0")

    assert info.license == "MIT"


def test_extract_license_prefers_short_spdx_style_license():
    assert _extract_license({"license": "MIT"}) == "MIT"


def test_extract_license_falls_back_to_classifier_when_license_field_is_unusable():
    info = {
        "license": "a" * 200,  # too long to be a real identifier
        "classifiers": [
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
        ],
    }
    assert _extract_license(info) == "MIT License"


def test_extract_license_returns_none_when_nothing_usable_is_present():
    assert _extract_license({"license": "", "classifiers": []}) is None
