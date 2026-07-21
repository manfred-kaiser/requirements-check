"""Unit tests for requirements_check.analyzer, with mocked HTTP responses."""

from requirements_check.analyzer import Analyzer
from requirements_check.models import UpdateLevel


def _write(tmp_path, content):
    path = tmp_path / "requirements.txt"
    path.write_text(content)
    return path


def _releases(*versions, requires_python=None):
    return {
        version: [{"yanked": False, "requires_python": requires_python}]
        for version in versions
    }


async def test_analyze_suggests_patch_minor_and_major_updates(tmp_path, httpx_mock):
    path = _write(tmp_path, "foo==1.0.0\nbar==2.0.0\n")

    httpx_mock.add_response(
        url="https://pypi.org/pypi/foo/json",
        json={"releases": _releases("1.0.0", "1.0.1", "1.1.0", "2.0.0")},
    )
    httpx_mock.add_response(
        url="https://pypi.org/pypi/bar/json",
        json={"releases": _releases("2.0.0")},
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": [{"id": "OSV-1"}]}, {"vulns": []}]},
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/OSV-1",
        json={
            "id": "OSV-1",
            "summary": "example vulnerability",
            "severity": [{"type": "CVSS_V3", "score": "9.0"}],
        },
    )

    result = await Analyzer(path).analyze()
    by_name = {dep.name: dep for dep in result.dependencies}

    foo = by_name["foo"]
    assert foo.update_level == UpdateLevel.MAJOR
    assert foo.latest_patch == "1.0.1"
    assert foo.latest_minor == "1.1.0"
    assert foo.latest_major == "2.0.0"
    assert len(foo.vulnerabilities) == 1
    assert foo.vulnerabilities[0].id == "OSV-1"

    bar = by_name["bar"]
    assert bar.update_level == UpdateLevel.NONE
    assert bar.latest_patch is None
    assert bar.vulnerabilities == []
    assert result.has_vulnerabilities is True


async def test_analyze_marks_missing_package_as_not_found(tmp_path, httpx_mock):
    path = _write(tmp_path, "doesnotexist==1.0.0\n")

    httpx_mock.add_response(url="https://pypi.org/pypi/doesnotexist/json", status_code=404)
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch", json={"results": [{"vulns": []}]}
    )

    result = await Analyzer(path).analyze()
    dep = result.dependencies[0]

    assert dep.update_level == UpdateLevel.NOT_FOUND
    assert dep.error is not None


async def test_analyze_skips_security_check_when_disabled(tmp_path, httpx_mock):
    path = _write(tmp_path, "foo==1.0.0\n")

    httpx_mock.add_response(
        url="https://pypi.org/pypi/foo/json", json={"releases": _releases("1.0.0")}
    )

    result = await Analyzer(path, check_security=False).analyze()

    assert result.dependencies[0].update_level == UpdateLevel.NONE
    assert result.dependencies[0].vulnerabilities == []


async def test_analyze_leaves_unsupported_requirements_unchecked(tmp_path, httpx_mock):
    path = _write(tmp_path, "git+https://github.com/example/foo.git#egg=foo\n")

    result = await Analyzer(path).analyze()

    assert result.dependencies[0].update_level == UpdateLevel.UNSUPPORTED


async def test_analyze_skips_incompatible_python_versions(tmp_path, httpx_mock):
    path = _write(tmp_path, "foo==1.0.0\n")

    httpx_mock.add_response(
        url="https://pypi.org/pypi/foo/json",
        json={
            "releases": {
                "1.0.0": [{"yanked": False, "requires_python": None}],
                "2.0.0": [{"yanked": False, "requires_python": ">=4.0"}],
            }
        },
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch", json={"results": [{"vulns": []}]}
    )

    result = await Analyzer(path, python_version="3.12").analyze()
    dep = result.dependencies[0]

    assert dep.update_level == UpdateLevel.NONE
    assert dep.latest_major is None
