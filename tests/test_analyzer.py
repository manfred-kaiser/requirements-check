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


def _mock_pypi(httpx_mock, name, json_body, pinned_version=None):
    """Register both the unversioned and (when given) version-specific PyPI
    endpoints with the same body — `fetch_versions()` calls the version-specific
    one for `info` (license/requires_dist) whenever a pinned version is known."""
    httpx_mock.add_response(url=f"https://pypi.org/pypi/{name}/json", json=json_body)
    if pinned_version:
        httpx_mock.add_response(
            url=f"https://pypi.org/pypi/{name}/{pinned_version}/json",
            json=json_body,
        )


async def test_analyze_suggests_patch_minor_and_major_updates(tmp_path, httpx_mock):
    path = _write(tmp_path, "foo==1.0.0\nbar==2.0.0\n")

    _mock_pypi(
        httpx_mock,
        "foo",
        {"releases": _releases("1.0.0", "1.0.1", "1.1.0", "2.0.0")},
        pinned_version="1.0.0",
    )
    _mock_pypi(
        httpx_mock,
        "bar",
        {"releases": _releases("2.0.0")},
        pinned_version="2.0.0",
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
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "foo"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.0.1"}],
                        },
                    ],
                },
            ],
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
    assert foo.vulnerabilities[0].fixed_version == "1.0.1"
    assert foo.vulnerabilities[0].fix_level == UpdateLevel.PATCH
    assert foo.minimum_safe_version == "1.0.1"
    assert foo.vulnerability_fix_level == UpdateLevel.PATCH

    bar = by_name["bar"]
    assert bar.update_level == UpdateLevel.NONE
    assert bar.latest_patch is None
    assert bar.vulnerabilities == []
    assert bar.vulnerability_fix_level is None
    assert result.has_vulnerabilities is True


async def test_analyze_marks_missing_package_as_not_found(tmp_path, httpx_mock):
    path = _write(tmp_path, "doesnotexist==1.0.0\n")

    httpx_mock.add_response(
        url="https://pypi.org/pypi/doesnotexist/json",
        status_code=404,
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": []}]},
    )

    result = await Analyzer(path).analyze()
    dep = result.dependencies[0]

    assert dep.update_level == UpdateLevel.NOT_FOUND
    assert dep.error is not None


async def test_analyze_skips_security_check_when_disabled(tmp_path, httpx_mock):
    path = _write(tmp_path, "foo==1.0.0\n")

    _mock_pypi(
        httpx_mock, "foo", {"releases": _releases("1.0.0")}, pinned_version="1.0.0"
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

    _mock_pypi(
        httpx_mock,
        "foo",
        {
            "releases": {
                "1.0.0": [{"yanked": False, "requires_python": None}],
                "2.0.0": [{"yanked": False, "requires_python": ">=4.0"}],
            },
        },
        pinned_version="1.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": []}]},
    )

    result = await Analyzer(path, python_version="3.12").analyze()
    dep = result.dependencies[0]

    assert dep.update_level == UpdateLevel.NONE
    assert dep.latest_major is None


async def test_analyze_vulnerability_fix_level_is_the_worst_of_all_fixes(
    tmp_path,
    httpx_mock,
):
    path = _write(tmp_path, "foo==1.0.0\n")

    _mock_pypi(
        httpx_mock,
        "foo",
        {"releases": _releases("1.0.0", "1.0.1", "2.0.0")},
        pinned_version="1.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": [{"id": "OSV-1"}, {"id": "OSV-2"}]}]},
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/OSV-1",
        json={
            "id": "OSV-1",
            "summary": "fixed in a patch release",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "foo"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.0.1"}],
                        },
                    ],
                },
            ],
        },
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/OSV-2",
        json={
            "id": "OSV-2",
            "summary": "only fixed in a major release",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "foo"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                        },
                    ],
                },
            ],
        },
    )

    result = await Analyzer(path).analyze()
    dep = result.dependencies[0]

    assert dep.minimum_safe_version == "2.0.0"
    assert dep.vulnerability_fix_level == UpdateLevel.MAJOR


async def test_analyze_no_fix_yet_when_osv_reports_no_fixed_version(
    tmp_path,
    httpx_mock,
):
    path = _write(tmp_path, "foo==1.0.0\n")

    _mock_pypi(
        httpx_mock, "foo", {"releases": _releases("1.0.0")}, pinned_version="1.0.0"
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": [{"id": "OSV-1"}]}]},
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/OSV-1",
        json={
            "id": "OSV-1",
            "summary": "still unpatched",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "foo"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                },
            ],
        },
    )

    result = await Analyzer(path).analyze()
    dep = result.dependencies[0]

    assert dep.vulnerabilities[0].fixed_version is None
    assert dep.vulnerability_fix_level == UpdateLevel.NO_FIX
    assert dep.minimum_safe_version is None


async def test_analyze_detects_missing_transitive_dependencies(tmp_path, httpx_mock):
    path = _write(tmp_path, "foo==1.0.0\n")

    _mock_pypi(
        httpx_mock,
        "foo",
        {
            "releases": _releases("1.0.0"),
            "info": {
                "requires_dist": [
                    "bar>=1.0",
                    "baz ; extra == 'dev'",  # optional extra, should be ignored
                ],
            },
        },
        pinned_version="1.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": []}]},
    )

    result = await Analyzer(path).analyze()

    assert result.missing_transitive_dependencies == ["bar"]


async def test_analyze_can_disable_transitive_check(tmp_path, httpx_mock):
    path = _write(tmp_path, "foo==1.0.0\n")

    _mock_pypi(
        httpx_mock,
        "foo",
        {
            "releases": _releases("1.0.0"),
            "info": {"requires_dist": ["bar>=1.0"]},
        },
        pinned_version="1.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": []}]},
    )

    result = await Analyzer(path, check_transitive=False).analyze()

    assert result.missing_transitive_dependencies == []


async def test_analyze_ignores_dependency_only_declared_for_other_python_versions(
    tmp_path,
    httpx_mock,
):
    path = _write(tmp_path, "foo==1.0.0\n")

    _mock_pypi(
        httpx_mock,
        "foo",
        {
            "releases": _releases("1.0.0"),
            "info": {"requires_dist": ['bar ; python_version < "3.8"']},
        },
        pinned_version="1.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": []}]},
    )

    result = await Analyzer(path, python_version="3.12").analyze()

    assert result.missing_transitive_dependencies == []


async def test_analyze_cross_checks_against_auto_detected_constraints_file(
    tmp_path,
    httpx_mock,
):
    path = _write(tmp_path, "foo==1.0.0\n")
    (tmp_path / "requirements.in").write_text("foo<1.5\n")

    _mock_pypi(
        httpx_mock,
        "foo",
        {"releases": _releases("1.0.0", "1.2.0", "2.0.0")},
        pinned_version="1.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": []}]},
    )

    result = await Analyzer(path).analyze()
    dep = result.dependencies[0]

    assert dep.constraint == "<1.5"
    assert dep.best_within_constraint == "1.2.0"
    assert dep.latest_major == "2.0.0"


async def test_analyze_uses_explicit_constraints_path(tmp_path, httpx_mock):
    path = _write(tmp_path, "foo==1.0.0\n")
    constraints_path = tmp_path / "custom-constraints.in"
    constraints_path.write_text("foo<1.5\n")

    _mock_pypi(
        httpx_mock,
        "foo",
        {"releases": _releases("1.0.0", "1.2.0", "2.0.0")},
        pinned_version="1.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": []}]},
    )

    result = await Analyzer(path, constraints_path=constraints_path).analyze()
    dep = result.dependencies[0]

    assert dep.constraint == "<1.5"
    assert dep.best_within_constraint == "1.2.0"
