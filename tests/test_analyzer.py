"""Unit tests for requirements_check.analyzer, with mocked HTTP responses."""

from packaging.version import Version

from requirements_check.analyzer import (
    Analyzer,
    _best_suggestions,
    _declared_runtime_dependencies,
    _is_compatible,
    _marker_applies,
)
from requirements_check.models import UpdateLevel


def _write(tmp_path, content):
    path = tmp_path / "requirements.txt"
    path.write_text(content)
    return path


def _write_pyproject(tmp_path, content):
    path = tmp_path / "pyproject.toml"
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


async def test_analyze_cross_checks_against_auto_detected_sibling_pyproject_toml(
    tmp_path,
    httpx_mock,
):
    path = _write(tmp_path, "foo==1.0.0\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "example"\ndependencies = ["foo<1.5"]\n',
    )

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


async def test_analyze_prefers_sibling_in_file_over_sibling_pyproject_toml(
    tmp_path,
    httpx_mock,
):
    path = _write(tmp_path, "foo==1.0.0\n")
    (tmp_path / "requirements.in").write_text("foo<1.5\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "example"\ndependencies = ["foo<1.9"]\n',
    )

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


async def test_analyze_suggests_latest_for_unpinned_dependency(tmp_path, httpx_mock):
    path = _write(tmp_path, "foo>=1.0\n")

    _mock_pypi(httpx_mock, "foo", {"releases": _releases("1.0.0", "1.5.0")})

    result = await Analyzer(path).analyze()
    dep = result.dependencies[0]

    assert dep.update_level == UpdateLevel.UNPINNED
    assert dep.latest_major == "1.5.0"


async def test_analyze_vulnerability_fix_level_is_minor_when_fix_is_a_minor_bump(
    tmp_path,
    httpx_mock,
):
    path = _write(tmp_path, "foo==1.0.0\n")

    _mock_pypi(
        httpx_mock,
        "foo",
        {"releases": _releases("1.0.0", "1.1.0")},
        pinned_version="1.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": [{"id": "OSV-1"}]}]},
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/OSV-1",
        json={
            "id": "OSV-1",
            "summary": "fixed in a minor release",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "foo"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.1.0"}],
                        },
                    ],
                },
            ],
        },
    )

    result = await Analyzer(path).analyze()
    dep = result.dependencies[0]

    assert dep.minimum_safe_version == "1.1.0"
    assert dep.vulnerability_fix_level == UpdateLevel.MINOR


def test_is_compatible_treats_invalid_specifier_as_compatible():
    assert _is_compatible("not a valid specifier!!", Version("1.0.0")) is True


def test_best_suggestions_treats_invalid_pinned_version_as_no_update():
    result = _best_suggestions("not-a-version", [Version("1.0.0")])
    assert result == (None, None, None, UpdateLevel.NONE)


def test_best_suggestions_detects_minor_update():
    _patch, minor, _major, level = _best_suggestions(
        "1.0.0",
        [Version("1.0.0"), Version("1.1.0")],
    )
    assert minor == "1.1.0"
    assert level == UpdateLevel.MINOR


def test_best_suggestions_detects_patch_update():
    patch, _minor, _major, level = _best_suggestions(
        "1.0.0",
        [Version("1.0.0"), Version("1.0.1")],
    )
    assert patch == "1.0.1"
    assert level == UpdateLevel.PATCH


def test_marker_applies_treats_an_unevaluable_marker_as_applying():
    class _ExplodingMarker:
        def evaluate(self, environment=None):  # noqa: ARG002
            raise ValueError("boom")

    assert _marker_applies(_ExplodingMarker(), {}) is True


def test_declared_runtime_dependencies_skips_unparsable_requirement_strings():
    declared = _declared_runtime_dependencies(
        ["not a valid requirement !!!", "bar>=1.0"],
        Version("3.12"),
    )
    assert declared == {"bar": "bar"}


async def test_analyze_flags_a_sibling_hard_pinned_dependency_as_locked(
    tmp_path,
    httpx_mock,
):
    path = _write(tmp_path, "wrapper==1.0.0\ncore==2.0.0\n")

    _mock_pypi(
        httpx_mock,
        "wrapper",
        {
            "releases": _releases("1.0.0"),
            # "other>=1.0" is a range, not a hard pin, and should be ignored
            # by the lock check (only exact `==` pins count as a lock).
            "info": {"requires_dist": ["core==2.0.0", "other>=1.0"]},
        },
        pinned_version="1.0.0",
    )
    _mock_pypi(
        httpx_mock,
        "core",
        {"releases": _releases("2.0.0", "2.1.0")},
        pinned_version="2.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": []}, {"vulns": []}]},
    )

    result = await Analyzer(path).analyze()
    core = next(dep for dep in result.dependencies if dep.name == "core")

    assert core.latest_minor == "2.1.0"
    assert core.locked_to == "2.0.0"
    assert core.locked_by == "wrapper==1.0.0"


async def test_analyze_does_not_flag_a_lock_that_does_not_cap_anything(
    tmp_path,
    httpx_mock,
):
    path = _write(tmp_path, "wrapper==1.0.0\ncore==2.0.0\n")

    _mock_pypi(
        httpx_mock,
        "wrapper",
        {
            "releases": _releases("1.0.0"),
            "info": {"requires_dist": ["core==2.0.0"]},
        },
        pinned_version="1.0.0",
    )
    _mock_pypi(
        httpx_mock,
        "core",
        {"releases": _releases("2.0.0")},
        pinned_version="2.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": []}, {"vulns": []}]},
    )

    result = await Analyzer(path).analyze()
    core = next(dep for dep in result.dependencies if dep.name == "core")

    assert core.locked_to is None
    assert core.locked_by is None


async def test_analyze_self_applies_pyproject_toml_dependencies_as_constraints(
    tmp_path,
    httpx_mock,
):
    path = tmp_path / "pyproject.toml"
    path.write_text('[project]\nname = "example"\ndependencies = ["foo<1.5,>=1.0"]\n')

    _mock_pypi(httpx_mock, "foo", {"releases": _releases("1.0.0", "1.2.0", "2.0.0")})

    result = await Analyzer(path).analyze()
    dep = result.dependencies[0]

    assert dep.constraint is not None
    assert ">=1.0" in dep.constraint
    assert "<1.5" in dep.constraint
    assert dep.best_within_constraint == "1.2.0"
    assert dep.latest_major == "2.0.0"


async def test_analyze_skips_transitive_check_for_pyproject_toml_input(
    tmp_path,
    httpx_mock,
):
    path = tmp_path / "pyproject.toml"
    path.write_text('[project]\nname = "example"\ndependencies = ["foo"]\n')

    _mock_pypi(
        httpx_mock,
        "foo",
        {
            "releases": _releases("1.0.0"),
            "info": {"requires_dist": ["bar>=1.0"]},
        },
    )

    result = await Analyzer(path).analyze()

    assert result.missing_transitive_dependencies == []


async def test_analyze_shows_source_specifier_for_a_single_source_extra_dependency(
    tmp_path,
    httpx_mock,
):
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dependencies = ["httpx>=0.20"]

        [project.optional-dependencies]
        docs = ["sphinx>=7.0,<8.0"]
        """,
    )

    _mock_pypi(httpx_mock, "httpx", {"releases": _releases("0.20.0")})
    _mock_pypi(httpx_mock, "sphinx", {"releases": _releases("7.5.0")})

    result = await Analyzer(path, extras=["docs"], check_security=False).analyze()
    by_name = {dep.name: dep for dep in result.dependencies}

    sphinx_dep = by_name["sphinx"]
    assert sphinx_dep.sources == ["docs"]
    assert "docs" in sphinx_dep.source_specifiers
    assert ">=7.0" in sphinx_dep.source_specifiers["docs"]
    assert "<8.0" in sphinx_dep.source_specifiers["docs"]


async def test_analyze_merges_a_package_required_by_multiple_extras(
    tmp_path,
    httpx_mock,
):
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dependencies = ["httpx>=0.20"]

        [project.optional-dependencies]
        docs = ["httpx<0.28", "sphinx"]
        """,
    )

    _mock_pypi(
        httpx_mock, "httpx", {"releases": _releases("0.20.0", "0.27.0", "0.28.0")}
    )
    _mock_pypi(httpx_mock, "sphinx", {"releases": _releases("7.0.0")})

    result = await Analyzer(path, extras=["docs"]).analyze()
    by_name = {dep.name: dep for dep in result.dependencies}

    httpx_dep = by_name["httpx"]
    assert sorted(httpx_dep.sources) == ["dependencies", "docs"]
    assert httpx_dep.error is None
    assert ">=0.20" in httpx_dep.source_specifiers["dependencies"]
    assert "<0.28" in httpx_dep.source_specifiers["docs"]
    assert by_name["sphinx"].sources == ["docs"]
    assert by_name["sphinx"].source_specifiers == {}


async def test_analyze_shows_a_range_from_one_group_alongside_a_pin_from_another(
    tmp_path,
    httpx_mock,
):
    # Mirrors a real-world pattern: a loose range in the core dependencies
    # (e.g. paramiko>=4.0,<6.0) plus an exact pin from a "production" extra
    # pointing at a fully resolved requirements.txt.
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dependencies = ["paramiko>=4.0,<6.0"]

        [project.optional-dependencies]
        production = ["paramiko==5.0.0"]
        """,
    )

    _mock_pypi(
        httpx_mock,
        "paramiko",
        {"releases": _releases("5.0.0")},
        pinned_version="5.0.0",
    )

    result = await Analyzer(
        path,
        extras=["production"],
        check_security=False,
    ).analyze()
    dep = result.dependencies[0]

    assert dep.pinned_version == "5.0.0"
    assert "production" not in dep.source_specifiers  # bare pin, redundant with Pinned
    assert ">=4.0" in dep.source_specifiers["dependencies"]
    assert "<6.0" in dep.source_specifiers["dependencies"]


async def test_analyze_flags_conflicting_pinned_versions_across_extras(
    tmp_path,
    httpx_mock,
):
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dependencies = ["httpx==1.0.0"]

        [project.optional-dependencies]
        test = ["httpx==2.0.0"]
        """,
    )

    result = await Analyzer(path, extras=["test"], check_security=False).analyze()
    dep = result.dependencies[0]

    assert dep.update_level == UpdateLevel.UNSUPPORTED
    assert "conflicting pinned versions" in dep.error
    assert sorted(dep.sources) == ["dependencies", "test"]


async def test_analyze_flags_an_unresolvable_range_conflict_across_extras(
    tmp_path,
    httpx_mock,
):
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dependencies = ["httpx>=0.20"]

        [project.optional-dependencies]
        legacy = ["httpx<0.10"]
        """,
    )

    _mock_pypi(
        httpx_mock, "httpx", {"releases": _releases("0.5.0", "0.20.0", "0.27.0")}
    )

    result = await Analyzer(path, extras=["legacy"], check_security=False).analyze()
    dep = result.dependencies[0]

    assert dep.error is not None
    assert "conflicting version requirements" in dep.error


async def test_analyze_reports_a_url_requirement_across_extras_as_a_conflict(
    tmp_path,
    httpx_mock,
):
    # A URL requirement parses fine (so its name matches the other group's
    # entry, triggering a merge) but is itself unsupported/unversionable.
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dependencies = ["httpx>=0.20"]

        [project.optional-dependencies]
        broken = ["httpx @ https://example.com/httpx.whl"]
        """,
    )

    result = await Analyzer(path, extras=["broken"], check_security=False).analyze()
    dep = result.dependencies[0]

    assert dep.name == "httpx"
    assert dep.update_level == UpdateLevel.UNSUPPORTED
    assert "unparsable requirement" in dep.error


async def test_analyze_leaves_a_single_source_url_requirement_unsupported(
    tmp_path,
    httpx_mock,
):
    # A URL requirement in an extra, for a package not present in any other
    # group — goes through the single-entry passthrough, not the merge path.
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dependencies = ["httpx>=0.20"]

        [project.optional-dependencies]
        broken = ["foo @ https://example.com/foo.whl"]
        """,
    )

    _mock_pypi(httpx_mock, "httpx", {"releases": _releases("0.20.0")})

    result = await Analyzer(path, extras=["broken"], check_security=False).analyze()
    dep = next(d for d in result.dependencies if d.name == "foo")

    assert dep.update_level == UpdateLevel.UNSUPPORTED
    assert dep.sources == ["broken"]
    assert dep.source_specifiers == {}
