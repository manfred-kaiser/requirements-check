"""Unit tests for requirements_check.parser."""

import json

import pytest

from requirements_check.models import UpdateLevel
from requirements_check.parser import (
    DynamicDependenciesError,
    UnknownExtraError,
    is_cyclonedx_sbom,
    is_pyproject_toml,
    parse_constraints,
    parse_cyclonedx_sbom,
    parse_dependencies,
    parse_pyproject_extra,
    parse_pyproject_toml,
    parse_requirements,
)


def _write(tmp_path, content):
    path = tmp_path / "requirements.txt"
    path.write_text(content)
    return path


def test_pinned_requirement(tmp_path):
    path = _write(tmp_path, "requests==2.31.0\n")
    deps = parse_requirements(path)
    assert len(deps) == 1
    assert deps[0].name == "requests"
    assert deps[0].pinned_version == "2.31.0"
    assert deps[0].update_level == UpdateLevel.NONE


def test_blank_lines_and_comments_are_skipped(tmp_path):
    path = _write(
        tmp_path,
        "\n# full line comment\nrequests==2.31.0  # inline comment\n\n",
    )
    deps = parse_requirements(path)
    assert len(deps) == 1
    assert deps[0].name == "requests"
    assert deps[0].pinned_version == "2.31.0"


def test_option_lines_are_skipped(tmp_path):
    path = _write(
        tmp_path,
        "-r other.txt\n--index-url https://example.com/simple\n-e .\nrequests==2.31.0\n",
    )
    deps = parse_requirements(path)
    assert len(deps) == 1
    assert deps[0].name == "requests"


def test_extras_are_stripped_from_name(tmp_path):
    path = _write(tmp_path, "requests[security]==2.31.0\n")
    deps = parse_requirements(path)
    assert deps[0].name == "requests"
    assert deps[0].pinned_version == "2.31.0"


def test_unpinned_requirement_has_no_pinned_version(tmp_path):
    path = _write(tmp_path, "numpy>=1.20\n")
    deps = parse_requirements(path)
    assert deps[0].name == "numpy"
    assert deps[0].pinned_version is None


def test_bare_requirement_without_specifier(tmp_path):
    path = _write(tmp_path, "click\n")
    deps = parse_requirements(path)
    assert deps[0].name == "click"
    assert deps[0].pinned_version is None


def test_direct_url_requirement_is_unsupported(tmp_path):
    path = _write(tmp_path, "foo @ https://example.com/foo-1.0.0-py3-none-any.whl\n")
    deps = parse_requirements(path)
    assert deps[0].update_level == UpdateLevel.UNSUPPORTED


def test_vcs_requirement_is_unsupported(tmp_path):
    path = _write(tmp_path, "git+https://github.com/example/foo.git#egg=foo\n")
    deps = parse_requirements(path)
    assert deps[0].update_level == UpdateLevel.UNSUPPORTED


def test_parse_constraints_captures_version_ranges(tmp_path):
    path = tmp_path / "requirements.in"
    path.write_text("flask<3.0,>=2.0\nrequests\n# comment\nclick~=8.0\n")

    constraints = parse_constraints(path)

    assert str(constraints["flask"]) == "<3.0,>=2.0" or ">=2.0" in str(
        constraints["flask"],
    )
    assert "requests" not in constraints  # unconstrained, no specifier
    assert "click" in constraints


def test_parse_constraints_skips_unparsable_lines(tmp_path):
    path = tmp_path / "requirements.in"
    path.write_text("not a valid requirement !!!\nbar<2.0\n")

    constraints = parse_constraints(path)

    assert "bar" in constraints


def test_parse_constraints_skips_urls_and_options(tmp_path):
    path = tmp_path / "requirements.in"
    path.write_text("-r base.in\nfoo @ https://example.com/foo.whl\nbar<2.0\n")

    constraints = parse_constraints(path)

    assert "foo" not in constraints
    assert "bar" in constraints


def test_line_numbers_are_tracked(tmp_path):
    path = _write(
        tmp_path,
        "# comment\n\nfoo==1.0.0\nbar>=2.0\ngit+https://example.com/baz.git#egg=baz\n",
    )
    deps = parse_requirements(path)

    by_name = {dep.name: dep for dep in deps}
    assert by_name["foo"].line_number == 3
    assert by_name["bar"].line_number == 4
    assert deps[2].line_number == 5  # the unsupported VCS line


def _write_sbom(tmp_path, components):
    path = tmp_path / "sbom.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": components,
            },
        ),
    )
    return path


def test_is_cyclonedx_sbom_detects_valid_sbom(tmp_path):
    path = _write_sbom(tmp_path, [])
    assert is_cyclonedx_sbom(path) is True


def test_is_cyclonedx_sbom_rejects_plain_requirements_txt(tmp_path):
    path = _write(tmp_path, "foo==1.0.0\n")
    assert is_cyclonedx_sbom(path) is False


def test_parse_cyclonedx_sbom_extracts_pypi_components(tmp_path):
    path = _write_sbom(
        tmp_path,
        [
            {
                "type": "library",
                "purl": "pkg:pypi/foo@1.0.0",
                "name": "foo",
                "version": "1.0.0",
            },
            {
                "type": "library",
                "purl": "pkg:npm/not-python@2.0.0",
                "name": "not-python",
                "version": "2.0.0",
            },
            {
                "type": "library",
                "purl": "pkg:pypi/bar@2.5.0",
                "name": "bar",
                "version": "2.5.0",
            },
        ],
    )

    deps = parse_cyclonedx_sbom(path)

    assert {dep.name for dep in deps} == {"foo", "bar"}
    foo = next(dep for dep in deps if dep.name == "foo")
    assert foo.pinned_version == "1.0.0"
    assert foo.line_number is None


def test_parse_cyclonedx_sbom_skips_components_missing_name_or_version(tmp_path):
    path = _write_sbom(
        tmp_path,
        [
            {"type": "library", "purl": "pkg:pypi/foo@1.0.0", "version": "1.0.0"},
            {"type": "library", "purl": "pkg:pypi/bar@2.0.0", "name": "bar"},
            {
                "type": "library",
                "purl": "pkg:pypi/baz@3.0.0",
                "name": "baz",
                "version": "3.0.0",
            },
        ],
    )

    deps = parse_cyclonedx_sbom(path)

    assert {dep.name for dep in deps} == {"baz"}


def test_parse_dependencies_auto_detects_sbom_vs_requirements(tmp_path):
    sbom_path = _write_sbom(
        tmp_path,
        [
            {
                "type": "library",
                "purl": "pkg:pypi/foo@1.0.0",
                "name": "foo",
                "version": "1.0.0",
            }
        ],
    )
    txt_path = _write(tmp_path, "bar==2.0.0\n")

    assert [dep.name for dep in parse_dependencies(sbom_path)] == ["foo"]
    assert [dep.name for dep in parse_dependencies(txt_path)] == ["bar"]


def _write_pyproject(tmp_path, content):
    path = tmp_path / "pyproject.toml"
    path.write_text(content)
    return path


def test_is_pyproject_toml_detects_a_project_table(tmp_path):
    path = _write_pyproject(tmp_path, '[project]\nname = "example"\n')
    assert is_pyproject_toml(path) is True


def test_is_pyproject_toml_rejects_a_plain_requirements_txt(tmp_path):
    path = _write(tmp_path, "foo==1.0.0\n")
    assert is_pyproject_toml(path) is False


def test_is_pyproject_toml_rejects_toml_without_a_project_table(tmp_path):
    path = _write_pyproject(tmp_path, '[build-system]\nrequires = ["hatchling"]\n')
    assert is_pyproject_toml(path) is False


def test_is_pyproject_toml_rejects_malformed_toml(tmp_path):
    path = _write_pyproject(tmp_path, "not valid [[[ toml")
    assert is_pyproject_toml(path) is False


def test_is_pyproject_toml_rejects_a_missing_file(tmp_path):
    assert is_pyproject_toml(tmp_path / "does-not-exist.toml") is False


def test_parse_pyproject_toml_extracts_direct_dependencies(tmp_path):
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dependencies = ["httpx>=0.25", "packaging==24.0"]
        """,
    )

    deps = parse_pyproject_toml(path)

    by_name = {dep.name: dep for dep in deps}
    assert by_name["httpx"].pinned_version is None
    assert by_name["httpx"].update_level == UpdateLevel.NONE
    assert by_name["packaging"].pinned_version == "24.0"
    assert all(dep.line_number is None for dep in deps)


def test_parse_pyproject_toml_returns_empty_list_when_no_dependencies_declared(
    tmp_path,
):
    path = _write_pyproject(tmp_path, '[project]\nname = "example"\n')
    assert parse_pyproject_toml(path) == []


def test_parse_pyproject_toml_flags_unparsable_entries_as_unsupported(tmp_path):
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dependencies = ["not a valid requirement !!!"]
        """,
    )

    deps = parse_pyproject_toml(path)

    assert deps[0].update_level == UpdateLevel.UNSUPPORTED


def test_parse_pyproject_toml_raises_when_dependencies_are_dynamic_and_unresolvable(
    tmp_path,
):
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dynamic = ["dependencies"]
        """,
    )

    with pytest.raises(DynamicDependenciesError):
        parse_pyproject_toml(path)


def test_parse_pyproject_toml_resolves_dynamic_dependencies_via_hatch_requirements_txt_hook(
    tmp_path,
):
    (tmp_path / "reqs.txt").write_text("foo>=1.0\nbar==2.0.0\n")
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dynamic = ["dependencies"]

        [tool.hatch.metadata.hooks.requirements_txt]
        files = ["reqs.txt"]
        """,
    )

    deps = parse_pyproject_toml(path)

    by_name = {dep.name: dep for dep in deps}
    assert by_name["foo"].pinned_version is None
    assert by_name["bar"].pinned_version == "2.0.0"


def test_parse_pyproject_toml_raises_when_dynamic_and_no_hook_files_configured(
    tmp_path,
):
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dynamic = ["dependencies"]

        [tool.hatch.metadata.hooks.requirements_txt]
        """,
    )

    with pytest.raises(DynamicDependenciesError):
        parse_pyproject_toml(path)


def test_parse_dependencies_auto_detects_pyproject_toml(tmp_path):
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dependencies = ["httpx>=0.25"]
        """,
    )

    assert [dep.name for dep in parse_dependencies(path)] == ["httpx"]


def test_parse_constraints_extracts_ranges_from_pyproject_toml(tmp_path):
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dependencies = ["flask<3.0,>=2.0", "requests"]
        """,
    )

    constraints = parse_constraints(path)

    assert "flask" in constraints
    assert "requests" not in constraints  # unconstrained, no specifier


def test_parse_constraints_propagates_dynamic_dependencies_error(tmp_path):
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dynamic = ["dependencies"]
        """,
    )

    with pytest.raises(DynamicDependenciesError):
        parse_constraints(path)


def test_parse_pyproject_extra_extracts_a_static_extra(tmp_path):
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dependencies = ["httpx>=0.25"]

        [project.optional-dependencies]
        docs = ["sphinx>=7.0", "sphinx-copybutton"]
        """,
    )

    deps = parse_pyproject_extra(path, "docs")

    assert {dep.name for dep in deps} == {"sphinx", "sphinx-copybutton"}


def test_parse_pyproject_extra_raises_for_an_unknown_static_extra(tmp_path):
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dependencies = ["httpx>=0.25"]

        [project.optional-dependencies]
        docs = ["sphinx>=7.0"]
        """,
    )

    with pytest.raises(UnknownExtraError):
        parse_pyproject_extra(path, "test")


def test_parse_pyproject_extra_resolves_via_hatch_requirements_txt_hook(tmp_path):
    (tmp_path / "doc-requirements.txt").write_text("sphinx>=7.0\n")
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dynamic = ["dependencies", "optional-dependencies"]

        [tool.hatch.metadata.hooks.requirements_txt]
        files = ["reqs.txt"]

        [tool.hatch.metadata.hooks.requirements_txt.optional-dependencies]
        docs = ["doc-requirements.txt"]
        """,
    )
    (tmp_path / "reqs.txt").write_text("httpx>=0.25\n")

    deps = parse_pyproject_extra(path, "docs")

    assert [dep.name for dep in deps] == ["sphinx"]


def test_parse_pyproject_extra_raises_for_an_unknown_dynamic_extra(tmp_path):
    (tmp_path / "reqs.txt").write_text("httpx>=0.25\n")
    path = _write_pyproject(
        tmp_path,
        """
        [project]
        name = "example"
        dynamic = ["dependencies", "optional-dependencies"]

        [tool.hatch.metadata.hooks.requirements_txt]
        files = ["reqs.txt"]
        """,
    )

    with pytest.raises(UnknownExtraError):
        parse_pyproject_extra(path, "docs")
