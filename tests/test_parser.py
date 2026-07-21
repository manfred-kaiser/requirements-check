"""Unit tests for requirements_check.parser."""

import json

from requirements_check.models import UpdateLevel
from requirements_check.parser import (
    is_cyclonedx_sbom,
    parse_constraints,
    parse_cyclonedx_sbom,
    parse_dependencies,
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
