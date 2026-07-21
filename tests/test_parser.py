"""Unit tests for requirements_check.parser."""

from requirements_check.models import UpdateLevel
from requirements_check.parser import parse_requirements


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
