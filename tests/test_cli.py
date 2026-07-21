"""Unit tests for requirements_check.cli."""

import json

import pytest

from requirements_check.cli import EXIT_USAGE_ERROR, EXIT_VULNERABILITY_FOUND, main


def _write(tmp_path, content):
    path = tmp_path / "requirements.txt"
    path.write_text(content)
    return path


def _mock_pypi(httpx_mock, name, json_body, pinned_version=None):
    httpx_mock.add_response(url=f"https://pypi.org/pypi/{name}/json", json=json_body)
    if pinned_version:
        httpx_mock.add_response(
            url=f"https://pypi.org/pypi/{name}/{pinned_version}/json",
            json=json_body,
        )


def test_main_exits_with_usage_error_when_file_is_missing(tmp_path, capsys):
    missing = tmp_path / "does-not-exist.txt"

    with pytest.raises(SystemExit) as exc_info:
        main([str(missing)])

    assert exc_info.value.code == EXIT_USAGE_ERROR
    assert "not found" in capsys.readouterr().err


def test_main_prints_json_output(tmp_path, httpx_mock, capsys):
    path = _write(tmp_path, "foo==1.0.0\n")

    _mock_pypi(
        httpx_mock,
        "foo",
        {"releases": {"1.0.0": [{"yanked": False, "requires_python": None}]}},
        pinned_version="1.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": []}]},
    )

    main([str(path), "--json"])

    data = json.loads(capsys.readouterr().out)
    assert data["dependencies"][0]["name"] == "foo"


def test_main_exits_with_vulnerability_status_when_fail_flag_set(
    tmp_path,
    httpx_mock,
    capsys,
):
    path = _write(tmp_path, "foo==1.0.0\n")

    _mock_pypi(
        httpx_mock,
        "foo",
        {"releases": {"1.0.0": [{"yanked": False, "requires_python": None}]}},
        pinned_version="1.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": [{"id": "GHSA-x"}]}]},
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/GHSA-x",
        json={"id": "GHSA-x", "summary": "bad"},
    )

    with pytest.raises(SystemExit) as exc_info:
        main([str(path), "--fail-on-vulnerability", "--no-color"])

    assert exc_info.value.code == EXIT_VULNERABILITY_FOUND
    assert "foo" in capsys.readouterr().out


def test_main_prints_sbom_output(tmp_path, httpx_mock, capsys):
    path = _write(tmp_path, "foo==1.0.0\n")

    _mock_pypi(
        httpx_mock,
        "foo",
        {"releases": {"1.0.0": [{"yanked": False, "requires_python": None}]}},
        pinned_version="1.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": []}]},
    )

    main([str(path), "--sbom"])

    bom = json.loads(capsys.readouterr().out)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["components"][0]["name"] == "foo"


def test_main_prints_html_output(tmp_path, httpx_mock, capsys):
    path = _write(tmp_path, "foo==1.0.0\n")

    _mock_pypi(
        httpx_mock,
        "foo",
        {"releases": {"1.0.0": [{"yanked": False, "requires_python": None}]}},
        pinned_version="1.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": []}]},
    )

    main([str(path), "--html"])

    output = capsys.readouterr().out
    assert "<html" in output
    assert "foo" in output


def test_main_writes_json_to_output_file_instead_of_stdout(
    tmp_path,
    httpx_mock,
    capsys,
):
    path = _write(tmp_path, "foo==1.0.0\n")
    out_file = tmp_path / "report.json"

    _mock_pypi(
        httpx_mock,
        "foo",
        {"releases": {"1.0.0": [{"yanked": False, "requires_python": None}]}},
        pinned_version="1.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": []}]},
    )

    main([str(path), "--json", "--output", str(out_file)])

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Wrote report to" in captured.err

    data = json.loads(out_file.read_text())
    assert data["dependencies"][0]["name"] == "foo"


def test_main_prints_sarif_output(tmp_path, httpx_mock, capsys):
    path = _write(tmp_path, "foo==1.0.0\n")

    _mock_pypi(
        httpx_mock,
        "foo",
        {"releases": {"1.0.0": [{"yanked": False, "requires_python": None}]}},
        pinned_version="1.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": [{"id": "GHSA-x"}]}]},
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/GHSA-x",
        json={"id": "GHSA-x", "summary": "bad"},
    )

    main([str(path), "--sarif"])

    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "GHSA-x"
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"] == str(path)


def test_main_reads_cyclonedx_sbom_as_input(tmp_path, httpx_mock, capsys):
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "type": "library",
                        "purl": "pkg:pypi/foo@1.0.0",
                        "name": "foo",
                        "version": "1.0.0",
                    },
                ],
            },
        ),
    )

    _mock_pypi(
        httpx_mock,
        "foo",
        {"releases": {"1.0.0": [{"yanked": False, "requires_python": None}]}},
        pinned_version="1.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": []}]},
    )

    main([str(sbom_path), "--json"])

    data = json.loads(capsys.readouterr().out)
    assert data["dependencies"][0]["name"] == "foo"
    assert data["dependencies"][0]["pinned_version"] == "1.0.0"


def test_main_lists_vulnerability_details_alongside_the_table(
    tmp_path,
    httpx_mock,
    capsys,
):
    path = _write(tmp_path, "foo==1.0.0\n")

    _mock_pypi(
        httpx_mock,
        "foo",
        {"releases": {"1.0.0": [{"yanked": False, "requires_python": None}]}},
        pinned_version="1.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": [{"id": "GHSA-x"}]}]},
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/GHSA-x",
        json={"id": "GHSA-x", "summary": "bad"},
    )

    main([str(path), "--list-vulnerabilities", "--no-color"])

    output = capsys.readouterr().out
    assert "requirements-check" in output
    assert "Vulnerability details" in output
    assert "GHSA-x" in output


def test_main_writes_table_to_output_file(tmp_path, httpx_mock, capsys):
    path = _write(tmp_path, "foo==1.0.0\n")
    out_file = tmp_path / "report.txt"

    _mock_pypi(
        httpx_mock,
        "foo",
        {"releases": {"1.0.0": [{"yanked": False, "requires_python": None}]}},
        pinned_version="1.0.0",
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": []}]},
    )

    main([str(path), "-o", str(out_file)])

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "foo" in out_file.read_text()
