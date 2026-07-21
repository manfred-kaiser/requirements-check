"""Unit tests for requirements_check.report."""

import json

from rich.console import Console

from requirements_check.models import (
    AnalysisResult,
    Dependency,
    UpdateLevel,
    Vulnerability,
)
from requirements_check.report import (
    render_html,
    render_json,
    render_table,
    render_vulnerability_details,
)


def _result():
    return AnalysisResult(
        dependencies=[
            Dependency(
                name="foo",
                raw_line="foo==1.0.0",
                pinned_version="1.0.0",
                latest_patch="1.0.1",
                latest_minor="1.1.0",
                latest_major="2.0.0",
                update_level=UpdateLevel.MAJOR,
                vulnerabilities=[
                    Vulnerability(
                        id="OSV-1",
                        summary="bad",
                        severity="9.0",
                        fixed_version="1.0.1",
                        fix_level=UpdateLevel.PATCH,
                        aliases=["CVE-2026-0001"],
                    ),
                ],
                minimum_safe_version="1.0.1",
                vulnerability_fix_level=UpdateLevel.PATCH,
            ),
            Dependency(
                name="bar",
                raw_line="bar==1.0.0",
                pinned_version="1.0.0",
                update_level=UpdateLevel.NONE,
            ),
        ],
    )


def test_render_json_round_trips_dependency_data():
    data = json.loads(render_json(_result()))
    names = {dep["name"] for dep in data["dependencies"]}
    assert names == {"foo", "bar"}

    foo = next(dep for dep in data["dependencies"] if dep["name"] == "foo")
    assert foo["update_level"] == "major"
    assert foo["vulnerabilities"][0]["id"] == "OSV-1"


def test_render_table_does_not_raise():
    console = Console(record=True, width=120)
    render_table(_result(), console=console)
    output = console.export_text()
    assert "foo" in output
    assert "bar" in output


def test_render_vulnerability_details_lists_each_vulnerability():
    console = Console(record=True, width=120)
    render_vulnerability_details(_result(), console=console)
    output = console.export_text()
    assert "OSV-1" in output
    assert "CVE-2026-0001" in output
    assert "1.0.1" in output


def test_render_vulnerability_details_handles_no_vulnerabilities():
    console = Console(record=True, width=120)
    clean_result = AnalysisResult(
        dependencies=[
            Dependency(
                name="bar",
                raw_line="bar==1.0.0",
                pinned_version="1.0.0",
                update_level=UpdateLevel.NONE,
            ),
        ],
    )
    render_vulnerability_details(clean_result, console=console)
    assert "No known vulnerabilities" in console.export_text()


def test_render_html_is_self_contained_and_includes_dependency_data():
    html = render_html(_result())
    assert html.strip().startswith("<!DOCTYPE html>") or "<html" in html
    assert "foo" in html
    assert "bar" in html
    assert "<style" in html or "style=" in html


def test_render_html_includes_vulnerability_details_when_requested():
    html = render_html(_result(), list_vulnerabilities=True)
    assert "OSV-1" in html
    assert "CVE-2026-0001" in html


def test_render_table_warns_about_missing_transitive_dependencies():
    result = _result()
    result.missing_transitive_dependencies = ["urllib3", "certifi"]

    console = Console(record=True, width=120)
    render_table(result, console=console)
    output = console.export_text()

    assert "urllib3" in output
    assert "certifi" in output
    assert "pip-compile" in output


def test_render_table_note_shows_constraint_cap():
    result = AnalysisResult(
        dependencies=[
            Dependency(
                name="foo",
                raw_line="foo==1.0.0",
                pinned_version="1.0.0",
                latest_major="2.0.0",
                update_level=UpdateLevel.MAJOR,
                constraint="<1.5",
                best_within_constraint="1.2.0",
            ),
        ],
    )

    console = Console(record=True, width=200)
    render_table(result, console=console)
    output = console.export_text()

    assert "<1.5" in output
    assert "1.2.0" in output
