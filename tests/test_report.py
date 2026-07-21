"""Unit tests for requirements_check.report."""

import json

from rich.console import Console

from requirements_check.models import AnalysisResult, Dependency, UpdateLevel, Vulnerability
from requirements_check.report import render_json, render_table


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
                vulnerabilities=[Vulnerability(id="OSV-1", summary="bad", severity="9.0")],
            ),
            Dependency(
                name="bar",
                raw_line="bar==1.0.0",
                pinned_version="1.0.0",
                update_level=UpdateLevel.NONE,
            ),
        ]
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
