# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

## [0.1.0] - 2026-07-21

Initial release.

### Added

- **Update checks**: scans a `requirements.txt` file and reports, per pinned dependency, the best available patch/minor/major update, by querying the PyPI JSON API directly — no installed environment needed; the table blanks out a column when it repeats the value shown to its left, so a package with no separate minor release doesn't show the same version twice
- **Vulnerability checks**: cross-checks every pinned version against [OSV.dev](https://osv.dev), including the fix level needed (patch/minor/major/no known fix yet) and deduplication of advisories listed under multiple IDs (e.g. GHSA + PYSEC for the same issue); an unpinned dependency is explicitly reported as `not checked (no pinned version)` rather than a blank result, since OSV needs an exact version and an unchecked dependency isn't the same as a clean one
- **Coverage awareness**: warns when pinned packages declare dependencies not listed in the file (a sign it isn't fully resolved), and cross-checks against a loose `.in` source or a `pyproject.toml` (auto-detected) to flag when your own version constraints — not just PyPI availability — are capping an update
- **Sibling-locked dependencies**: flags when a checked package's own update is blocked by another checked, pinned package hard-requiring an exact version of it (e.g. `pydantic` pinning `pydantic-core` in lockstep) — a newer release existing on PyPI doesn't mean it's actually installable
- **`pyproject.toml` support**: reads a [PEP 621](https://peps.python.org/pep-0621/) `pyproject.toml`'s direct `[project.dependencies]` as a standalone input (update-checkable, unpinned) or as a constraints source against a real lock file (auto-detected as a sibling, same as a `.in` file); resolves `dynamic = ["dependencies"]` via the `hatch-requirements-txt` plugin's convention where present
- **`--extra NAME`**: also checks a `[project.optional-dependencies]` extra from a `pyproject.toml` (repeatable); a package required by several groups is merged into one row with a per-group range breakdown, or reported as an error if no release satisfies all of them
- **Output formats**: table (default), `--json`, `--sbom` (CycloneDX 1.6, schema-validated, both export and auto-detected import), `--html` (self-contained report), `--sarif` (SARIF 2.1.0, schema-validated, with per-line locations for GitHub/Azure code scanning), and `--list-vulnerabilities` for a full per-CVE breakdown
- **CLI ergonomics**: `--output`/`-o` to write to a file, `--no-color`, `--fail-on-vulnerability` with distinct exit codes, `--python-version`/`--proxy`/`--ca-bundle`/`--constraints` for environment control
- Usable as a library via `requirements_check.Analyzer` (async `analyze()` and sync `analyze_sync()`), ships a `py.typed` marker
- **GitHub Action** (`action.yml`): composite action wrapping the CLI, with automatic SARIF upload to code scanning
- Documented CI pipeline integration, network access, and current limitations; `examples/` directory with generated sample reports

[Unreleased]: https://github.com/manfred-kaiser/requirements-check/compare/0.1.0...main
[0.1.0]: https://github.com/manfred-kaiser/requirements-check/releases/tag/0.1.0
