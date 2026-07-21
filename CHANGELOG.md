# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

## [0.1.0] - 2026-07-21

Initial release.

### Added

- **Update checks**: scans a `requirements.txt` file and reports, per pinned dependency, the best available patch/minor/major update, by querying the PyPI JSON API directly — no installed environment needed
- **Vulnerability checks**: cross-checks every pinned version against [OSV.dev](https://osv.dev), including the fix level needed (patch/minor/major/no known fix yet) and deduplication of advisories listed under multiple IDs (e.g. GHSA + PYSEC for the same issue)
- **Coverage awareness**: warns when pinned packages declare dependencies not listed in the file (a sign it isn't fully resolved), and cross-checks against a loose `.in` source (e.g. from pip-compile) to flag when your own version constraints — not just PyPI availability — are capping an update
- **Output formats**: table (default), `--json`, `--sbom` (CycloneDX 1.6, schema-validated), `--html` (self-contained report), and `--list-vulnerabilities` for a full per-CVE breakdown
- **CLI ergonomics**: `--output`/`-o` to write to a file, `--no-color`, `--fail-on-vulnerability` with distinct exit codes, `--python-version`/`--proxy`/`--ca-bundle`/`--constraints` for environment control
- Usable as a library via `requirements_check.Analyzer` (async `analyze()` and sync `analyze_sync()`), ships a `py.typed` marker
- Documented CI pipeline integration, network access, and current limitations; `examples/` directory with generated sample reports

[Unreleased]: https://github.com/manfred-kaiser/requirements-check/compare/0.1.0...main
[0.1.0]: https://github.com/manfred-kaiser/requirements-check/releases/tag/0.1.0
