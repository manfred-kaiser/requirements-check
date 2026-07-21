# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

## [0.1.0] - 2026-07-21

### Added

- Initial release
- `requirements-check` CLI: scans a `requirements.txt` file and reports outdated dependencies (major/minor/patch) by querying the PyPI JSON API directly
- Vulnerability check against the [OSV.dev](https://osv.dev) database, shown per dependency
- `--json` flag for machine-readable output
- `--no-security` flag to skip the OSV.dev check
- `--fail-on-vulnerability` flag for CI usage (non-zero exit code when vulnerabilities are found)
- Usable as a library via `requirements_check.Analyzer` (async `analyze()` and sync `analyze_sync()`)
- Reports patch, minor, and major upgrade suggestions per dependency, not just the single latest version
- `requires-python` compatibility filtering: suggested versions are checked against the target Python version (`--python-version`), defaulting to the running interpreter
- `--proxy` and `--ca-bundle` flags for corporate proxy / TLS-intercepting environments

[Unreleased]: https://github.com/manfred-kaiser/requirements-check/compare/0.1.0...main
[0.1.0]: https://github.com/manfred-kaiser/requirements-check/releases/tag/0.1.0
