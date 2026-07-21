<h1 align="center">requirements-check</h1>

<p align="center">
  <strong>Check requirements.txt for outdated dependencies and known vulnerabilities.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/requirements-check"><img src="https://img.shields.io/pypi/v/requirements-check" alt="PyPI"></a>
  <a href="https://pypi.org/project/requirements-check"><img src="https://img.shields.io/pypi/pyversions/requirements-check" alt="Python versions"></a>
  <a href="https://github.com/manfred-kaiser/requirements-check/blob/main/LICENSE"><img src="https://img.shields.io/github/license/manfred-kaiser/requirements-check" alt="License"></a>
</p>

---

`requirements-check` scans a `requirements.txt` file (or a [`pyproject.toml`](#pyprojecttoml)) and reports, per dependency, the best available patch, minor, and major update, and whether the pinned version has known vulnerabilities — directly from the [PyPI JSON API](https://warehouse.pypa.io/api-reference/json.html) and [OSV.dev](https://osv.dev), in parallel via `httpx`/`asyncio`, with nothing installed.

Most tools cover only one half of this. `pip-check`-style tools show outdated versions but nothing about vulnerabilities, and need the packages installed. `pip-audit`/Safety show vulnerabilities but not update size. Dependabot does both, but only as a GitHub platform service (PRs), not a CLI you can run anywhere. `requirements-check` combines both **and** goes one step further: for every known vulnerability, it tells you whether a low-risk **patch** already fixes it or whether you're forced into a **minor**/**major** bump — from one command, against a plain `requirements.txt`. It also exports the same data as a [CycloneDX SBOM](#sbom-software-bill-of-materials) or [self-contained HTML report](#html-report), and is built to run unattended in [CI pipelines](#ci-integration).

## Quick Start

```sh
pip install requirements-check
```

```sh
requirements-check
```

Scans `./requirements.txt` by default and prints a table with the pinned version, the latest available patch/minor/major update, notes for exceptional cases, and known vulnerabilities (including whether a patch already fixes them, or a bigger bump is required):

```
                               requirements-check
┏━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Package     ┃ Pinned  ┃ Patch   ┃ Minor  ┃ Major  ┃ Note ┃ Vulnerabiliti… ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━┩
│ aiohttp     │ 3.11.11 │ 3.11.18 │ 3.14.2 │ 3.14.2 │ -    │ 30 known       │
│             │         │         │        │        │      │ (minor needed) │
├─────────────┼─────────┼─────────┼────────┼────────┼──────┼────────────────┤
│ cryptograp… │ 44.0.0  │ 44.0.3  │ 44.0.3 │ 49.0.0 │ -    │ 7 known (major │
│             │         │         │        │        │      │ needed)        │
├─────────────┼─────────┼─────────┼────────┼────────┼──────┼────────────────┤
│ Jinja2      │ 3.1.5   │ 3.1.6   │ 3.1.6  │ 3.1.6  │ -    │ 2 known (patch │
│             │         │         │        │        │      │ fixes)         │
├─────────────┼─────────┼─────────┼────────┼────────┼──────┼────────────────┤
│ alembic     │ 1.18.4  │ 1.18.5  │ 1.18.5 │ 1.18.5 │ -    │ -              │
└─────────────┴─────────┴─────────┴────────┴────────┴──────┴────────────────┘
```

The `Note` column only shows exceptional cases (`unpinned`, `unsupported`, `not found`, or a constraint capping an update — see [How it works](#how-it-works)) — for normal dependencies the Patch/Minor/Major columns already say everything there is to say about available updates, so it stays empty.

Add `--list-vulnerabilities` to see each vulnerability individually (ID, severity, which update level fixes it, summary, CVE/PYSEC aliases) instead of just a count:

```sh
requirements-check --list-vulnerabilities
```

## CLI

```sh
requirements-check [FILE] [OPTIONS]
```

`FILE` — path to the `requirements.txt` file to check (default: `requirements.txt` in the current directory). A [CycloneDX SBOM](#sbom-software-bill-of-materials) or a [`pyproject.toml`](#pyprojecttoml) is also accepted here and auto-detected.

| Option                      | Description                                                                          |
| ---------------------------- | ------------------------------------------------------------------------------------- |
| `--json`                     | Machine-readable JSON output instead of a table                                       |
| `--sbom`                     | CycloneDX 1.6 JSON SBOM instead of a table                                            |
| `--html`                     | Self-contained HTML report instead of a table                                         |
| `--sarif`                     | SARIF 2.1.0 log of known vulnerabilities, for GitHub/Azure code scanning              |
| `--list-vulnerabilities`     | List each known vulnerability individually instead of just a count                    |
| `--no-security`               | Skip the OSV.dev vulnerability check                                                  |
| `--no-transitive-check`        | Skip warning about dependencies declared by your pinned packages that aren't listed in this file |
| `--constraints PATH`          | Loose, unresolved requirements source (a pip-compile `.in` file, or a `pyproject.toml`) to cross-check suggestions against; auto-detected as `FILE` with a `.in` extension, or as `FILE` itself when `FILE` is a `pyproject.toml`, if not given |
| `--extra NAME`                | Also check a `[project.optional-dependencies]` extra from a `pyproject.toml` `FILE` (repeatable) |
| `--fail-on-vulnerability`     | Exit with status 1 if a known vulnerability is found (for CI)                         |
| `--python-version VERSION`    | Target Python version (e.g. `3.11`) for `requires-python` compatibility filtering; defaults to the running interpreter |
| `--proxy URL`                 | HTTP(S) proxy for PyPI/OSV requests (overrides `HTTP_PROXY`/`HTTPS_PROXY` env vars)   |
| `--ca-bundle PATH`            | Custom CA bundle file, e.g. for corporate TLS-intercepting proxies                    |
| `--no-color`                  | Disable colored/styled table output (also honors the `NO_COLOR` env var)              |
| `--output PATH`, `-o PATH`    | Write the report to this file instead of stdout (works with every format) |

`--json`, `--sbom`, `--html`, and `--sarif` are mutually exclusive — pick one output format.

Exit codes: `0` success, `1` vulnerabilities found (only with `--fail-on-vulnerability`), `2` usage error (e.g. file not found).

```sh
# JSON output for a specific file
requirements-check requirements/prod.txt --json

# CycloneDX SBOM
requirements-check --sbom --output sbom.json

# Self-contained HTML report
requirements-check --html --output report.html

# SARIF for GitHub code scanning
requirements-check --sarif --output results.sarif

# Re-check an existing CycloneDX SBOM instead of a requirements.txt (auto-detected)
requirements-check sbom.json --json

# CI usage: fail the build on known vulnerabilities
requirements-check --fail-on-vulnerability

# Behind a corporate TLS-intercepting proxy
requirements-check --proxy http://proxy.example.com:3128 --ca-bundle /etc/ssl/ca-bundle.pem

# Cross-check against an explicit pip-compile source (auto-detected if named requirements.in)
requirements-check requirements.txt --constraints requirements.in

# Check a pyproject.toml directly, or cross-check a lock file against it
requirements-check pyproject.toml
requirements-check requirements.txt --constraints pyproject.toml

# Also check optional-dependencies extras (repeatable)
requirements-check pyproject.toml --extra docs --extra test
```

## SBOM (Software Bill of Materials)

```sh
requirements-check --sbom --output sbom.json
```

Produces a [CycloneDX](https://cyclonedx.org) 1.6 JSON SBOM (validated against the official schema), built entirely from data `requirements-check` already collects — no extra network calls:

- **Components**: one per pinned dependency, with a [PURL](https://github.com/package-url/purl-spec) (`pkg:pypi/name@version`) and, when available, a license
- **Vulnerabilities**: every known vulnerability, with `affects` pointing at the exact component, plus its CVE/PYSEC aliases and OSV severity/fixed-version as CycloneDX `properties`

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:pypi/jinja2@3.1.5",
      "purl": "pkg:pypi/jinja2@3.1.5",
      "name": "Jinja2",
      "version": "3.1.5",
      "licenses": [{ "license": { "name": "BSD-3-Clause" } }]
    }
  ],
  "vulnerabilities": [
    {
      "id": "GHSA-cpwx-vrp4-4pq7",
      "source": { "name": "OSV", "url": "https://osv.dev/vulnerability/GHSA-cpwx-vrp4-4pq7" },
      "description": "Jinja2 vulnerable to sandbox breakout through attr filter selecting format method",
      "affects": [{ "ref": "pkg:pypi/jinja2@3.1.5" }],
      "references": [{ "id": "CVE-2025-27516", "source": { "name": "OSV" } }],
      "properties": [
        { "name": "requirements-check:osv_severity", "value": "CVSS:4.0/AV:N/AC:L/..." },
        { "name": "requirements-check:fixed_version", "value": "3.1.6" }
      ]
    }
  ]
}
```

Only dependencies with a pinned version become components — an SBOM describes a concrete build, so unpinned or unresolvable entries are excluded. As with the update/vulnerability checks, coverage depends on `requirements.txt` being fully resolved (see [How it works](#how-it-works)).

An SBOM is typically most useful uploaded to a tracking system like [OWASP Dependency-Track](https://dependencytrack.org/), which continuously re-scans stored SBOMs against new vulnerability feeds — so you find out about a newly disclosed CVE in a dependency you shipped months ago, without re-running a build. Only CycloneDX JSON is supported (not SPDX or XML) — see [CI Integration](#ci-integration) below for an upload example.

Full example: [`examples/sample-sbom.json`](examples/sample-sbom.json), generated from [`examples/requirements.txt`](examples/requirements.txt) (see [How it works](#how-it-works) for how that file was produced).

**SBOM as input.** `requirements-check` also reads a CycloneDX SBOM back in as `FILE`, auto-detected by content (`"bomFormat": "CycloneDX"`), no flag needed:

```sh
requirements-check sbom.json --json
```

Every `pkg:pypi/...` component becomes a pinned dependency (other ecosystems in the same SBOM are skipped); everything else — update checks, vulnerabilities, `--sbom`/`--html`/`--sarif` output — works exactly the same as with a `requirements.txt`. This is useful for re-validating an SBOM you didn't generate yourself (e.g. from a vendor, or from `syft`/`docker sbom` against a running container) against current data, and it sidesteps the whole "is this file fully resolved" question from [How it works](#how-it-works) — an SBOM already reflects what's actually installed. The `.in`-constraints cross-check doesn't apply to SBOM input (there's no associated loose source file).

## pyproject.toml

```sh
requirements-check pyproject.toml
```

`requirements-check` reads a [PEP 621](https://peps.python.org/pep-0621/) `pyproject.toml`'s `[project.dependencies]` directly — the standard, backend-agnostic way of declaring direct dependencies, so this works the same for hatch, setuptools, PDM, or Poetry ≥2.0 projects. By default only the core direct dependencies are read; tool-specific tables (e.g. `[tool.hatch.envs.*]`) aren't included, and extras need `--extra` (below).

Unlike a `requirements.txt`, `[project.dependencies]` entries are usually abstract ranges (`httpx>=0.25`), not exact pins — there's nothing for OSV to check a range against, so vulnerability checking only applies to the rare entry that *is* pinned (`==`). Update checking still works for every entry: it's reported the same way an unpinned line in a `requirements.txt` is (see [Update levels](#update-levels)). The transitive-completeness warning is skipped automatically for this input, since `[project.dependencies]` is intentionally not an exhaustive, fully-resolved list.

**As a constraints source.** This is usually the more useful mode: cross-check a real, pinned lock file against the ranges your project actually declares, with full vulnerability checking on the pins that are actually installed:

```sh
requirements-check requirements.txt --constraints pyproject.toml
```

This is auto-detected too — a `pyproject.toml` sitting next to `requirements.txt` is picked up automatically, no `--constraints` needed, the same way a sibling `.in` file already is (`.in` wins if both are present). When `pyproject.toml` is given directly as `FILE` instead, it's automatically used as its own constraints source — so a bounded range like `flask<3.0` still shows a `capped by constraint` note if PyPI's true latest exceeds it.

**Dynamic dependencies.** Some projects compute `dependencies` via a build-backend hook instead of listing them statically (`dynamic = ["dependencies"]`) — commonly via the [`hatch-requirements-txt`](https://github.com/repo-helper/hatch-requirements-txt) plugin, which points at an external requirements file via `[tool.hatch.metadata.hooks.requirements_txt]`. `requirements-check` recognizes that specific, well-documented convention and reads the referenced file(s) instead — without running hatch or any build hooks. Any other dynamic-dependency mechanism (a custom hook, `setuptools`' own dynamic tables, etc.) can't be resolved statically and produces a clear error instead of silently reporting zero dependencies.

**Extras.** Add `--extra NAME` (repeatable) to also check a `[project.optional-dependencies]` extra alongside the core dependencies — dynamic extras declared via the same `hatch-requirements-txt` hook's `optional-dependencies` sub-table are resolved the same way as the main dependencies:

```sh
requirements-check pyproject.toml --extra docs --extra test
```

A package required by more than one group (core and/or several extras) is merged into a single row rather than listed twice. A `Source` column (shown only once any `--extra` is used) lists which groups required it — one per line — with that group's own range in parens whenever it adds real information beyond the Pinned column:

```
Source
• dependencies (>=4.0,<6.0)
• production
```

Here `paramiko` is pinned to an exact version via a `production` extra (e.g. one pointing at a fully resolved `requirements.txt`), while the core `dependencies` group only constrains it to a range — both are shown, since the range is genuinely more permissive than the pin. A group that contributes nothing beyond the resolved pin (e.g. `production` above, which is exactly the pinned version) is listed without a range, to avoid repeating the Pinned column.

If the combined requirements can't actually be satisfied by any available release — say core wants `httpx>=0.25` but an extra pins `httpx==0.10.0` — that's reported as an error on the row rather than silently picking one side.

## HTML Report

```sh
requirements-check --html --output report.html
```

Renders the same table(s) as the terminal output (plus the vulnerability details table with `--list-vulnerabilities`) as a single self-contained HTML file — inline CSS, no external assets, safe to email or drop on a file share for people who don't use a terminal.

<p align="center">
  <img src="examples/sample-report-screenshot.png" alt="requirements-check HTML report showing a package table with patch/minor/major columns and a vulnerability details table below it" width="700">
</p>

Full example: [`examples/sample-report.html`](examples/sample-report.html) — download it (or clone the repo) and open it locally; GitHub's file viewer shows HTML as source rather than rendering it. It was generated from [`examples/requirements.txt`](examples/requirements.txt) via:

```sh
requirements-check examples/requirements.txt --html --output examples/sample-report.html --list-vulnerabilities
```

A plain, non-HTML JSON equivalent is at [`examples/sample-report.json`](examples/sample-report.json) for comparison.

## SARIF

```sh
requirements-check --sarif --output results.sarif
```

[SARIF](https://sarifweb.azurewebsites.net/) (Static Analysis Results Interchange Format) is the standard result format for GitHub/Azure DevOps **code scanning**. Uploading it via `github/codeql-action/upload-sarif` makes every known vulnerability show up in the repo's **Security → Code scanning** tab — with an inline annotation on the exact line in `requirements.txt` where the affected package is pinned, and persistent tracking across commits (open/fixed state), instead of only being visible in a workflow log or artifact download.

Only vulnerabilities are represented (one SARIF `result` per CVE/GHSA/PYSEC finding) — SARIF is for actionable findings, not a full inventory; use `--json` or `--sbom` for that. Severity mapping: `note` if a patch already fixes it, `warning` if minor/major is needed, `error` if no fix is known yet.

Full example: [`examples/sample-report.sarif`](examples/sample-report.sarif) (validated against the official SARIF 2.1.0 schema), generated the same way as the other example reports. See [CI Integration](#ci-integration) below for the upload step.

## CI Integration

`requirements-check` is designed to run unattended: no prompts, stable exit codes, `--no-color` to keep log output free of ANSI codes, and `--output` to write a report straight to a file (no shell redirection required).

### GitHub Action

The simplest way to wire this into GitHub: this repo is itself a [composite action](action.yml).

```yaml
# .github/workflows/requirements-check.yml
name: requirements-check

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * 1"  # weekly

permissions:
  contents: read
  security-events: write   # required to upload SARIF to the Security tab

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: manfred-kaiser/requirements-check@v1
        with:
          file: requirements.txt
          format: sarif                 # table, json, sbom, html, or sarif
          fail-on-vulnerability: true
```

Findings show up directly in **Security → Code scanning alerts**, with inline annotations on the affected `requirements.txt` line — see [SARIF](#sarif) above. `fail-on-vulnerability` still fails the job, but only *after* the SARIF upload, so findings are never hidden by a red job. See [`action.yml`](action.yml) for all inputs (`no-security`, `constraints`, `proxy`, `ca-bundle`, `requirements-check-version`, etc.) and outputs (`report-path`, `exit-code`).

### Without the action

Equivalent manual steps, useful if you want more control or aren't on GitHub:

```yaml
# .github/workflows/requirements-check.yml
name: requirements-check

on:
  pull_request:
  schedule:
    - cron: "0 6 * * 1"  # weekly

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: pip install requirements-check

      # Human-readable summary in the log
      - run: requirements-check --no-color

      # Machine-readable report as a workflow artifact
      - run: requirements-check --json --output requirements-check.json
      - uses: actions/upload-artifact@v4
        with:
          name: requirements-check-report
          path: requirements-check.json

      # SBOM as a workflow artifact (and optionally push to Dependency-Track)
      - run: requirements-check --sbom --output sbom.json
      - uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json
      # - run: |
      #     curl -X POST "$DTRACK_URL/api/v1/bom" \
      #       -H "X-Api-Key: $DTRACK_API_KEY" \
      #       -F "project=$DTRACK_PROJECT_UUID" \
      #       -F "bom=@sbom.json"

      # Fail the build on known vulnerabilities
      - run: requirements-check --fail-on-vulnerability
```

For scripts, agents, or any other automated caller: use `--json` rather than parsing the table — the table's formatting isn't a stable interface, the JSON schema is. Each dependency has `name`, `pinned_version`, `latest_patch`/`latest_minor`/`latest_major`, `update_level`, `vulnerabilities` (with `id`, `summary`, `severity`, `aliases`, `fixed_version`, `fix_level`), `minimum_safe_version`, `vulnerability_fix_level`, and `error`.

## How it works

### Update levels

For each pinned dependency, `requirements-check` fetches all non-yanked, non-prerelease versions from PyPI, filters out versions whose `requires-python` doesn't match the target Python version, and then reports the best version available at each level:

- **Patch**: highest version within the same major.minor as the pinned version
- **Minor**: highest version within the same major as the pinned version
- **Major**: highest version overall

The `update_level` field (not shown as its own table column — it's already implied by which of Patch/Minor/Major differs from Pinned) reflects the size of the jump to the highest available version; it's used for `--json` output and for `Note` in the table when no ordinary patch/minor/major applies (`unpinned`/`unsupported`/`not_found`).

Version parsing and comparison uses [`packaging.version.Version`](https://packaging.pypa.io/en/stable/version.html) — the same reference [PEP 440](https://peps.python.org/pep-0440/) implementation pip itself uses — so it's not limited to plain `major.minor.patch`:

- **Any number of release segments**: CalVer-style versions like `2024.11.06` or short ones like `23.1` work the same way; missing segments are treated as `0`
- **Epochs** (`1!2.0`) are compared and displayed correctly
- **Post-releases** (`1.0.0.post1`) count as an available patch, same as a normal patch bump
- **Pre-releases and dev-releases** (alpha/beta/rc/dev) are never suggested — only stable releases are considered

### Vulnerabilities

Every dependency with a pinned version is queried against [OSV.dev](https://osv.dev) in a single batched request (`POST /v1/querybatch`), matching the exact pinned version — not the latest one. Matching vulnerability IDs are then resolved to their summary and severity via `GET /v1/vulns/{id}`, run in parallel. OSV.dev aggregates GitHub Security Advisories, the PyPA Advisory DB, and other sources; no API key required.

For each vulnerability, the OSV record's affected-version range is used to find the lowest version that actually resolves it (`fixed_version`), which is then classified the same way as updates: does a **patch** already fix it, or is a **minor**/**major** bump required? If OSV lists no fix yet, it's flagged `no_fix`. A dependency's `vulnerability_fix_level` is the worst of all its vulnerabilities' fix levels — e.g. if one CVE is patch-fixable but another needs a major bump, the dependency shows `major`, since that's what's needed to be fully clean. This lets you tell at a glance whether you can resolve a CVE with a low-risk patch bump or are forced into a bigger jump.

An unpinned dependency (an abstract `pyproject.toml` range, or a bare `requirements.txt` line without `==`) can't be checked at all — OSV needs an exact version, and there isn't one to query. The table says so explicitly (`not checked (no pinned version)`) rather than showing the same blank `-` a genuinely clean, checked dependency gets — an empty result and an unchecked one are different things, and conflating them would make the tool's "no known vulnerabilities" signal untrustworthy.

### Sibling-locked dependencies

A newer version existing on PyPI doesn't always mean it's actually reachable. Some packages are released in lockstep with another one they hard-pin via `requires_dist` — most commonly a pure-Python wrapper around a compiled extension, e.g. `pydantic` pinning an exact `pydantic-core` version. If `pydantic-core` has a newer release on PyPI but the `pydantic` version you have pinned still requires the older one, upgrading `pydantic-core` alone isn't possible — you'd need a newer `pydantic` release first, and one might not exist yet.

`requirements-check` cross-references every checked dependency's declared requirements against every *other* checked, pinned dependency (no extra network calls — this reuses metadata already fetched for the transitive-dependency check) and flags it when this happens:

```
Note: locked to 2.46.4 by pydantic==2.13.4
```

The Patch/Minor/Major columns still show the true PyPI-wide latest, same as with a [version constraint](#direct-transitive-and-constrained-dependencies) — this is a note, not a change to what's reported as available. It only fires when the lock actually hides something (i.e. a newer version is being suggested that the lock rules out); if you're already at the locked version, there's nothing to flag.

### Direct, transitive, and constrained dependencies

`requirements-check` only looks at what's actually written in the given file — it does not resolve dependencies itself.

**Coverage.** If your `requirements.txt` lists only direct dependencies, only those get checked; anything they pull in transitively stays invisible to it. For full coverage, use a fully resolved file — e.g. generated with [pip-compile](https://pip-tools.readthedocs.io/) (from [pip-tools](https://github.com/jazzband/pip-tools)) or `uv pip compile`, which pin every direct *and* transitive dependency with exact versions. Point `requirements-check` at that file (not your loose `requirements.in`/`pyproject.toml`) and every installed package gets checked and included in the SBOM.

To help catch it when you forget: `requirements-check` fetches each pinned package's own declared dependencies (`requires_dist` from PyPI) and warns if any aren't listed in your file at all — a strong signal it isn't fully resolved:

```
⚠ 3 dependencies declared by your pinned packages aren't listed in this file: certifi, idna, urllib3
  This requirements.txt may not be fully resolved — consider generating it with pip-compile or a similar tool.
```

Disable with `--no-transitive-check`. This is a heuristic based on declared metadata, not a real resolver — it can miss or over-flag edge cases (optional/platform-specific dependencies in particular).

**Constraints.** If you *do* use pip-compile, its `.in` source has your actual version ceilings (e.g. `flask<2.0`), while the compiled `requirements.txt` only has the single resolved pin. `requirements-check` cross-checks against that `.in` file (or a [`pyproject.toml`](#pyprojecttoml)) when present — auto-detected next to your requirements file (same name with a `.in` extension, or a sibling `pyproject.toml`), or given explicitly via `--constraints PATH`. If the true latest release on PyPI is blocked by your own constraint, the `Note` column says so instead of just suggesting an update `pip-compile --upgrade` can't actually deliver until you edit `requirements.in` yourself:

```
Note: capped by constraint <2.0 (max: 1.1.4)
```

All example files in this repo follow that pattern: [`examples/requirements.in`](examples/requirements.in) has 3 range-constrained direct dependencies (`flask<2.0`, `requests<2.26`, `aiohttp<3.10`), and [`examples/requirements.txt`](examples/requirements.txt) is its `pip-compile` output — 18 packages, direct and transitive. The constraints deliberately cap old, vulnerable versions so the example actually has outdated packages, known vulnerabilities, and constraint-capped updates to show off — they're not a recommendation to use these versions or ranges.

## Network access

`requirements-check` only talks to two hosts, both read-only (`GET`/`POST`, no credentials sent):

| Host                | Endpoint(s)                                                              | Purpose                                                   |
| -------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `pypi.org`            | `GET /pypi/{package}/json`                                                 | Version list per dependency                                |
| `pypi.org`            | `GET /pypi/{package}/{pinned_version}/json`                                | License and declared dependencies for the *pinned* version (only when a version is pinned — see below) |
| `api.osv.dev`         | `POST /v1/querybatch`, `GET /v1/vulns/{id}`                                 | Vulnerability lookup and details                            |

Two GET requests per pinned dependency to `pypi.org` (not one): PyPI's unversioned endpoint always reflects the *latest* release, so a second, version-specific request is needed to get accurate license and dependency metadata for what's actually pinned — otherwise an old pin could be reported against its latest release's metadata. Both the `license` field and the transitive-dependency check are read from that same second request, so `--no-transitive-check` skips the *comparison*, not the request itself. All requests run concurrently and are batched where the API allows it (OSV.dev). Use `--no-security` to skip `api.osv.dev` entirely. Use `--proxy`/`--ca-bundle` (or the standard `HTTP_PROXY`/`HTTPS_PROXY`/`SSL_CERT_FILE` env vars) to route all of this through a corporate proxy.

## Limitations

- Supported input formats: `requirements.txt` (pip's plain `name==version` / PEP 508 format), a [PEP 621 `pyproject.toml`](#pyprojecttoml)'s direct dependencies, and CycloneDX SBOMs — not `Pipfile`/`Pipfile.lock`, `poetry.lock`, or `uv.lock` directly. Export or compile those to a `requirements.txt` first (e.g. `poetry export`, `uv export --format requirements-txt`).
- A `pyproject.toml` with `dynamic = ["dependencies"]` can only be read statically when it uses the [`hatch-requirements-txt`](https://github.com/repo-helper/hatch-requirements-txt) plugin's convention (see [pyproject.toml](#pyprojecttoml)) — any other dynamic-metadata hook (a custom one, `setuptools`' own dynamic tables, etc.) isn't resolved and produces an error rather than a silent empty result.
- Sibling-lock detection (see [How it works](#how-it-works)) only catches locks where the locking package is *also* in the file being checked — a lock coming from a deeper transitive dependency that isn't listed stays invisible, same limitation as the transitive-coverage check.
- `--extra` conflict detection checks whether *some* available PyPI release satisfies the combined requirements across groups — it isn't a full dependency resolver, so it won't catch conflicts that only emerge from *other* transitive constraints.
- VCS and direct URL requirements (`git+https://...`, `name @ https://...`) can't be version-checked and are reported as `unsupported`.
- The transitive-dependency warning and constraint cross-check are heuristics based on declared PyPI metadata, not a real dependency resolver — they can miss or over-flag edge cases (see [How it works](#how-it-works)).
- SBOM export is CycloneDX JSON only — no SPDX, no XML (see [SBOM](#sbom-software-bill-of-materials)).
- The PyPI host is hardcoded to `pypi.org` — there's currently no way to point it at an internal mirror (Artifactory, Nexus, devpi). Whether that would even work depends on the mirror: most only implement the [Simple Repository API](https://peps.python.org/pep-0503/) (`/simple/{name}/`, enough for `pip install`), not the richer PyPI JSON API (`/pypi/{name}/json`) this tool relies on for `requires_dist`, license, and per-release `requires_python` — even a mirror that proxies the full upstream may or may not pass that through, depending on its configuration.
- There's no offline mode for the OSV.dev vulnerability check — it requires live internet access to `api.osv.dev`. In fully air-gapped environments, `--no-security` is the only current option (skips vulnerability checking entirely). OSV.dev does publish downloadable per-ecosystem data dumps (e.g. `https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`) that could support a future offline mode, but that isn't implemented yet.

## License

[MIT](LICENSE)
