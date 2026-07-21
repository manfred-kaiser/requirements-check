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

`requirements-check` scans a `requirements.txt` file and reports, per dependency, the best available patch, minor, and major update, and whether the pinned version has known vulnerabilities.

It queries the [PyPI JSON API](https://warehouse.pypa.io/api-reference/json.html) directly and in parallel via `httpx`/`asyncio` — no `pip index` call, and the dependencies don't need to be installed — and cross-checks every pinned version against the [OSV.dev](https://osv.dev) vulnerability database.

## Quick Start

```sh
pip install requirements-check
```

```sh
requirements-check
```

Scans `./requirements.txt` by default and prints a table with the pinned version, the latest available patch/minor/major update, the overall status, and known vulnerabilities.

```
                               requirements-check
┏━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ Package     ┃ Pinned  ┃ Patch   ┃ Minor  ┃ Major  ┃ Status     ┃ Vulnerabil… ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ aiohttp     │ 3.11.11 │ 3.11.18 │ 3.14.2 │ 3.14.2 │ minor      │ 60 known    │
│             │         │         │        │        │ update     │             │
│ alembic     │ 1.18.4  │ 1.18.5  │ 1.18.5 │ 1.18.5 │ patch      │ -           │
│             │         │         │        │        │ update     │             │
└─────────────┴─────────┴─────────┴────────┴────────┴────────────┴─────────────┘
```

## CLI

```sh
requirements-check [FILE] [OPTIONS]
```

`FILE` — path to the `requirements.txt` file to check (default: `requirements.txt` in the current directory).

| Option                     | Description                                                                          |
| --------------------------- | ------------------------------------------------------------------------------------- |
| `--json`                    | Machine-readable JSON output instead of a table                                       |
| `--no-security`              | Skip the OSV.dev vulnerability check                                                  |
| `--fail-on-vulnerability`    | Exit with status 1 if a known vulnerability is found (for CI)                         |
| `--python-version VERSION`   | Target Python version (e.g. `3.11`) for `requires-python` compatibility filtering; defaults to the running interpreter |
| `--proxy URL`                | HTTP(S) proxy for PyPI/OSV requests (overrides `HTTP_PROXY`/`HTTPS_PROXY` env vars)   |
| `--ca-bundle PATH`           | Custom CA bundle file, e.g. for corporate TLS-intercepting proxies                    |

```sh
# JSON output for a specific file
requirements-check requirements/prod.txt --json

# CI usage: fail the build on known vulnerabilities
requirements-check --fail-on-vulnerability

# Behind a corporate TLS-intercepting proxy
requirements-check --proxy http://proxy.example.com:3128 --ca-bundle /etc/ssl/ca-bundle.pem
```

## Library

```python
from requirements_check import Analyzer

result = Analyzer("./requirements.txt").analyze_sync()
for dep in result.dependencies:
    print(dep.name, dep.pinned_version, "->", dep.latest_major, dep.update_level)
```

`Analyzer` accepts the same knobs as the CLI: `check_security=False`, `python_version="3.11"`, `proxy="http://..."`, `ca_bundle="/path/to/bundle.pem"`.

For callers already running an event loop, use the async method directly instead of `analyze_sync()`:

```python
import asyncio
from requirements_check import Analyzer

async def main():
    result = await Analyzer("./requirements.txt").analyze()
    print(result.to_dict())  # same structure as `--json`

asyncio.run(main())
```

Each `Dependency` has: `name`, `pinned_version`, `latest_patch`, `latest_minor`, `latest_major`, `update_level` (`none`/`patch`/`minor`/`major`/`unpinned`/`unsupported`/`not_found`), `vulnerabilities` (list of `Vulnerability` with `id`, `summary`, `severity`, `aliases`), and `error`.

## How update levels are determined

For each pinned dependency, `requirements-check` fetches all non-yanked, non-prerelease versions from PyPI, filters out versions whose `requires-python` doesn't match the target Python version, and then reports the best version available at each level:

- **Patch**: highest version within the same major.minor as the pinned version
- **Minor**: highest version within the same major as the pinned version
- **Major**: highest version overall

The overall `Status` column reflects the size of the jump to the highest available version.

## How vulnerabilities are determined

Every dependency with a pinned version is queried against [OSV.dev](https://osv.dev) in a single batched request (`POST /v1/querybatch`), matching the exact pinned version — not the latest one. Matching vulnerability IDs are then resolved to their summary and severity via `GET /v1/vulns/{id}`, run in parallel. OSV.dev aggregates GitHub Security Advisories, the PyPA Advisory DB, and other sources; no API key required.

## License

[MIT](LICENSE)
