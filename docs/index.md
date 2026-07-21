# requirements-check

```{toctree}
:hidden:
:maxdepth: 2

cli
library
changelog
```

**`requirements-check` scans a `requirements.txt` file for outdated dependencies and known security vulnerabilities.**

Unlike tools that rely on `pip index` or already-installed packages, it queries the [PyPI JSON API](https://warehouse.pypa.io/api-reference/json.html) directly and in parallel, and cross-checks every pinned dependency against the [OSV.dev](https://osv.dev) vulnerability database.

## Install

```sh
pip install requirements-check
```

## Usage

```sh
requirements-check
```

Scans `./requirements.txt` by default and prints a table with the pinned version, latest version, update level (patch/minor/major), and any known vulnerabilities.

```sh
requirements-check path/to/requirements.txt --json
requirements-check --no-security
requirements-check --fail-on-vulnerability
```

See [CLI Reference](cli.md) for all options and [Library Usage](library.md) for the Python API.
