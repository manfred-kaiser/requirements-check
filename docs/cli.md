# CLI Reference

```sh
requirements-check [FILE] [OPTIONS]
```

## Arguments

`FILE`
: Path to the `requirements.txt` file to check. Defaults to `requirements.txt` in the current directory.

## Options

`--json`
: Print a machine-readable JSON report instead of a table.

`--no-security`
: Skip the [OSV.dev](https://osv.dev) vulnerability check. Only the PyPI version comparison is performed.

`--fail-on-vulnerability`
: Exit with status code `1` if any known vulnerability was found. Intended for CI pipelines.

`--python-version VERSION`
: Target Python version (e.g. `3.11`) used to filter out suggested versions whose `requires-python` is incompatible. Defaults to the running interpreter's version.

`--proxy URL`
: HTTP(S) proxy to use for PyPI/OSV requests. Overrides the `HTTP_PROXY`/`HTTPS_PROXY` environment variables (which are otherwise used automatically).

`--ca-bundle PATH`
: Path to a custom CA bundle file for TLS verification. Needed in environments with a TLS-intercepting corporate proxy whose root CA isn't in the bundled `certifi` trust store — point this at the system trust store (e.g. `/etc/ssl/ca-bundle.pem`) or `SSL_CERT_FILE` in that case.

## Examples

```sh
# Table output for the requirements.txt in the current directory
requirements-check

# JSON output for a specific file
requirements-check requirements/prod.txt --json

# CI usage: fail the build on known vulnerabilities
requirements-check --fail-on-vulnerability

# Behind a corporate TLS-intercepting proxy
requirements-check --proxy http://proxy.example.com:3128 --ca-bundle /etc/ssl/ca-bundle.pem
```
