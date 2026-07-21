# Library Usage

`requirements-check` can be imported and used programmatically via the `Analyzer` class.

## Async

```python
import asyncio
from requirements_check import Analyzer

async def main():
    analyzer = Analyzer("./requirements.txt")
    result = await analyzer.analyze()
    for dep in result.dependencies:
        print(dep.name, dep.pinned_version, "->", dep.latest_version, dep.update_level)

asyncio.run(main())
```

## Sync

For callers that don't want to deal with `asyncio`, `analyze_sync()` wraps `analyze()` in `asyncio.run(...)`:

```python
from requirements_check import Analyzer

result = Analyzer("./requirements.txt").analyze_sync()
```

## Skipping the security check

```python
result = Analyzer("./requirements.txt", check_security=False).analyze_sync()
```

## Result shape

`analyze()` / `analyze_sync()` return an `AnalysisResult` with a `dependencies` list of `Dependency` objects (`name`, `pinned_version`, `latest_version`, `update_level`, `vulnerabilities`, `error`). Call `.to_dict()` on the result for the same structure used by `--json`.
