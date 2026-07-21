"""requirements-check module.

Checks a `requirements.txt` file for outdated dependencies (via the PyPI JSON API)
and known vulnerabilities (via the OSV.dev API), usable as CLI or as a library.
"""

from .analyzer import Analyzer
from .models import AnalysisResult, Dependency, UpdateLevel, Vulnerability

__version__ = "0.1.0"

__all__ = [
    "Analyzer",
    "AnalysisResult",
    "Dependency",
    "UpdateLevel",
    "Vulnerability",
]
