"""DECON — sanitize operational data without destroying its analytical value."""

from decon.api import build_engine, desanitize, query_cloud_safe, sanitize
from decon.ask import AskError
from decon.engine import RedactionEngine

__version__ = "0.4.0"

__all__ = [
    "AskError",
    "RedactionEngine",
    "build_engine",
    "desanitize",
    "query_cloud_safe",
    "sanitize",
    "__version__",
]
