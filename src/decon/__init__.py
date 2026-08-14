"""DECON — sanitize operational data without destroying its analytical value."""

from decon.api import ask_safely, build_engine, desanitize, sanitize
from decon.ask import AskError
from decon.engine import RedactionEngine

__version__ = "0.9.2"

__all__ = [
    "AskError",
    "RedactionEngine",
    "ask_safely",
    "build_engine",
    "desanitize",
    "sanitize",
    "__version__",
]
