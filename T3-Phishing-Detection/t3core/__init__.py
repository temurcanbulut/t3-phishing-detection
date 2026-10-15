"""Evidence collection for domain/URL investigations; no safety verdicts."""

from .inspector import inspect_url
from .target import InvalidTarget, parse_target

__all__ = ["InvalidTarget", "inspect_url", "parse_target"]
