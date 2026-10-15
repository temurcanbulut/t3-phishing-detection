"""Synchronous adapter for the local Flask UI and compatibility imports."""

import asyncio

from t3core import InvalidTarget, inspect_url, parse_target

__all__ = ["InvalidTarget", "analyze_url", "parse_target"]


def analyze_url(value, api_key="", *, active=False, threat_lookup=False):
    return asyncio.run(
        inspect_url(value, active=active, threat_lookup=threat_lookup, api_key=api_key)
    )
