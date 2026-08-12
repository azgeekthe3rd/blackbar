"""Detector registry.

Importing this package is what populates the registry -- each module's
``@register`` decorators run on import.
"""

from __future__ import annotations

from .base import Detector, RegexDetector, all_detectors, get_detector, register

# Imported for their side effect of registering detectors.
from . import contact, credentials, financial, government, network  # noqa: F401  isort:skip

__all__ = [
    "Detector",
    "RegexDetector",
    "all_detectors",
    "get_detector",
    "register",
]
