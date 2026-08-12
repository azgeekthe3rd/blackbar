"""blackbar -- a dependency-free PII scrubber that checks its work.

    >>> from blackbar import scrub
    >>> scrub("card 4111 1111 1111 1111, ref 4111 1111 1111 1112")
    'card [CREDIT_CARD], ref 4111 1111 1111 1112'

The second number differs by one digit and fails the Luhn checksum, so it is
left alone. That distinction is the entire point of the library.
"""

from __future__ import annotations

from .core import Scrubber, ScrubResult, scan, scrub
from .detectors import Detector, RegexDetector, all_detectors, register
from .redact import (
    HashStrategy,
    LabelStrategy,
    MaskStrategy,
    RemoveStrategy,
    Strategy,
    build_strategy,
)
from .types import Entity, Match

__version__ = "0.1.0"

__all__ = [
    "Detector",
    "Entity",
    "HashStrategy",
    "LabelStrategy",
    "MaskStrategy",
    "Match",
    "RegexDetector",
    "RemoveStrategy",
    "ScrubResult",
    "Scrubber",
    "Strategy",
    "__version__",
    "all_detectors",
    "build_strategy",
    "register",
    "scan",
    "scrub",
]
