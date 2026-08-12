"""Government-issued identifiers."""

from __future__ import annotations

import re
from typing import ClassVar

from ..types import Entity
from ..validators import is_uk_nino, is_us_ssn
from .base import RegexDetector, register


@register
class UsSsnDetector(RegexDetector):
    """US Social Security numbers.

    Separators are required. An unpunctuated nine-digit run is indistinguishable
    from a zip+4, a product code or a timestamp fragment, and flagging those is
    how a scrubber earns a reputation for being unusable.
    """

    entity: ClassVar[Entity] = Entity.US_SSN
    priority: ClassVar[int] = 58
    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w\-])\d{3}[\- ]\d{2}[\- ]\d{4}(?![\w\-])"
    )

    def canonicalise(self, raw: str) -> str:
        return re.sub(r"\D", "", raw)

    def validate(self, canonical: str, raw: str) -> bool:
        return is_us_ssn(canonical)


@register
class UkNinoDetector(RegexDetector):
    entity: ClassVar[Entity] = Entity.UK_NINO
    priority: ClassVar[int] = 57
    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w])[A-Za-z]{2}[ \-]?\d{2}[ \-]?\d{2}[ \-]?\d{2}[ \-]?[A-Da-d](?![\w])"
    )

    def canonicalise(self, raw: str) -> str:
        return re.sub(r"[^A-Za-z0-9]", "", raw).upper()

    def validate(self, canonical: str, raw: str) -> bool:
        return is_uk_nino(canonical)
