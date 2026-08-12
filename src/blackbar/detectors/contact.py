"""Contact details: email addresses and telephone numbers."""

from __future__ import annotations

import re
from typing import ClassVar

from ..types import Entity
from .base import RegexDetector, register

# Reserved for documentation and testing (RFC 2606 / RFC 6761). Redacting these
# is noise, and it makes the tool unusable on its own README.
RESERVED_DOMAINS = frozenset(
    {
        "example.com",
        "example.org",
        "example.net",
        "example.edu",
        "test",
        "invalid",
        "localhost",
    }
)


@register
class EmailDetector(RegexDetector):
    entity: ClassVar[Entity] = Entity.EMAIL
    priority: ClassVar[int] = 70
    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"""
        (?<![A-Za-z0-9._%+\-/])          # not mid-token, and not a URL path
        [A-Za-z0-9._%+\-]+               # local part
        @
        (?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+  # labels
        [A-Za-z]{2,63}                   # TLD
        (?![A-Za-z0-9\-])
        """,
        re.VERBOSE,
    )

    def canonicalise(self, raw: str) -> str:
        return raw.lower()

    def validate(self, canonical: str, raw: str) -> bool:
        domain = canonical.rpartition("@")[2]
        if domain in RESERVED_DOMAINS:
            return False
        # Consecutive dots are illegal in both halves.
        return ".." not in canonical

    def annotate(self, canonical: str, raw: str) -> str | None:
        return canonical.rpartition("@")[2]


@register
class PhoneDetector(RegexDetector):
    """Telephone numbers.

    Deliberately conservative: a bare run of ten digits is far more likely to
    be an order number than a phone number, so we require a positive signal --
    an international ``+`` prefix, parentheses, or internal separators. Missing
    a few unformatted numbers is a better failure mode than shredding every
    identifier in a log file.
    """

    entity: ClassVar[Entity] = Entity.PHONE
    priority: ClassVar[int] = 30
    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"""
        (?<![\w.\-])
        (?:
            \+\d{1,3}[\s.\-]?\(?\d{1,4}\)?(?:[\s.\-]?\d{2,4}){1,4}   # E.164-ish
          | \(\d{2,4}\)[\s.\-]?\d{3,4}[\s.\-]?\d{3,4}                # (020) 7946 0958
          | \b0\d{2,4}[\s.\-]\d{3,4}[\s.\-]?\d{3,4}                  # 0161 496 0122
          | \b\d{3}[\s.\-]\d{3}[\s.\-]\d{4}                          # 555-0134 style
        )
        (?![\w\-])
        """,
        re.VERBOSE,
    )

    def canonicalise(self, raw: str) -> str:
        return re.sub(r"[^\d+]", "", raw)

    def validate(self, canonical: str, raw: str) -> bool:
        digits = canonical.lstrip("+")
        if not 7 <= len(digits) <= 15:  # ITU-T E.164 bounds
            return False
        # A single repeated digit is a placeholder, not a subscriber.
        return len(set(digits)) > 1
