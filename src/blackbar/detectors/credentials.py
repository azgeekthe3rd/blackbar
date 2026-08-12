"""Machine credentials: API keys, tokens, and private key material.

Not strictly *personal* data, but a scrubber that cleans a log of emails and
leaves an AWS key in place has solved the wrong half of the problem.
"""

from __future__ import annotations

import re
from typing import ClassVar

from ..types import Entity
from .base import RegexDetector, register

#: ``(label, pattern)`` pairs for vendor-specific key formats. Ordered by
#: specificity; the first match supplies the annotation.
KEY_FORMATS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key", re.compile(r"^(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}$")),
    ("GitHub token", re.compile(r"^gh[pousr]_[A-Za-z0-9]{36,}$")),
    ("Slack token", re.compile(r"^xox[baprs]-[A-Za-z0-9\-]{10,}$")),
    ("Anthropic key", re.compile(r"^sk-ant-[A-Za-z0-9\-_]{20,}$")),
    ("OpenAI key", re.compile(r"^sk-(?:proj-)?[A-Za-z0-9\-_]{20,}$")),
    ("Stripe key", re.compile(r"^(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}$")),
    ("Google API key", re.compile(r"^AIza[A-Za-z0-9\-_]{35}$")),
    ("SendGrid key", re.compile(r"^SG\.[A-Za-z0-9\-_]{16,}\.[A-Za-z0-9\-_]{16,}$")),
)


@register
class ApiKeyDetector(RegexDetector):
    entity: ClassVar[Entity] = Entity.API_KEY
    priority: ClassVar[int] = 85
    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"""
        (?<![\w\-])
        (?:
            (?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}
          | gh[pousr]_[A-Za-z0-9]{36,}
          | xox[baprs]-[A-Za-z0-9\-]{10,}
          | sk-ant-[A-Za-z0-9\-_]{20,}
          | sk-(?:proj-)?[A-Za-z0-9\-_]{20,}
          | (?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}
          | AIza[A-Za-z0-9\-_]{35}
          | SG\.[A-Za-z0-9\-_]{16,}\.[A-Za-z0-9\-_]{16,}
        )
        (?![\w\-])
        """,
        re.VERBOSE,
    )

    def annotate(self, canonical: str, raw: str) -> str | None:
        for label, matcher in KEY_FORMATS:
            if matcher.match(raw):
                return label
        return None


@register
class JwtDetector(RegexDetector):
    """JSON Web Tokens. The ``eyJ`` prefix is base64url for ``{"``."""

    entity: ClassVar[Entity] = Entity.JWT
    priority: ClassVar[int] = 90
    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w\-.])eyJ[A-Za-z0-9\-_]{8,}\.eyJ[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}(?![\w\-.])"
    )


@register
class PrivateKeyDetector(RegexDetector):
    """PEM-armoured private keys, matched across their whole multi-line block."""

    entity: ClassVar[Entity] = Entity.PRIVATE_KEY
    priority: ClassVar[int] = 100
    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"
        r".*?"
        r"-----END (?:[A-Z ]+ )?PRIVATE KEY-----",
        re.DOTALL,
    )


@register
class UrlCredentialsDetector(RegexDetector):
    """The ``user:password@`` portion of a URL.

    Only the credential span is captured, so ``postgres://app:hunter2@db:5432``
    redacts to ``postgres://[URL_CREDENTIALS]@db:5432`` and stays diagnosable.
    """

    entity: ClassVar[Entity] = Entity.URL_CREDENTIALS
    priority: ClassVar[int] = 80
    group: ClassVar[int] = 1
    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"[a-zA-Z][a-zA-Z0-9+.\-]*://([^/\s:@]+:[^/\s:@]+)@"
    )
