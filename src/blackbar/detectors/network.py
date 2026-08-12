"""Network identifiers: IP and MAC addresses."""

from __future__ import annotations

import re
from typing import ClassVar

from ..types import Entity
from ..validators import is_routable_ip, parse_ip
from .base import RegexDetector, register


@register
class Ipv4Detector(RegexDetector):
    """IPv4 addresses, parsed by :mod:`ipaddress` rather than trusted to regex.

    Only globally routable addresses are redacted. ``127.0.0.1``, ``10.x`` and
    friends are not PII, and stripping them from a log destroys the very thing
    an engineer opened the log to see.
    """

    entity: ClassVar[Entity] = Entity.IPV4
    priority: ClassVar[int] = 40
    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w.\-])\d{1,3}(?:\.\d{1,3}){3}(?![\w.\-])"
    )

    def validate(self, canonical: str, raw: str) -> bool:
        return is_routable_ip(raw)


@register
class Ipv6Detector(RegexDetector):
    entity: ClassVar[Entity] = Entity.IPV6
    priority: ClassVar[int] = 45
    # Writing a correct IPv6 regex -- with `::` compression, embedded IPv4 and
    # zone identifiers -- is a famous way to waste an afternoon. Cast a loose
    # net over "hex digits and colons" and let `ipaddress` be the arbiter.
    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w:.])[A-Fa-f0-9]{0,4}(?::[A-Fa-f0-9]{0,4}){2,7}(?![\w:.])"
    )

    def validate(self, canonical: str, raw: str) -> bool:
        address = parse_ip(raw)
        if address is None or address.version != 6:
            return False
        return is_routable_ip(raw)


@register
class MacDetector(RegexDetector):
    entity: ClassVar[Entity] = Entity.MAC
    priority: ClassVar[int] = 50
    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<![\w:.\-])(?:[A-Fa-f0-9]{2}[:\-]){5}[A-Fa-f0-9]{2}(?![\w:.\-])"
    )

    def canonicalise(self, raw: str) -> str:
        return re.sub(r"[^A-Fa-f0-9]", "", raw).lower()

    def validate(self, canonical: str, raw: str) -> bool:
        # All-zero and broadcast addresses identify nobody.
        return canonical not in {"000000000000", "ffffffffffff"}
