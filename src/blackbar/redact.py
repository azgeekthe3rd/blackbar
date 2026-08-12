"""Redaction strategies -- what actually replaces a detected span."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from typing import ClassVar, Protocol, runtime_checkable

from .types import Entity, Match


@runtime_checkable
class Strategy(Protocol):
    name: str

    def apply(self, match: Match) -> str: ...


class LabelStrategy:
    """Replace with the entity name: ``[EMAIL]``. The safe default."""

    name = "label"

    def __init__(self, template: str = "[{entity}]") -> None:
        self.template = template

    def apply(self, match: Match) -> str:
        return self.template.format(entity=match.entity.value)


class HashStrategy:
    """Replace with a deterministic pseudonym: ``[EMAIL:3f9a1c4e]``.

    The same input maps to the same token everywhere, so a scrubbed corpus
    remains *joinable* -- you can still count distinct users, follow one session
    across services, or group errors by customer -- without exposing anyone.

    Determinism is the whole feature and also the whole risk: a plain digest of
    a low-entropy value is trivially reversed by brute force (there are only so
    many phone numbers). The keyed HMAC is what stops that, so the key must be
    secret and stable. Without one, a random per-run key is generated: tokens
    stay consistent within a run and are unlinkable between runs.
    """

    name = "hash"

    def __init__(self, key: bytes | str | None = None, length: int = 8) -> None:
        if key is None:
            key = secrets.token_bytes(32)
            self.ephemeral = True
        else:
            self.ephemeral = False
        self.key = key.encode("utf-8") if isinstance(key, str) else key
        self.length = length

    def token(self, value: str) -> str:
        digest = hmac.new(self.key, value.encode("utf-8"), hashlib.sha256)
        return digest.hexdigest()[: self.length]

    def apply(self, match: Match) -> str:
        # Normalise so that formatting variants collapse to one pseudonym.
        value = match.text.strip().lower()
        if match.entity in {Entity.CREDIT_CARD, Entity.PHONE, Entity.US_SSN, Entity.IBAN}:
            value = re.sub(r"[\s\-()]", "", value)
        return f"[{match.entity.value}:{self.token(value)}]"


class MaskStrategy:
    """Replace with a shape-preserving mask, keeping a documented tail.

    Retaining the last four digits of a card is standard practice for receipts
    and support workflows. It is *not* anonymisation -- the tail plus a
    timestamp is often enough to re-identify -- so this is opt-in.
    """

    name = "mask"

    #: Per-entity number of trailing characters to preserve.
    KEEP: ClassVar[dict[Entity, int]] = {
        Entity.CREDIT_CARD: 4,
        Entity.PHONE: 3,
        Entity.IBAN: 4,
        Entity.US_SSN: 0,
        Entity.API_KEY: 0,
    }

    def __init__(self, char: str = "*", keep: int | None = None) -> None:
        self.char = char
        self.keep_override = keep

    def apply(self, match: Match) -> str:
        raw = match.text
        keep = self.keep_override
        if keep is None:
            keep = self.KEEP.get(match.entity, 0)

        if match.entity is Entity.EMAIL:
            local, _, domain = raw.partition("@")
            first = local[0] if local else ""
            return f"{first}{self.char * max(len(local) - 1, 1)}@{domain}"

        if keep <= 0:
            return "".join(self.char if ch.isalnum() else ch for ch in raw)

        # Preserve separators; mask every alphanumeric except the final `keep`.
        alnum_total = sum(1 for ch in raw if ch.isalnum())
        seen = 0
        out: list[str] = []
        for ch in raw:
            if not ch.isalnum():
                out.append(ch)
                continue
            seen += 1
            out.append(ch if seen > alnum_total - keep else self.char)
        return "".join(out)


class RemoveStrategy:
    """Delete the span entirely."""

    name = "remove"

    def apply(self, match: Match) -> str:
        return ""


def build_strategy(name: str, *, key: str | None = None, keep: int | None = None) -> Strategy:
    """Factory used by the CLI."""
    match name:
        case "label":
            return LabelStrategy()
        case "hash":
            return HashStrategy(key=key)
        case "mask":
            return MaskStrategy(keep=keep)
        case "remove":
            return RemoveStrategy()
        case _:
            raise ValueError(f"unknown strategy: {name!r}")


STRATEGY_NAMES = ("label", "hash", "mask", "remove")
