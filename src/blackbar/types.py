"""Core value types shared across detectors, policies and redaction strategies."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Entity(str, Enum):
    """A category of personally identifying or otherwise sensitive data."""

    EMAIL = "EMAIL"
    PHONE = "PHONE"
    CREDIT_CARD = "CREDIT_CARD"
    IBAN = "IBAN"
    US_SSN = "US_SSN"
    UK_NINO = "UK_NINO"
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    MAC = "MAC"
    URL_CREDENTIALS = "URL_CREDENTIALS"
    API_KEY = "API_KEY"
    JWT = "JWT"
    PRIVATE_KEY = "PRIVATE_KEY"
    CRYPTO_WALLET = "CRYPTO_WALLET"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass(frozen=True, slots=True, order=False)
class Match:
    """A single detected span of sensitive text.

    ``start`` and ``end`` are byte-agnostic string offsets into the *original*
    input, so a caller can always recover the source text with
    ``text[match.start:match.end]``.
    """

    entity: Entity
    start: int
    end: int
    text: str
    priority: int = 50
    note: str | None = None

    def __post_init__(self) -> None:
        if self.start < 0:
            raise ValueError(f"start must be non-negative, got {self.start}")
        if self.end <= self.start:
            raise ValueError(f"end ({self.end}) must be greater than start ({self.start})")

    @property
    def span(self) -> tuple[int, int]:
        return (self.start, self.end)

    def __len__(self) -> int:
        return self.end - self.start

    def overlaps(self, other: Match) -> bool:
        return self.start < other.end and other.start < self.end
