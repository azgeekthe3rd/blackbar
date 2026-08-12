"""Financial identifiers: payment cards, bank accounts, crypto wallets."""

from __future__ import annotations

import re
from typing import ClassVar

from ..types import Entity
from ..validators import base58check_ok, card_brand, iban_checksum_ok, is_credit_card
from .base import RegexDetector, register


@register
class CreditCardDetector(RegexDetector):
    """Payment card numbers, gated on issuer prefix *and* the Luhn checksum.

    The regex alone matches roughly one in ten random 16-digit strings; adding
    Luhn drops that to about one in a hundred, and requiring a known issuer
    prefix removes most of what remains.
    """

    entity: ClassVar[Entity] = Entity.CREDIT_CARD
    priority: ClassVar[int] = 60
    pattern: ClassVar[re.Pattern[str]] = re.compile(r"(?<![\d.\-])\d(?:[ \-]?\d){12,18}(?![\d.\-])")

    def canonicalise(self, raw: str) -> str:
        return re.sub(r"[^\d]", "", raw)

    def validate(self, canonical: str, raw: str) -> bool:
        return is_credit_card(canonical)

    def annotate(self, canonical: str, raw: str) -> str | None:
        return card_brand(canonical)


@register
class IbanDetector(RegexDetector):
    entity: ClassVar[Entity] = Entity.IBAN
    priority: ClassVar[int] = 65
    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b"
    )

    def canonicalise(self, raw: str) -> str:
        return raw.replace(" ", "").upper()

    def validate(self, canonical: str, raw: str) -> bool:
        return iban_checksum_ok(canonical)

    def annotate(self, canonical: str, raw: str) -> str | None:
        return f"country={canonical[:2]}"


@register
class CryptoWalletDetector(RegexDetector):
    """Bitcoin and Ethereum addresses.

    Legacy Bitcoin addresses carry a Base58Check checksum, which we verify.
    Ethereum addresses have no mandatory checksum -- EIP-55 mixed-case encoding
    needs Keccak-256, which is not Python's ``hashlib.sha3_256`` -- so those are
    accepted on shape alone and marked accordingly.
    """

    entity: ClassVar[Entity] = Entity.CRYPTO_WALLET
    priority: ClassVar[int] = 55
    pattern: ClassVar[re.Pattern[str]] = re.compile(
        r"""
        (?<![\w])
        (?:
            [13][a-km-zA-HJ-NP-Z1-9]{25,34}      # BTC legacy P2PKH / P2SH
          | bc1[02-9ac-hj-np-z]{11,71}           # BTC bech32
          | 0x[a-fA-F0-9]{40}                    # ETH / EVM
        )
        (?![\w])
        """,
        re.VERBOSE,
    )

    def validate(self, canonical: str, raw: str) -> bool:
        if raw.startswith("0x") or raw.startswith("bc1"):
            return True
        return base58check_ok(raw)

    def annotate(self, canonical: str, raw: str) -> str | None:
        if raw.startswith("0x"):
            return "evm (unverified checksum)"
        return "bitcoin"
