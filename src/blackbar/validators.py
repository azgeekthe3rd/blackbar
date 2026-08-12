"""Structural and checksum validators.

These exist to answer the question a bare regex cannot: *is this actually a
credit card number, or is it a 16-digit order ID?* Every validator here is
pure, dependency-free and individually unit-tested.
"""

from __future__ import annotations

import ipaddress
import re
import string

# --------------------------------------------------------------------------- #
# Credit cards
# --------------------------------------------------------------------------- #

#: Issuer prefixes, longest-first so that more specific rules win.
_CARD_BRANDS: tuple[tuple[str, re.Pattern[str], frozenset[int]], ...] = (
    ("American Express", re.compile(r"^3[47]"), frozenset({15})),
    ("Diners Club", re.compile(r"^3(?:0[0-5]|[68])"), frozenset({14, 16, 19})),
    ("JCB", re.compile(r"^35(?:2[89]|[3-8][0-9])"), frozenset({16, 17, 18, 19})),
    ("Discover", re.compile(r"^(?:6011|65|64[4-9])"), frozenset({16, 19})),
    ("Mastercard", re.compile(r"^(?:5[1-5]|2(?:2[2-9]|[3-6][0-9]|7[01]|720))"), frozenset({16})),
    ("UnionPay", re.compile(r"^62"), frozenset({16, 17, 18, 19})),
    ("Visa", re.compile(r"^4"), frozenset({13, 16, 19})),
)


def luhn_checksum_ok(digits: str) -> bool:
    """Return ``True`` if ``digits`` satisfies the Luhn (mod-10) checksum.

    Doubling starts from the second digit counting from the right. Working
    left-to-right over a string of length ``n``, the digit at index ``i`` sits
    ``n - 1 - i`` places from the right, so it must be doubled whenever
    ``n - 1 - i`` is odd -- equivalently whenever ``i % 2 == n % 2``.
    """
    if not digits or not digits.isdigit():
        return False
    parity = len(digits) % 2
    total = 0
    for index, char in enumerate(digits):
        value = ord(char) - 48
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def card_brand(digits: str) -> str | None:
    """Return the issuing network for ``digits``, or ``None`` if unrecognised."""
    for name, prefix, lengths in _CARD_BRANDS:
        if prefix.match(digits) and len(digits) in lengths:
            return name
    return None


def is_credit_card(digits: str) -> bool:
    """A candidate is a card only if the length, issuer prefix *and* Luhn agree."""
    if not (13 <= len(digits) <= 19):
        return False
    if card_brand(digits) is None:
        return False
    return luhn_checksum_ok(digits)


# --------------------------------------------------------------------------- #
# IBAN
# --------------------------------------------------------------------------- #

#: ISO 13616 registry: country code -> total IBAN length.
IBAN_LENGTHS: dict[str, int] = {
    "AD": 24,
    "AE": 23,
    "AL": 28,
    "AT": 20,
    "AZ": 28,
    "BA": 20,
    "BE": 16,
    "BG": 22,
    "BH": 22,
    "BR": 29,
    "BY": 28,
    "CH": 21,
    "CR": 22,
    "CY": 28,
    "CZ": 24,
    "DE": 22,
    "DK": 18,
    "DO": 28,
    "EE": 20,
    "EG": 29,
    "ES": 24,
    "FI": 18,
    "FO": 18,
    "FR": 27,
    "GB": 22,
    "GE": 22,
    "GI": 23,
    "GL": 18,
    "GR": 27,
    "GT": 28,
    "HR": 21,
    "HU": 28,
    "IE": 22,
    "IL": 23,
    "IQ": 23,
    "IS": 26,
    "IT": 27,
    "JO": 30,
    "KW": 30,
    "KZ": 20,
    "LB": 28,
    "LC": 32,
    "LI": 21,
    "LT": 20,
    "LU": 20,
    "LV": 21,
    "LY": 25,
    "MC": 27,
    "MD": 24,
    "ME": 22,
    "MK": 19,
    "MR": 27,
    "MT": 31,
    "MU": 30,
    "NL": 18,
    "NO": 15,
    "PK": 24,
    "PL": 28,
    "PS": 29,
    "PT": 25,
    "QA": 29,
    "RO": 24,
    "RS": 22,
    "SA": 24,
    "SC": 31,
    "SE": 24,
    "SI": 19,
    "SK": 24,
    "SM": 27,
    "ST": 25,
    "SV": 28,
    "TL": 23,
    "TN": 24,
    "TR": 26,
    "UA": 29,
    "VA": 22,
    "VG": 24,
    "XK": 20,
}

_ALNUM = frozenset(string.ascii_uppercase + string.digits)


def iban_checksum_ok(candidate: str) -> bool:
    """Validate an IBAN with the ISO 7064 mod-97-10 check.

    Move the first four characters to the end, map each letter to a two-digit
    number (``A`` -> 10 ... ``Z`` -> 35), then require the resulting integer to
    be congruent to 1 modulo 97.
    """
    compact = candidate.replace(" ", "").replace("-", "").upper()
    if len(compact) < 5 or not set(compact) <= _ALNUM:
        return False
    country = compact[:2]
    expected = IBAN_LENGTHS.get(country)
    if expected is None or len(compact) != expected:
        return False
    if not compact[2:4].isdigit():
        return False

    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(ord(ch) - 55) if ch.isalpha() else ch for ch in rearranged)
    # Chunked reduction avoids building a several-hundred-digit integer.
    remainder = 0
    for chunk_start in range(0, len(numeric), 9):
        remainder = int(str(remainder) + numeric[chunk_start : chunk_start + 9]) % 97
    return remainder == 1


# --------------------------------------------------------------------------- #
# US Social Security Number
# --------------------------------------------------------------------------- #


def is_us_ssn(digits: str) -> bool:
    """Apply the SSA's structural rules for a never-issued SSN.

    Area ``000``, ``666`` and ``900``-``999`` are never allocated; the group and
    serial fields are never all zeros. This rejects placeholders such as
    ``000-00-0000`` and ``123-45-6789``-style test data that a bare
    ``\\d{3}-\\d{2}-\\d{4}`` pattern would happily flag.
    """
    if len(digits) != 9 or not digits.isdigit():
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area == "000" or area == "666" or area[0] == "9":
        return False
    if group == "00" or serial == "0000":
        return False
    # 078-05-1120 -- the Woolworth wallet card, the most reused fake in existence.
    return digits != "078051120"


# --------------------------------------------------------------------------- #
# UK National Insurance number
# --------------------------------------------------------------------------- #

_NINO_INVALID_PREFIXES = frozenset({"BG", "GB", "KN", "NK", "NT", "TN", "ZZ"})
_NINO_FIRST = frozenset("ABCEGHJKLMNOPRSTWXYZ")  # D, F, I, Q, U, V never used
_NINO_SECOND = frozenset("ABCEGHJKLMNPRSTWXYZ")  # additionally excludes O


def is_uk_nino(candidate: str) -> bool:
    """Validate a UK National Insurance number's prefix and suffix rules."""
    compact = candidate.replace(" ", "").replace("-", "").upper()
    if len(compact) != 9:
        return False
    if compact[0] not in _NINO_FIRST or compact[1] not in _NINO_SECOND:
        return False
    if compact[:2] in _NINO_INVALID_PREFIXES:
        return False
    if not compact[2:8].isdigit():
        return False
    return compact[8] in "ABCD"


# --------------------------------------------------------------------------- #
# Network addresses
# --------------------------------------------------------------------------- #


def parse_ip(candidate: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse ``candidate`` with the stdlib rather than trusting a regex."""
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def is_routable_ip(candidate: str) -> bool:
    """``True`` for globally routable addresses only.

    Loopback, link-local, private and reserved ranges are almost never PII and
    redacting them destroys the debuggability of a log file.
    """
    address = parse_ip(candidate)
    if address is None:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


# --------------------------------------------------------------------------- #
# Bitcoin addresses
# --------------------------------------------------------------------------- #

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {char: value for value, char in enumerate(_B58_ALPHABET)}


def base58check_ok(candidate: str) -> bool:
    """Validate a Base58Check payload (legacy P2PKH / P2SH Bitcoin addresses).

    The last four bytes are the first four bytes of ``sha256(sha256(payload))``.
    Leading ``1`` characters encode leading zero bytes and must be restored by
    hand, since Base58 has no way to represent them positionally.
    """
    import hashlib

    if not candidate or any(char not in _B58_INDEX for char in candidate):
        return False

    number = 0
    for char in candidate:
        number = number * 58 + _B58_INDEX[char]

    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    leading_zeros = len(candidate) - len(candidate.lstrip("1"))
    decoded = b"\x00" * leading_zeros + body

    if len(decoded) != 25:
        return False
    payload, checksum = decoded[:21], decoded[21:]
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    return digest[:4] == checksum
