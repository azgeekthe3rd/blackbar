"""Resolving conflicts between detectors that claim the same span.

Detectors run independently, so they collide constantly: the digits inside an
IBAN look like a phone number, an email's domain looks like a hostname. Rather
than let ordering decide by accident, conflicts are resolved by an explicit,
testable rule.
"""

from __future__ import annotations

from collections.abc import Iterable

from .types import Match


def _rank(match: Match) -> tuple[int, int, int]:
    """Sort key for greedy selection -- higher is better.

    1. Detector priority. This is the explicit statement of which detector is
       more trustworthy about a span, so it leads. A ``user:pass@host`` URL
       credential outranks the email address the regex sees inside it, even
       though the email span is longer.
    2. Then length, which settles conflicts within a priority tier -- a full
       IBAN beats the phone-shaped fragment sitting inside it.
    3. Then earlier position, purely so the result is deterministic.
    """
    return (match.priority, len(match), -match.start)


def resolve(matches: Iterable[Match]) -> list[Match]:
    """Return a non-overlapping subset of ``matches``, sorted by position.

    Greedy by :func:`_rank`: repeatedly take the strongest remaining match and
    discard anything it overlaps.
    """
    ordered = sorted(matches, key=_rank, reverse=True)
    kept: list[Match] = []
    occupied: list[tuple[int, int]] = []

    for match in ordered:
        if any(match.start < end and start < match.end for start, end in occupied):
            continue
        kept.append(match)
        occupied.append((match.start, match.end))

    kept.sort(key=lambda m: (m.start, m.end))
    return kept
