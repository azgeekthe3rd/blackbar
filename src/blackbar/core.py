"""The scrubbing engine: run detectors, resolve conflicts, rewrite the text."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .detectors import Detector, all_detectors
from .overlap import resolve
from .redact import LabelStrategy, Strategy
from .types import Entity, Match


@dataclass(frozen=True, slots=True)
class ScrubResult:
    """The outcome of a scrub: the cleaned text plus what was found and where."""

    text: str
    matches: tuple[Match, ...] = field(default=())

    @property
    def counts(self) -> dict[str, int]:
        tally = Counter(match.entity.value for match in self.matches)
        return dict(sorted(tally.items()))

    @property
    def found_anything(self) -> bool:
        return bool(self.matches)

    def report(self, *, include_text: bool = False) -> dict[str, object]:
        """A JSON-serialisable summary.

        ``include_text`` is off by default: a report that quotes the secrets it
        found is itself a leak, and these reports get pasted into tickets.
        """
        return {
            "total": len(self.matches),
            "counts": self.counts,
            "matches": [
                {
                    "entity": m.entity.value,
                    "start": m.start,
                    "end": m.end,
                    "length": len(m),
                    "note": m.note,
                    **({"text": m.text} if include_text else {}),
                }
                for m in self.matches
            ],
        }


class Scrubber:
    """Configurable PII scrubber.

    >>> Scrubber().scrub("ping ops@acme.io").text
    'ping [EMAIL]'
    """

    def __init__(
        self,
        *,
        strategy: Strategy | None = None,
        only: Iterable[Entity] | None = None,
        exclude: Iterable[Entity] | None = None,
        detectors: Sequence[Detector] | None = None,
        allowlist: Iterable[str] | None = None,
    ) -> None:
        self.strategy: Strategy = strategy or LabelStrategy()

        chosen = list(detectors) if detectors is not None else all_detectors()
        if only is not None:
            wanted = set(only)
            chosen = [d for d in chosen if d.entity in wanted]
        if exclude is not None:
            unwanted = set(exclude)
            chosen = [d for d in chosen if d.entity not in unwanted]
        self.detectors: tuple[Detector, ...] = tuple(chosen)

        patterns = [re.escape(item) for item in (allowlist or ())]
        self._allowlist: re.Pattern[str] | None = (
            re.compile("|".join(patterns), re.IGNORECASE) if patterns else None
        )

    def _allowed(self, match: Match) -> bool:
        return self._allowlist is not None and bool(self._allowlist.fullmatch(match.text))

    def scan(self, text: str) -> list[Match]:
        """Find every non-overlapping match without modifying ``text``."""
        found: list[Match] = []
        for detector in self.detectors:
            found.extend(detector.find(text))
        return [m for m in resolve(found) if not self._allowed(m)]

    def scrub(self, text: str) -> ScrubResult:
        """Return ``text`` with every match replaced by the active strategy."""
        matches = self.scan(text)
        if not matches:
            return ScrubResult(text=text, matches=())

        # Rebuild in one pass; offsets stay valid because matches are sorted
        # and non-overlapping, and we never look back at rewritten output.
        pieces: list[str] = []
        cursor = 0
        for match in matches:
            pieces.append(text[cursor : match.start])
            pieces.append(self.strategy.apply(match))
            cursor = match.end
        pieces.append(text[cursor:])

        return ScrubResult(text="".join(pieces), matches=tuple(matches))


def scrub(text: str, **kwargs: object) -> str:
    """One-liner convenience wrapper returning just the cleaned string."""
    return Scrubber(**kwargs).scrub(text).text  # type: ignore[arg-type]


def scan(text: str, **kwargs: object) -> list[Match]:
    """One-liner convenience wrapper returning just the matches."""
    return Scrubber(**kwargs).scan(text)  # type: ignore[arg-type]
