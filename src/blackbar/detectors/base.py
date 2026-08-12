"""Detector protocol, a regex-backed base implementation, and the registry.

A detector is anything that can turn text into :class:`Match` objects. Keeping
that surface tiny means a user can drop in their own -- a bloom filter over
known employee IDs, say -- without touching the engine.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import ClassVar, Protocol, runtime_checkable

from ..types import Entity, Match


@runtime_checkable
class Detector(Protocol):
    """Structural type every detector must satisfy."""

    entity: Entity
    priority: int

    @property
    def name(self) -> str: ...

    def find(self, text: str) -> Iterator[Match]: ...


class RegexDetector:
    """Base class: match a pattern, then subject each candidate to ``validate``.

    Subclasses set :attr:`pattern` and optionally override :meth:`validate` and
    :meth:`canonicalise`. The two-stage design is the whole point of this
    library -- the regex casts a wide net, the validator throws back the junk.
    """

    entity: ClassVar[Entity]
    pattern: ClassVar[re.Pattern[str]]
    priority: ClassVar[int] = 50
    #: Which capture group constitutes the redactable span (0 = whole match).
    group: ClassVar[int] = 0

    @property
    def name(self) -> str:
        return self.entity.value.lower()

    def canonicalise(self, raw: str) -> str:
        """Strip formatting before validation (spaces, dashes, and so on)."""
        return raw

    def validate(self, canonical: str, raw: str) -> bool:
        """Return ``True`` to keep the candidate. Default accepts everything."""
        return True

    def annotate(self, canonical: str, raw: str) -> str | None:
        """Optional human-readable note attached to the match."""
        return None

    def find(self, text: str) -> Iterator[Match]:
        for found in self.pattern.finditer(text):
            raw = found.group(self.group)
            if raw is None:
                continue
            canonical = self.canonicalise(raw)
            if not self.validate(canonical, raw):
                continue
            yield Match(
                entity=self.entity,
                start=found.start(self.group),
                end=found.end(self.group),
                text=raw,
                priority=self.priority,
                note=self.annotate(canonical, raw),
            )


_REGISTRY: dict[Entity, Detector] = {}


def register(cls: type) -> type:
    """Class decorator that instantiates a detector into the global registry."""
    instance = cls()
    if instance.entity in _REGISTRY:
        raise ValueError(f"duplicate detector registered for {instance.entity}")
    _REGISTRY[instance.entity] = instance
    return cls


def all_detectors() -> list[Detector]:
    """Every registered detector, ordered by descending priority."""
    return sorted(_REGISTRY.values(), key=lambda d: -d.priority)


def get_detector(entity: Entity) -> Detector:
    return _REGISTRY[entity]
