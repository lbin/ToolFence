from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from toolfence.utils import now_iso


@dataclass(slots=True)
class PanicRecord:
    state: str
    reason: str
    actor: str
    timestamp: str = field(default_factory=now_iso)
    resolved_at: str | None = None
    resolved_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PanicManager:
    def __init__(self):
        self.current: PanicRecord | None = None
        self.history: list[PanicRecord] = []

    @property
    def is_panicking(self) -> bool:
        return self.current is not None

    def panic(self, reason: str, actor: str = "system") -> PanicRecord:
        if self.current is not None:
            return self.current
        self.current = PanicRecord(state="panic", reason=reason, actor=actor)
        self.history.append(self.current)
        return self.current

    def resume(self, actor: str = "system") -> PanicRecord | None:
        if self.current is None:
            return None
        self.current.resolved_at = now_iso()
        self.current.resolved_by = actor
        record = self.current
        self.current = None
        return record

