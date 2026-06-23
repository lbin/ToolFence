from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from toolfence.runtime.models import RuntimeDecision
from toolfence.runtime.sanitizer import Sanitizer
from toolfence.utils import now_iso


class AuditLogger:
    def __init__(self, path: Path, sanitizer: Sanitizer | None = None):
        self.path = path.expanduser()
        self.sanitizer = sanitizer or Sanitizer()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: dict[str, Any], decision: RuntimeDecision) -> None:
        record = {
            "timestamp": now_iso(),
            "event": self.sanitizer.sanitize_value(event),
            "decision": decision.to_dict(),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

