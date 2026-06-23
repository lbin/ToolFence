from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class ApprovalRequest:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    created_at: float = field(default_factory=time.time)
    approval_type: str = ""
    operation: str = ""
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    resolved_at: float | None = None
    resolved_by: str | None = None
    resolution_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ApprovalQueue:
    def __init__(self, max_queue_size: int = 100):
        self.max_queue_size = max_queue_size
        self.pending: dict[str, ApprovalRequest] = {}
        self.history: list[ApprovalRequest] = []

    def add(self, approval_type: str, operation: str, reason: str, details: dict[str, Any] | None = None) -> ApprovalRequest:
        if len(self.pending) >= self.max_queue_size:
            oldest = next(iter(self.pending))
            self.deny(oldest, "system", "approval queue overflow")
        request = ApprovalRequest(
            approval_type=approval_type,
            operation=operation,
            reason=reason,
            details=details or {},
        )
        self.pending[request.id] = request
        return request

    def approve(self, request_id: str, resolved_by: str = "system", reason: str = "") -> ApprovalRequest | None:
        return self._resolve(request_id, "approved", resolved_by, reason)

    def deny(self, request_id: str, resolved_by: str = "system", reason: str = "") -> ApprovalRequest | None:
        return self._resolve(request_id, "denied", resolved_by, reason)

    def _resolve(self, request_id: str, status: str, resolved_by: str, reason: str) -> ApprovalRequest | None:
        request = self.pending.pop(request_id, None)
        if request is None:
            return None
        request.status = status
        request.resolved_at = time.time()
        request.resolved_by = resolved_by
        request.resolution_reason = reason
        self.history.append(request)
        return request

