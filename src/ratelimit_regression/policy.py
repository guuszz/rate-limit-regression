from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from threading import Lock
from time import monotonic


@dataclass(frozen=True)
class Decision:
    allowed: bool
    retry_after: int = 0
    remaining: int = 0


class SlidingWindowLimiter:
    """Small in-memory limiter intended only for the bundled local fixture."""

    def __init__(self, limit: int = 3, window_seconds: int = 5) -> None:
        if limit < 1 or window_seconds < 1:
            raise ValueError("limit and window_seconds must be positive")
        self.limit = limit
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = {}
        self._lock = Lock()

    def check(self, identity: str, now: float | None = None) -> Decision:
        """Record one attempt and return a deterministic allow/block decision."""
        instant = monotonic() if now is None else now
        with self._lock:
            events = self._events.setdefault(identity, deque())
            while events and instant - events[0] >= self.window_seconds:
                events.popleft()
            if len(events) >= self.limit:
                wait = max(1, int(self.window_seconds - (instant - events[0]) + 0.999))
                return Decision(False, retry_after=wait, remaining=0)
            events.append(instant)
            return Decision(True, remaining=self.limit - len(events))
