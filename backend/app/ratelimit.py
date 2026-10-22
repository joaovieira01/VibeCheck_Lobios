"""Limitador de taxa em memória (janela deslizante).

Vale por processo: com vários workers/instâncias cada um conta separado. Para
produção em escala use um limitador compartilhado (Redis) ou o do proxy reverso.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable

_MAX_KEYS = 10_000


class RateLimiter:
    def __init__(
        self,
        max_events: int,
        window_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max = max_events
        self._window = window_seconds
        self._clock = clock
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> bool:
        """Registra um evento. Retorna False se o limite da janela foi excedido."""
        now = self._clock()
        cutoff = now - self._window
        with self._lock:
            if len(self._events) > _MAX_KEYS:
                self._purge(cutoff)
            events = self._events.setdefault(key, deque())
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= self._max:
                return False
            events.append(now)
            return True

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)

    def _purge(self, cutoff: float) -> None:
        for key in [k for k, v in self._events.items() if not v or v[-1] <= cutoff]:
            del self._events[key]
