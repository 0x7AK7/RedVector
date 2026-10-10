"""Bounded recovery for connections/processes RedVector controls directly.

Default schedule: attempt, then wait 1s, 2s, 4s between retries, then stop. Never
infinite, never a busy loop, never repeated paid-API calls beyond a minimal probe.
The sleeper is injectable so tests record waits without real delay.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, List


@dataclass
class RecoveryResult:
    ok: bool
    attempts: int
    waits: List[float] = field(default_factory=list)
    final_state: str = "FAILED"   # READY | CONNECTED | FAILED | DEGRADED

    def to_dict(self):
        return {"ok": self.ok, "attempts": self.attempts, "waits": self.waits,
                "final_state": self.final_state}


# Default backoff schedule (seconds to wait BEFORE retries 2..N).
DEFAULT_BACKOFF = (1.0, 2.0, 4.0)


def recover(probe: Callable[[], bool], backoff=DEFAULT_BACKOFF,
            sleeper: Callable[[float], None] = time.sleep,
            success_state: str = "READY", fail_state: str = "FAILED") -> RecoveryResult:
    """Call ``probe`` up to len(backoff)+1 times with bounded backoff between tries.

    The first attempt happens immediately; each subsequent attempt is preceded by
    the next backoff wait. Stops as soon as the probe returns truthy.
    """
    waits: List[float] = []
    attempts = 0
    total = len(backoff) + 1
    for i in range(total):
        if i > 0:
            w = float(backoff[i - 1])
            waits.append(w)
            sleeper(w)
        attempts += 1
        try:
            if probe():
                return RecoveryResult(True, attempts, waits, success_state)
        except Exception:
            pass
    return RecoveryResult(False, attempts, waits, fail_state)
