#!/usr/bin/env python3
"""R5 — cancellation-safety regression tests for ``EnhancedCommandExecutor``.

These confirm that when a command TIMES OUT:
  * its direct child process is terminated and reaped (no leftover, no zombie),
    on both Windows and POSIX; and
  * on POSIX, helper processes the child spawned (its process group) are also
    reaped, so nothing is orphaned — while an UNRELATED process is left running.

Isolation / safety
  * Workloads are **harmless synthetic sleepers** (`python -c "... time.sleep ..."`
    and, as a grandchild, `sleep`) — no network, no security tool, no RedVector
    backend. Every process started here is tracked and force-cleaned in a
    ``finally`` so the test never leaks a process even on failure.
  * Imports ``redvector_server`` only (no MCP SDK needed), so these run on the
    Windows dev box and on Kali.

Run with pytest:   pytest tests/test_cancellation_safety.py
Standalone:        python tests/test_cancellation_safety.py
"""
import os
import pathlib
import sys
import time

import psutil

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

# redvector_server resolves its auth configuration ONCE, at import, from
# REDVECTOR_API_TOKEN. Because pytest imports every test module during
# collection, whichever module imports the server first fixes that token for the
# whole session. Set the SAME strong throwaway token that
# test_security_remediation.py uses, so this file's (alphabetically earlier)
# import leaves auth correctly configured and does not disturb that suite,
# regardless of collection order. This value must match that file's TEST_TOKEN.
os.environ["REDVECTOR_API_TOKEN"] = "unit-test-strong-token-0123456789abcdef"

import redvector_server as rv  # noqa: E402

try:
    import pytest
except Exception:  # pragma: no cover
    pytest = None


def _pid_dead(pid, timeout=10.0):
    """True once ``pid`` no longer refers to a live process (gone, or a
    reaped/zombie/dead remnant). Polls up to ``timeout`` seconds."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            p = psutil.Process(pid)
            if p.status() in (psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD):
                return True
        except psutil.NoSuchProcess:
            return True
        except Exception:
            return True
        time.sleep(0.2)
    return False


def test_timeout_terminates_and_reaps_direct_child():
    """A timed-out command's direct child is terminated and reaped on any OS."""
    cmd = [sys.executable, "-c", "import time; time.sleep(300)"]
    ex = rv.EnhancedCommandExecutor(cmd, timeout=2)
    result = ex.execute()
    child_pid = ex.process.pid

    assert result["timed_out"] is True, result
    assert result["success"] is False, result
    assert _pid_dead(child_pid), f"direct child {child_pid} survived the timeout"


@pytest.mark.skipif(os.name == "nt", reason="process-group reaping is POSIX-only")
def test_timeout_reaps_child_group_and_spares_unrelated_posix():
    """On POSIX, a timed-out child's whole process group is reaped (its spawned
    grandchild dies — no orphan), while an UNRELATED process keeps running."""
    import subprocess

    # Unrelated control process in the test's OWN group — must survive.
    control = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        # Synthetic parent that spawns a grandchild `sleep`, prints its PID, then
        # blocks. With start_new_session (added by the executor on POSIX), parent
        # and grandchild share a new group that the timeout path signals.
        parent_cmd = [
            sys.executable, "-c",
            "import subprocess,time;"
            "p=subprocess.Popen(['sleep','300']);"
            "print('CHILD:%d' % p.pid, flush=True);"
            "time.sleep(300)",
        ]
        ex = rv.EnhancedCommandExecutor(parent_cmd, timeout=3)
        result = ex.execute()

        assert result["timed_out"] is True, result
        out = result.get("stdout", "")
        assert "CHILD:" in out, f"did not capture grandchild pid; stdout={out!r}"
        grandchild_pid = int(out.split("CHILD:", 1)[1].split()[0])

        # Orphan prevention: the grandchild must be gone.
        assert _pid_dead(grandchild_pid), f"grandchild {grandchild_pid} was orphaned"
        # The direct child (parent python) is also reaped.
        assert _pid_dead(ex.process.pid), "parent child survived the timeout"
        # Unrelated process is untouched.
        assert control.poll() is None, "an UNRELATED process was affected by cleanup"
    finally:
        try:
            control.terminate()
            control.wait(timeout=5)
        except Exception:
            try:
                control.kill()
            except Exception:
                pass


def _main():
    import types

    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and isinstance(v, types.FunctionType)]
    failed = 0
    for t in tests:
        if os.name == "nt" and t.__name__.endswith("_posix"):
            print(f"SKIP  {t.__name__} (POSIX-only)")
            continue
        try:
            t()
            print(f"PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {t.__name__}: {e!r}")
    print(f"\n{len(tests) - failed} ok")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_main())
