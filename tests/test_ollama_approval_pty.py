"""Real pseudo-terminal (PTY) approval tests for the interactive operator decision loop.

Unlike the input-source doubles in test_ollama_approval_states.py, these spawn a child process
whose stdin/stdout are a real PTY and exercise the ACTUAL interactive approval path end to end:
redvector_ollama_agent._resolve_approval -> Wizard.ask (real stdin read) -> Terminal output, the
exact one-liner used by interactive(). They prove APPROVE/DENY (case-insensitive), that empty and
invalid input re-prompt rather than silently deny, invalid-then-valid retry, and that exhausted
invalid input cancels (never a silent deny). PTYs are Unix-only, so these are native-only."""
import os
import sys
import time
import unittest

try:
    import pty
    import select
    import subprocess
    _HAVE_PTY = True
except ImportError:
    _HAVE_PTY = False

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Child driver: the real interactive approval call. Color is disabled so assertions match plain
# text; the label mirrors interactive()'s APPROVE/DENY prompt.
_DRIVER = r"""
import os, sys
os.environ["NO_COLOR"] = "1"
from redvector_ollama_agent import _resolve_approval
from redvector_ollama_setup import Wizard, Terminal
term = Terminal(sys.stdout)
wizard = Wizard(read=input, terminal=term)
label = "Enter APPROVE to execute this operation, or DENY to cancel:"
result = _resolve_approval(lambda: wizard.ask(label), lambda m: term.message("warning", m))
term.write("DECISION=" + ("APPROVED" if result else "DENIED"))
sys.stdout.flush()
"""


def _drive(responses):
    master, slave = pty.openpty()
    env = dict(os.environ, NO_COLOR="1", PYTHONUNBUFFERED="1")
    proc = subprocess.Popen([sys.executable, "-c", _DRIVER], stdin=slave, stdout=slave, stderr=slave,
                            cwd=ROOT, env=env, close_fds=True)
    os.close(slave)
    os.write(master, ("\n".join(responses) + "\n").encode())
    chunks = []
    deadline = time.time() + 20
    while time.time() < deadline:
        ready, _, _ = select.select([master], [], [], 0.5)
        if ready:
            try:
                data = os.read(master, 4096)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
        elif proc.poll() is not None:
            break
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    os.close(master)
    return b"".join(chunks).decode("utf-8", "replace")


@unittest.skipUnless(_HAVE_PTY and sys.platform != "win32" and os.environ.get("REDVECTOR_RUN_SMOKE") == "1",
                     "Requires a Unix PTY and REDVECTOR_RUN_SMOKE=1")
class ApprovalPTY(unittest.TestCase):
    def test_explicit_approve_is_case_insensitive(self):
        for word in ("approve", "APPROVE", "Approve", "yes", "y"):
            out = _drive([word])
            self.assertIn("DECISION=APPROVED", out, (word, out))
            self.assertNotIn("RETRY", out)

    def test_explicit_deny(self):
        for word in ("deny", "DENY", "no", "cancel"):
            out = _drive([word])
            self.assertIn("DECISION=DENIED", out, (word, out))

    def test_empty_input_reprompts_then_approves_not_a_silent_deny(self):
        out = _drive(["", "approve"])
        self.assertIn("RETRY", out)                 # empty input re-prompted
        self.assertIn("DECISION=APPROVED", out)     # not treated as deny

    def test_invalid_then_valid_retries(self):
        out = _drive(["maybe", "yes"])
        self.assertIn("RETRY", out)
        self.assertIn("DECISION=APPROVED", out)

    def test_exhausted_invalid_cancels_not_silent_deny(self):
        out = _drive(["", "x", "?"])                # three non-decisions
        self.assertIn("CANCELLED BY OPERATOR", out)
        self.assertIn("DECISION=DENIED", out)


if __name__ == "__main__":
    unittest.main()
