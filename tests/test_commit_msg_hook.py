"""Tests for the commit-msg hook that blocks AI co-author trailers."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / 'hooks' / 'commit-msg'
BASH = shutil.which('bash') if os.name != 'nt' else r'C:\Program Files\Git\bin\bash.exe'


def _run_hook(message: str) -> subprocess.CompletedProcess:
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
        f.write(message)
        f.flush()
        msg_file = f.name
    try:
        return subprocess.run(
            [BASH, str(HOOK), msg_file],
            capture_output=True, text=True, encoding='utf-8', timeout=10,
        )
    finally:
        os.unlink(msg_file)


@unittest.skipUnless(BASH and Path(BASH).exists(), 'Bash is unavailable')
class CommitMsgHookTests(unittest.TestCase):
    """Verify the commit-msg hook blocks AI trailers and allows legitimate ones."""

    # --- SHOULD BLOCK ---

    def test_blocks_claude_co_author(self):
        r = _run_hook('Fix bug\n\nCo-authored-by: Claude <noreply@anthropic.com>')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('Unwanted AI co-author', r.stdout)

    def test_blocks_claude_case_insensitive(self):
        r = _run_hook('Fix\n\nCO-AUTHORED-BY: CLAUDE <noreply@anthropic.com>')
        self.assertNotEqual(r.returncode, 0)

    def test_blocks_claude_code(self):
        r = _run_hook('Fix\n\nCo-authored-by: Claude Code <noreply@anthropic.com>')
        self.assertNotEqual(r.returncode, 0)

    def test_blocks_claude_opus(self):
        r = _run_hook('Fix\n\nCo-authored-by: Claude Opus 4.6 <noreply@anthropic.com>')
        self.assertNotEqual(r.returncode, 0)

    def test_blocks_anthropic_email(self):
        r = _run_hook('Fix\n\nCo-authored-by: SomeBot <noreply@anthropic.com>')
        self.assertNotEqual(r.returncode, 0)

    def test_blocks_codex(self):
        r = _run_hook('Fix\n\nCo-authored-by: Codex <noreply@openai.com>')
        self.assertNotEqual(r.returncode, 0)

    def test_blocks_github_copilot(self):
        r = _run_hook('Fix\n\nCo-authored-by: GitHub Copilot <copilot@github.com>')
        self.assertNotEqual(r.returncode, 0)

    def test_blocks_copilot_standalone(self):
        r = _run_hook('Fix\n\nCo-authored-by: Copilot <noreply@github.com>')
        self.assertNotEqual(r.returncode, 0)

    def test_blocks_openai(self):
        r = _run_hook('Fix\n\nCo-authored-by: OpenAI <noreply@openai.com>')
        self.assertNotEqual(r.returncode, 0)

    def test_blocks_cursor(self):
        r = _run_hook('Fix\n\nCo-authored-by: Cursor <noreply@cursor.com>')
        self.assertNotEqual(r.returncode, 0)

    def test_blocks_codeium(self):
        r = _run_hook('Fix\n\nCo-authored-by: Codeium <noreply@codeium.com>')
        self.assertNotEqual(r.returncode, 0)

    def test_blocks_amazon_q(self):
        r = _run_hook('Fix\n\nCo-authored-by: Amazon Q <noreply@amazon.com>')
        self.assertNotEqual(r.returncode, 0)

    def test_blocks_windsurf(self):
        r = _run_hook('Fix\n\nCo-authored-by: Windsurf <noreply@windsurf.com>')
        self.assertNotEqual(r.returncode, 0)

    def test_blocks_multiple_trailers(self):
        msg = ('Fix\n\n'
               'Co-authored-by: Claude <noreply@anthropic.com>\n'
               'Co-authored-by: Copilot <copilot@github.com>\n')
        r = _run_hook(msg)
        self.assertNotEqual(r.returncode, 0)

    # --- SHOULD ALLOW ---

    def test_allows_plain_commit(self):
        r = _run_hook('Fix a bug in the scanner')
        self.assertEqual(r.returncode, 0)

    def test_allows_human_co_author(self):
        r = _run_hook('Fix\n\nCo-authored-by: Jane Doe <jane@example.com>')
        self.assertEqual(r.returncode, 0)

    def test_allows_claude_in_message_body(self):
        r = _run_hook('Fix bug reported by Claude in review\n\nRefactored the parser.')
        self.assertEqual(r.returncode, 0)

    def test_allows_anthropic_in_message_body(self):
        r = _run_hook('Update Anthropic SDK dependency\n\nBumped to v2.0.')
        self.assertEqual(r.returncode, 0)

    def test_allows_empty_message(self):
        r = _run_hook('')
        self.assertEqual(r.returncode, 0)

    def test_allows_multiline_without_trailers(self):
        r = _run_hook('Title\n\nBody line 1\nBody line 2\n\nSigned-off-by: Adam <adam@kth.se>')
        self.assertEqual(r.returncode, 0)


if __name__ == '__main__':
    unittest.main()
