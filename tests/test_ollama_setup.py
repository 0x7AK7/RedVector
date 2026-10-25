"""Setup regressions use temporary paths and controlled external boundaries."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
from redvector_ollama_setup import Ollama, Wizard, SetupError, model_id, save_model, load_model, Terminal

class SetupTests(unittest.TestCase):
    def wizard(self, answers, api=None):
        return Wizard(api or Mock(), Terminal(io.StringIO()), iter(answers).__next__)
    def test_invalid_model(self):
        for name in ("", "-x", "a;id", "a b", "../model", "https://evil/x", "a\n"):
            with self.subTest(name=name), self.assertRaises(SetupError): model_id(name)
        self.assertEqual(model_id("dolphin-llama3:8b"),"dolphin-llama3:8b")
    def test_local_endpoint_only(self):
        for url in ("http://evil:11434","https://127.0.0.1:11434","http://user@127.0.0.1:11434",
                    "http://127.0.0.1:11434/path","http://127.0.0.1:11434?x=1"):
            with self.subTest(url=url),self.assertRaises(SetupError): Ollama(url)
    def test_configuration_is_separate_atomic_and_validated(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"ollama"/"config.json"; claude=Path(d)/"claude_desktop_config.json"
            claude.write_bytes(b'{"unchanged": true}')
            save_model("gpt-oss:20b",path)
            self.assertEqual(load_model(path),"gpt-oss:20b")
            self.assertEqual(claude.read_bytes(),b'{"unchanged": true}')
            with self.assertRaises(SetupError):save_model("bad;id",path)
            self.assertEqual(load_model(path),"gpt-oss:20b")
    def test_ollama_present_is_reused(self):
        api=Mock();api.healthy.return_value=True
        with patch("shutil.which",return_value="/usr/bin/ollama"):
            self.assertTrue(self.wizard([],api).install_ollama())
    def test_missing_ollama_declined(self):
        api=Mock();api.healthy.return_value=False
        with patch("shutil.which",return_value=None):
            self.assertFalse(self.wizard(["2"],api).install_ollama())
    def test_missing_ollama_exit(self):
        api=Mock();api.healthy.return_value=False
        with patch("shutil.which",return_value=None),self.assertRaises(SystemExit):
            self.wizard(["3"],api).install_ollama()
    def test_existing_model_not_downloaded(self):
        api=Mock();api.models.return_value=[{"name":"dolphin-llama3:8b","size":4700000000}]
        result=self.wizard(["1"],api).select_model()
        self.assertEqual(result,"dolphin-llama3:8b")
        api.pull.assert_not_called()
    def test_choose_installed_model(self):
        api=Mock();api.models.return_value=[{"name":"local:latest","size":1}]
        self.assertEqual(self.wizard(["5","1"],api).select_model(),"local:latest")
    def test_insufficient_storage_prevents_pull(self):
        api=Mock();api.models.return_value=[]
        wizard=self.wizard(["1"],api)
        with patch.object(wizard,"resource_budget",side_effect=SetupError("Insufficient storage")),self.assertRaises(SetupError):
            wizard.select_model()
        api.pull.assert_not_called()
    def test_successful_selection_pulls_then_verifies(self):
        api=Mock();api.models.return_value=[]
        wizard=self.wizard(["3"],api)
        with patch.object(wizard,"resource_budget",return_value=None):
            self.assertEqual(wizard.select_model(),"gpt-oss:20b")
        api.pull.assert_called_once_with("gpt-oss:20b")
        api.show.assert_called_once_with("gpt-oss:20b")
    def test_invalid_custom_model_never_downloads(self):
        api=Mock();api.models.return_value=[]
        with self.assertRaises(SetupError):self.wizard(["4","bad;id"],api).select_model()
        api.pull.assert_not_called()
    def test_cancellation_and_no_ansi(self):
        term=Terminal(io.StringIO());term.message("success","ready")
        self.assertNotIn("\x1b",term.stream.getvalue())
        wizard=Wizard(Mock(),term,lambda:(_ for _ in ()).throw(EOFError()))
        with self.assertRaises(SystemExit):wizard.ask("Choose")
    def test_unavailable_service_fails_without_starting_duplicate(self):
        api=Ollama()
        with patch.object(api,"healthy",return_value=False),patch("socket.create_connection") as sock:
            with self.assertRaises(SetupError): api.ensure_service()
