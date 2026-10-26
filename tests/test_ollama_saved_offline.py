import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch,Mock
from redvector_ollama_results import ResultsStore
from redvector_ollama_setup import saved_result_mode
from test_ollama_results import response

class OfflineResults(unittest.TestCase):
    def test_saved_results_open_without_mcp_or_ollama(self):
        with tempfile.TemporaryDirectory() as d:
            store=ResultsStore(Path(d)/"results");record=store.save("nmap_scan","fixture",{},response(),{"original":True},1)
            for mode in ("results","raw","export"):
                args=SimpleNamespace(results=None,raw=None,export=None,summary=None,page=1)
                setattr(args,mode,record["id"])
                with patch("redvector_ollama_setup.ResultsStore",return_value=store),patch("redvector_ollama_setup.Ollama",side_effect=AssertionError("Offline view must not open API")),patch("sys.stdout",new=io.StringIO()) as out:
                    self.assertEqual(saved_result_mode(args),0)
                    self.assertTrue(out.getvalue())
    def test_no_saved_data_is_an_error_without_network_access(self):
        with tempfile.TemporaryDirectory() as d:
            store=ResultsStore(Path(d)/"results")
            args=SimpleNamespace(results="latest",raw=None,export=None,summary=None,page=1)
            with patch("redvector_ollama_setup.ResultsStore",return_value=store),patch("redvector_ollama_setup.Ollama",side_effect=AssertionError("No API allowed")),patch("sys.stdout",new=io.StringIO()):
                self.assertEqual(saved_result_mode(args),1)
