"""Model-facing schemas must describe the restrictions actually enforced."""
import io
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from redvector_ollama_agent import tool_schema
from redvector_ollama_setup import Wizard,Terminal,SetupError
from redvector_ollama_storage import StorageInfo
from redvector_ollama_capacity import CapacityAssessment,CapacitySnapshot
from pathlib import Path

class SchemaViewTests(unittest.TestCase):
    def test_nmap_schema_advertises_fixed_arguments_without_changing_catalog(self):
        schema={"type":"object","properties":{"target":{"type":"string"},"scan_type":{"type":"string","default":"-sV"},"ports":{"type":"string"},"additional_args":{"type":"string"}},"required":["target"]}
        tool=SimpleNamespace(name="nmap_scan",description="Nmap",inputSchema=schema)
        view=tool_schema(tool)["function"]["parameters"]
        self.assertEqual(view["properties"]["scan_type"]["enum"],["-sT","-6 -sT"])
        self.assertEqual(view["properties"]["scan_type"]["default"],"-sT")
        self.assertEqual(view["properties"]["additional_args"]["enum"],[""])
        self.assertFalse(view["additionalProperties"])
        self.assertEqual(schema["properties"]["scan_type"]["default"],"-sV")
    def test_constrained_memory_gets_explicit_warning(self):
        api=Mock();api.manifest_size.return_value=10_000_000_000
        wizard=Wizard(api,Terminal(io.StringIO()),lambda:"n")
        with patch.object(wizard,"storage_location",return_value=StorageInfo(Path.cwd(),"OS fixture")),patch("redvector_ollama_setup.probe_storage",return_value=CapacityAssessment(CapacitySnapshot("verified",available_bytes=100_000_000_000),CapacitySnapshot("verified",available_bytes=100_000_000_000))),patch("psutil.virtual_memory",return_value=SimpleNamespace(total=8_000_000_000,available=1_000_000_000)),patch("shutil.which",return_value=None):
            with self.assertRaises(SetupError):wizard.resource_budget("custom")
        self.assertIn("below",wizard.term.stream.getvalue())
