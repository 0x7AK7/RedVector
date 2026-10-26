"""Selection uses capability evidence, never names; all download boundaries are fakes."""
import io
import unittest
from unittest.mock import Mock, patch
from redvector_ollama_setup import Wizard, Terminal, SetupError, DownloadCancelled
from redvector_ollama_models import ModelCompatibility

class Selection(unittest.TestCase):
    def wizard(self,answers,installed=False,state="SUPPORTED",model="owner/custom:variant"):
        api=Mock()
        api.models.return_value=[{"name":model,"size":123}] if installed else []
        api.show.return_value={"capabilities":["tools"]} if state=="SUPPORTED" else {"capabilities":["completion"]} if state=="UNSUPPORTED" else {}
        api.registry_info.return_value=ModelCompatibility(model,"UNVERIFIED","Official metadata incomplete","Official registry",1234)
        api.healthy.return_value=False
        wizard=Wizard(api,Terminal(io.StringIO()),iter(answers).__next__)
        wizard.resource_budget=Mock()
        wizard.verify_model=Mock(return_value={"status":"healthy"})
        return wizard,api

    def test_installed_custom_supported_no_pull_or_registry(self):
        w,api=self.wizard(["5","1"],installed=True)
        self.assertEqual(w.select_model(),"owner/custom:variant")
        api.pull.assert_not_called();api.registry_info.assert_not_called()
        w.verify_model.assert_called_once_with("owner/custom:variant")
        self.assertIn("Tool Calling:      Supported",w.term.stream.getvalue())
        self.assertIn("Download Required: No",w.term.stream.getvalue())

    def test_confirmed_unsupported_never_downloads_or_verifies_or_saves(self):
        for installed in (False,True):
            w,api=self.wizard(["4","owner/custom:variant","2"],installed,"UNSUPPORTED")
            self.assertIsNone(w.select_model())
            api.pull.assert_not_called();w.resource_budget.assert_not_called();w.verify_model.assert_not_called()
            self.assertIn("MODEL NOT COMPATIBLE",w.term.stream.getvalue())
            self.assertIn("Tool Calling:      Unsupported",w.term.stream.getvalue())

    def test_unverified_requires_exact_informed_consent_before_capacity_or_pull(self):
        for answer in ("","y","UNVERIFIED","download unverified","cancel"):
            w,api=self.wizard(["4","owner/custom:variant",answer],False,"UNVERIFIED")
            with self.assertRaises(DownloadCancelled):w.select_model()
            api.pull.assert_not_called();w.resource_budget.assert_not_called()
            self.assertIn("Tool Calling:      Unverified",w.term.stream.getvalue())

    def test_unverified_explicit_consent_still_checks_storage_and_verifies(self):
        w,api=self.wizard(["4","owner/custom:variant","DOWNLOAD UNVERIFIED"],False,"UNVERIFIED")
        calls=[]
        w.resource_budget.side_effect=lambda *args:calls.append("capacity")
        api.pull.side_effect=lambda *args:calls.append("pull")
        w.verify_model.side_effect=lambda *args:calls.append("verify")
        self.assertEqual(w.select_model(),"owner/custom:variant")
        self.assertEqual(calls,["capacity","pull","verify"])
        self.assertIn("Estimated Size:",w.term.stream.getvalue())

    def test_failed_post_selection_offers_back_without_acceptance(self):
        w,api=self.wizard(["5","1","2"],True)
        w.verify_model.side_effect=SetupError("Native tool call failed.")
        self.assertIsNone(w.select_model())
        self.assertIn("Native tool call failed.",w.term.stream.getvalue())
        self.assertIn("Previous selection remains unchanged",w.term.stream.getvalue())
        api.pull.assert_not_called()

    def test_incompatible_choose_another_and_exit(self):
        w,api=self.wizard(["4","owner/custom:variant","1","6"],False,"UNSUPPORTED")
        self.assertIsNone(w.select_model())
        w,api=self.wizard(["4","owner/custom:variant","3"],False,"UNSUPPORTED")
        with self.assertRaises(SystemExit):w.select_model()
        api.pull.assert_not_called()

    def test_storage_cancel_after_supported_check_never_pulls(self):
        w,api=self.wizard(["4","owner/custom:variant"])
        w.resource_budget.side_effect=DownloadCancelled("Cancelled")
        with self.assertRaises(DownloadCancelled):w.select_model()
        api.pull.assert_not_called();w.verify_model.assert_not_called()

    def test_selection_has_no_model_deletion_path(self):
        w,api=self.wizard(["6"])
        self.assertIsNone(w.select_model())
        api.delete.assert_not_called();api.pull.assert_not_called()

    def test_malformed_installed_capabilities_recovers_without_traceback(self):
        w,api=self.wizard(["5","1","2"],True,"UNVERIFIED")
        api.show.return_value={"capabilities":None}
        api.healthy.return_value=True
        w.verify_model.side_effect=SetupError("Native capability evidence is missing.")
        from redvector_ollama_storage import StorageInfo
        from redvector_ollama_capacity import CapacityAssessment,CapacitySnapshot
        capacity=CapacityAssessment(CapacitySnapshot("unverified"),CapacitySnapshot("unverified"))
        with patch("redvector_ollama_setup.detect_storage",return_value=StorageInfo(None,"unknown")),patch("redvector_ollama_setup.probe_storage",return_value=capacity):
            self.assertIsNone(w.select_model())
        api.pull.assert_not_called()
