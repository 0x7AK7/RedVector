"""Capacity checks use metadata, not model-file access or guessed ancestors."""
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch
from redvector_ollama_storage import StorageInfo
from redvector_ollama_capacity import (
    CapacitySnapshot,CapacityAssessment,probe_storage,measure_directory,
    current_identity,trusted_executable,service_probe_command,_PROBE_NS)
from redvector_ollama_setup import Wizard,Terminal,SetupError,DownloadCancelled

def verified(free=20_000_000_000,readonly=False):
    return CapacitySnapshot("verified",available_bytes=free,total_bytes=free+10_000_000_000,
                            checked_path="/fixture/volume",device="fixture-device",read_only=readonly)

def assessment(blob=None,metadata=None):
    return CapacityAssessment(blob or verified(),metadata or verified())

@unittest.skipUnless(sys.platform.startswith("linux"),"Real Linux metadata-only capacity APIs")
class LinuxCapacity(unittest.TestCase):
    def test_private_leaf_capacity_needs_no_directory_listing(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"private-model-data";path.mkdir()
            path.chmod(0)
            try:
                before=stat.S_IMODE(path.stat().st_mode)
                if os.geteuid()!=0:
                    with self.assertRaises(PermissionError):list(path.iterdir())
                result=measure_directory(str(path))
                self.assertEqual(result["status"],"verified",result)
                self.assertGreater(result["available_bytes"],0)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode),before)
            finally:path.chmod(0o700)

    def test_private_parent_never_substitutes_root_or_ancestor_capacity(self):
        if os.geteuid()==0:self.skipTest("Root bypasses traversal permissions")
        with tempfile.TemporaryDirectory() as d:
            private=Path(d)/"private";private.mkdir()
            models=private/"models";models.mkdir()
            private.chmod(0)
            try:
                result=measure_directory(str(models/"blobs"))
                self.assertEqual(result["status"],"unverified")
                self.assertIsNone(result["available_bytes"])
                self.assertIsNone(result.get("checked_path"))
            finally:private.chmod(0o700)

    def test_denied_traversal_followed_by_parent_components_never_verifies_another_path(self):
        if os.geteuid()==0:self.skipTest("Root bypasses traversal permissions")
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);private=root/"private";private.mkdir()
            accessible=root/"accessible";accessible.mkdir()
            private.chmod(0)
            try:
                for path in (private/"link"/".."/".."/"accessible"/"blobs",private/".."/"accessible"/"blobs"):
                    result=measure_directory(str(path))
                    self.assertEqual(result["status"],"unverified",result)
                    self.assertIsNone(result["available_bytes"])
            finally:private.chmod(0o700)

    def test_unresolvable_installer_name_keeps_numeric_uid_and_no_guessed_home(self):
        import pwd
        with patch("pwd.getpwuid",side_effect=KeyError("not resolvable")),patch("pathlib.Path.home",side_effect=RuntimeError("no home")):
            identity=current_identity()
        self.assertEqual(identity.uid,os.geteuid())
        self.assertEqual(identity.name,f"UID {os.geteuid()}")
        self.assertIsNone(identity.home)

    def test_symlinked_blobs_measure_destination_not_models_parent(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);models=root/"models";models.mkdir()
            target=root/"separate-volume";target.mkdir()
            (models/"blobs").symlink_to(target,target_is_directory=True)
            result=measure_directory(str(models/"blobs"))
            self.assertEqual(result["status"],"verified",result)
            self.assertEqual(Path(result["checked_path"]),target.resolve())
            self.assertEqual(result["device"],str(target.stat().st_dev))

    def test_missing_symlink_target_uses_resolved_volume_parent(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);volume=root/"volume";volume.mkdir()
            models=root/"models";models.symlink_to(volume/"missing"/"models",target_is_directory=True)
            result=measure_directory(str(models/"blobs"))
            self.assertEqual(result["status"],"verified",result)
            self.assertEqual(Path(result["checked_path"]),volume.resolve())
            self.assertFalse((volume/"missing").exists())

    def test_symlink_resolution_preserves_parent_component_order(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);volume=root/"volume";volume.mkdir()
            child=volume/"child";child.mkdir()
            (root/"alias").symlink_to(child,target_is_directory=True)
            result=measure_directory(str(root/"alias"/".."/"new"/"blobs"))
            self.assertEqual(result["status"],"verified",result)
            self.assertEqual(Path(result["checked_path"]),volume.resolve())

    def test_proc_fd_text_path_is_optional(self):
        with tempfile.TemporaryDirectory() as d:
            original=os.readlink
            def restricted(path,*a,**kw):
                if str(path).startswith("/proc/self/fd/"):raise PermissionError("restricted fd text")
                return original(path,*a,**kw)
            with patch("os.readlink",side_effect=restricted):
                result=measure_directory(d)
            self.assertEqual(result["status"],"verified",result)

    def test_autofs_is_not_reported_as_storage_capacity(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(_PROBE_NS,{"filesystem_type":lambda fd:"autofs"}):
            result=measure_directory(d)
        self.assertEqual(result["status"],"unverified")
        self.assertIsNone(result["available_bytes"])

    def test_symlink_loop_is_unknown_not_parent_capacity(self):
        with tempfile.TemporaryDirectory() as d:
            link=Path(d)/"loop";link.symlink_to(link)
            result=measure_directory(str(link/"blobs"))
            self.assertEqual(result["status"],"unverified")
            self.assertIsNone(result["available_bytes"])

    def test_v2_manifest_volume_is_measured_independently(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);volume=root/"metadata-volume";volume.mkdir()
            models=root/"models";models.mkdir()
            (models/"manifests-v2").symlink_to(volume,target_is_directory=True)
            result=probe_storage(StorageInfo(models,"explicit local fixture"))
            self.assertTrue(result.manifests_v2.verified,result)
            self.assertEqual(Path(result.manifests_v2.checked_path),volume.resolve())

    def test_runtime_path_uses_ollamas_clean_join_semantics_before_filesystem_resolution(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            configured=str(root/"alias"/".."/"effective")
            fields="44 (ollama) "+" ".join(["S"]+["0"]*18+["777"])
            def link(path):
                text=str(path)
                if text.endswith("/exe"):return "/runtime/ollama"
                if text.endswith("/ns/mnt"):return "mnt:[123]"
                if text.endswith("/root"):return "/"
                if text.endswith("/cwd"):return str(root)
                raise AssertionError(text)
            with patch("pathlib.Path.read_text",return_value=fields),patch("pathlib.Path.read_bytes",return_value=("OLLAMA_MODELS="+configured+"\0").encode()),patch("os.readlink",side_effect=link):
                result=_PROBE_NS["server_root"]("unused",44,"777","/runtime/ollama")
            self.assertEqual(result,root/"effective")

    def test_blobs_and_metadata_are_measured_separately(self):
        with tempfile.TemporaryDirectory() as d:
            info=StorageInfo(Path(d),"explicit local fixture")
            result=probe_storage(info)
            self.assertTrue(result.blobs.verified,result)
            self.assertTrue(result.manifests.verified,result)
            self.assertEqual(result.blobs.quota_status,"Unverified")
            self.assertEqual(result.manifests.quota_status,"Unverified")

class CapacityDecisions(unittest.TestCase):
    def wizard(self,answers=()):
        api=Mock();api.host="127.0.0.1";api.port=11434
        api.healthy.return_value=True;api.manifest_size.return_value=5_200_000_000
        return Wizard(api,Terminal(io.StringIO()),iter(answers).__next__)

    def budget(self,wizard,result):
        with patch.object(wizard,"storage_location",return_value=StorageInfo(Path.cwd(),"verified process")),patch("redvector_ollama_setup.probe_storage",return_value=result),patch("shutil.which",return_value=None):
            return wizard.resource_budget("qwen3:8b",5.2)

    def test_verified_insufficient_blobs_cannot_offer_unknown_bypass(self):
        wizard=self.wizard(["UNVERIFIED","y"])
        with self.assertRaisesRegex(SetupError,"Insufficient"):
            self.budget(wizard,assessment(blob=verified(1)))
        self.assertNotIn("STORAGE CAPACITY UNVERIFIED",wizard.term.stream.getvalue())
        wizard.api.pull.assert_not_called()

    def test_shared_filesystem_includes_both_blob_and_manifest_reservations(self):
        wizard=self.wizard(["y"])
        required=int(5_200_000_000*1.15)+1_000_000_000
        free=required+8*1024*1024
        with self.assertRaisesRegex(SetupError,"Insufficient"):
            self.budget(wizard,assessment(verified(free),verified(free)))
        wizard.api.pull.assert_not_called()

    def test_remote_or_forwarded_engine_is_not_labeled_local(self):
        wizard=self.wizard()
        wizard.api.host="remote.invalid"
        info=StorageInfo(None,"forwarded endpoint","remote storage",manual_allowed=False)
        wizard.preflight("qwen3:8b",0,info,assessment(),installed=True,metadata={"capabilities":["tools"]})
        self.assertNotIn("Detected through the local API",wizard.term.stream.getvalue())

    def test_metadata_insufficiency_is_a_hard_stop_even_with_unknown_blobs(self):
        wizard=self.wizard(["UNVERIFIED"])
        with self.assertRaisesRegex(SetupError,"Insufficient"):
            self.budget(wizard,assessment(CapacitySnapshot("unverified",reason="private"),verified(0)))
        wizard.api.pull.assert_not_called()

    def test_v2_metadata_insufficiency_is_a_hard_stop(self):
        wizard=self.wizard(["UNVERIFIED"])
        result=CapacityAssessment(verified(),verified(),manifests_v2=verified(0))
        with self.assertRaisesRegex(SetupError,"Insufficient"):
            self.budget(wizard,result)
        wizard.api.pull.assert_not_called()

    def test_readonly_storage_cannot_be_reclassified_unknown(self):
        wizard=self.wizard(["UNVERIFIED"])
        with self.assertRaisesRegex(SetupError,"read-only"):
            self.budget(wizard,assessment(blob=verified(readonly=True)))

    def test_unknown_capacity_defaults_to_cancellation(self):
        wizard=self.wizard([""])
        with self.assertRaises(DownloadCancelled):
            self.budget(wizard,assessment(blob=CapacitySnapshot("unverified",reason="private parent")))
        wizard.api.pull.assert_not_called()

    def test_unknown_capacity_requires_explicit_separate_consent(self):
        wizard=self.wizard(["UNVERIFIED","y"])
        self.budget(wizard,assessment(blob=CapacitySnapshot("unverified",reason="private parent")))
        output=wizard.term.stream.getvalue()
        self.assertIn("Unverified",output)
        self.assertIn("Unknown",output)
        self.assertNotIn("Available space:    0",output)
        wizard.api.pull.assert_not_called()

    def test_failed_readonly_probe_reason_is_visible_without_an_installation_retry(self):
        wizard=self.wizard(["1",""])
        info=StorageInfo(Path.cwd(),"service",uid=2001,pid=44,started=1.0,host="127.0.0.1",port=11434)
        initial=assessment(blob=CapacitySnapshot("unverified",reason="private directory"))
        failed=CapacityAssessment(CapacitySnapshot("unverified",reason="Probe authentication cancelled"),
                                  CapacitySnapshot("unverified",reason="Probe authentication cancelled"))
        command=["/trusted/sudo","-u","#2001","--","/trusted/python"]
        with patch("redvector_ollama_setup.service_probe_command",return_value=command),patch("redvector_ollama_setup.probe_storage",return_value=failed):
            with self.assertRaises(DownloadCancelled):
                wizard.confirm_unknown_capacity("qwen3:8b",5_200_000_000,info,initial,7_000_000_000)
        self.assertIn("Probe authentication cancelled",wizard.term.stream.getvalue())
        self.assertNotIn("Retry installation",wizard.term.stream.getvalue())
        wizard.api.pull.assert_not_called()

    def test_normal_confirmation_does_not_count_as_unknown_consent(self):
        wizard=self.wizard(["y"])
        with self.assertRaises(DownloadCancelled):
            self.budget(wizard,assessment(blob=CapacitySnapshot("unverified",reason="hidden volume")))

    def test_real_api_failure_stops_before_storage_or_download(self):
        wizard=self.wizard([])
        wizard.api.healthy.return_value=False
        with patch.object(wizard,"storage_location") as storage,self.assertRaisesRegex(SetupError,"API"):
            wizard.resource_budget("qwen3:8b",5.2)
        storage.assert_not_called();wizard.api.pull.assert_not_called()

    def test_preflight_reports_actual_data_and_unverified_quota(self):
        wizard=self.wizard(["y"])
        self.budget(wizard,assessment())
        output=wizard.term.stream.getvalue()
        for required in ("OLLAMA PREFLIGHT CHECK","qwen3:8b","5.20 GB","Verified","20.00 GB","Unverified","Tool calling"):
            self.assertIn(required,output)

    def test_declining_download_is_not_an_installation_retry_loop(self):
        wizard=self.wizard(["6"])
        with patch.object(wizard,"install_ollama",return_value=True),patch.object(wizard,"select_model",side_effect=DownloadCancelled("Download cancelled")),patch("redvector_ollama_setup.load_model",return_value=None):
            wizard.run(install=True)
        self.assertNotIn("Retry installation",wizard.term.stream.getvalue())
        wizard.api.pull.assert_not_called()

class ProbeSafety(unittest.TestCase):
    def test_user_writable_probe_executable_is_not_trusted(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"interpreter";path.write_text("not executable")
            self.assertIsNone(trusted_executable(str(path)))

    def test_no_automatic_sudo_for_unknown_metadata(self):
        with patch("redvector_ollama_capacity.subprocess.run") as runner:
            result=probe_storage(StorageInfo(None,"unknown","restricted"))
        self.assertFalse(result.blobs.verified);runner.assert_not_called()

    def test_service_probe_can_recover_executable_metadata_under_the_approved_uid(self):
        from types import SimpleNamespace
        info=StorageInfo(Path.cwd(),"verified service",uid=2001,pid=44,started=1.0,host="127.0.0.1",port=11434)
        process=Mock();process.create_time.return_value=1.0
        process.cmdline.return_value=["/custom/bin/ollama","serve"]
        process.uids.return_value=SimpleNamespace(effective=2001)
        fields="44 (ollama) "+" ".join(["S"]+["0"]*18+["777"])
        with patch("redvector_ollama_capacity.psutil.Process",return_value=process),patch("os.readlink",side_effect=PermissionError("restricted")),patch("pathlib.Path.read_text",return_value=fields),patch("shutil.which",return_value="/trusted/sudo"),patch("redvector_ollama_capacity.trusted_executable",side_effect=["/trusted/sudo","/trusted/python"]):
            command=service_probe_command(info)
        self.assertEqual(command[1:4],["-u","#2001","--"])
        self.assertEqual(command[-4],"777")
        self.assertEqual(command[-3],"")

    def test_unverified_service_identity_cannot_request_privileged_probe(self):
        with self.assertRaises(ValueError):
            service_probe_command(StorageInfo(Path.cwd(),"manual",uid=2001))

class EndpointAssociation(unittest.TestCase):
    def verify(self,rows,inodes=(111,),namespace="net:[1]",mapped_rows=()):
        import socket
        address=int.from_bytes(socket.inet_pton(socket.AF_INET,"127.0.0.1"),sys.byteorder)
        table="header\n"+"\n".join(f"0: {address:08X}:2CAA 00000000:0000 0A 0:0 0:0 0 1000 0 {inode}" for inode in rows)
        packed=socket.inet_pton(socket.AF_INET6,"::ffff:127.0.0.1")
        encoded="".join(f"{int.from_bytes(packed[i:i+4],sys.byteorder):08X}" for i in range(0,16,4))
        table6="header\n"+"\n".join(f"0: {encoded}:2CAA 00000000000000000000000000000000:0000 0A 0:0 0:0 0 1000 0 {inode}" for inode in mapped_rows)
        def read(path,*args,**kwargs):
            return table6 if str(path).endswith("tcp6") else table
        def link(path,*args,**kwargs):
            text=str(path)
            if text=="/proc/self/ns/net":return "net:[1]"
            if text=="/proc/44/ns/net":return namespace
            if "/fd/" in text:return "socket:["+text.rsplit("/",1)[1]+"]"
            raise AssertionError(text)
        with patch("pathlib.Path.read_text",autospec=True,side_effect=read),patch("os.listdir",return_value=[str(n) for n in inodes]),patch("os.readlink",side_effect=link):
            return _PROBE_NS["verify_endpoint"](44,"127.0.0.1",11434)

    def test_owned_matching_listener_verifies_endpoint(self):
        self.verify((111,))

    def test_another_process_reuseport_listener_makes_endpoint_ambiguous(self):
        with self.assertRaises(PermissionError):self.verify((111,222))

    def test_different_network_namespace_cannot_identify_client_endpoint(self):
        with self.assertRaises(PermissionError):self.verify((111,),namespace="net:[2]")

    def test_owned_ipv4_mapped_listener_is_supported(self):
        self.verify((),mapped_rows=(111,))

    def test_foreign_ipv4_mapped_listener_makes_endpoint_ambiguous(self):
        with self.assertRaises(PermissionError):self.verify((111,),mapped_rows=(222,))

    def test_missing_listener_is_not_a_verified_service(self):
        with self.assertRaises(PermissionError):self.verify(())

class RestrictedServiceProbe(unittest.TestCase):
    def test_unreadable_process_identity_returns_a_clear_unavailable_probe(self):
        import psutil
        info=StorageInfo(Path.cwd(),"service",uid=2001,pid=44,started=1.0,host="127.0.0.1",port=11434)
        with patch("redvector_ollama_capacity._server_identity",side_effect=psutil.AccessDenied(44)):
            with self.assertRaises(ValueError):service_probe_command(info)
