"""Storage detection uses read-only OS boundary fixtures, never real model downloads."""
import io
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
import psutil
from redvector_ollama_storage import StorageInfo,StorageError,detect_storage,filesystem_path,directory_permissions
from redvector_ollama_setup import Ollama,Wizard,Terminal,SetupError

class StorageDetection(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.home=self.root/"service-home"
        self.home.mkdir()
        self.unit=self.root/"ollama.service"
        self.unit.write_text("[Service]\nUser=separate-operator\n")
        self.proc=Mock()
        self.proc.pid=44
        self.proc.cmdline.return_value=["/opt/runtime/bin/ollama","serve"]
        self.proc.exe.return_value="/opt/runtime/bin/ollama"
        self.proc.environ.return_value={"HOME":str(self.home)}
        self.proc.cwd.return_value=str(self.root)
        self.proc.uids.return_value=SimpleNamespace(effective=2001)
        self.proc.gids.return_value=SimpleNamespace(real=2001,effective=2001,saved=2001)
        self.proc.create_time.return_value=time.time()+20
        self.properties={"ActiveState":"active","MainPID":"44","User":"separate-operator",
            "Environment":"","EnvironmentFiles":"","FragmentPath":str(self.unit),"DropInPaths":"",
            "ExecStart":"{ path=/opt/runtime/bin/ollama ; argv[]=/opt/runtime/bin/ollama serve ; }"}
        for target,value in [
            ("redvector_ollama_storage.psutil.Process",self.proc),
            ("redvector_ollama_storage.listener_pids",{44}),
            ("redvector_ollama_storage.same_namespace",True),
            ("redvector_ollama_storage.unit_properties",self.properties),
            ("redvector_ollama_storage.account",SimpleNamespace(pw_dir=str(self.home),pw_uid=2001,pw_gid=2001))]:
            p=patch(target,return_value=value);p.start();self.addCleanup(p.stop)

    def detect(self):return detect_storage("127.0.0.1",11434)

    def systemd(self):
        self.proc.environ.side_effect=psutil.AccessDenied(44)
        return self.detect()

    def test_manual_process_uses_its_home_not_callers_home(self):
        with patch.dict(os.environ,{"HOME":str(self.root/"caller"),"OLLAMA_MODELS":str(self.root/"wrong")}):
            result=self.detect()
        self.assertEqual(result.path,self.home/".ollama"/"models")
        self.assertEqual(result.uid,2001)

    def test_effective_process_override_wins(self):
        models=self.root/"shared-models"
        self.proc.environ.return_value={"HOME":str(self.home),"OLLAMA_MODELS":str(models)}
        self.assertEqual(self.detect().path,models)

    def test_relative_override_uses_server_working_directory(self):
        self.proc.environ.return_value={"OLLAMA_MODELS":"models with spaces"}
        self.assertEqual(self.detect().path,self.root/"models with spaces")

    def test_literal_tilde_override_is_not_expanded_as_shell_home(self):
        self.proc.environ.return_value={"OLLAMA_MODELS":"~/weights"}
        self.assertEqual(self.detect().path,self.root/"~"/"weights")

    def test_missing_process_home_is_unknown_not_guessed(self):
        self.proc.environ.return_value={}
        self.assertIsNone(self.detect().path)

    def test_systemd_group_override_does_not_invent_account_primary_group_membership(self):
        self.proc.gids.return_value=SimpleNamespace(real=3000,effective=3000,saved=3000)
        with patch("pathlib.Path.read_text",return_value="Groups: 3000\n"):
            result=self.systemd()
        self.assertNotIn(2001,result.gids)
        self.assertIn(3000,result.gids)

    def test_standard_systemd_user_account_home_is_detected(self):
        result=self.systemd()
        self.assertEqual(result.path,self.home/".ollama"/"models")
        self.assertIn("systemd",result.source)

    def test_user_manager_service_uses_actual_process_uid_when_user_is_implicit(self):
        self.properties["User"]=""
        self.properties["_UserManager"]="yes"
        self.assertEqual(self.systemd().path,self.home/".ollama"/"models")

    def test_unresolvable_service_name_can_still_use_verified_uid_and_explicit_override(self):
        self.properties["Environment"]='OLLAMA_MODELS="'+str(self.root/"explicit-models")+'"'
        with patch("redvector_ollama_storage.account",side_effect=KeyError("name unavailable")):
            self.assertEqual(self.systemd().path,self.root/"explicit-models")

    def test_systemd_custom_environment_overrides_account_home(self):
        self.properties["Environment"]='HOME="'+str(self.root/"custom home")+'" OLLAMA_MODELS="'+str(self.root/"custom weights")+'"'
        self.assertEqual(self.systemd().path,self.root/"custom weights")

    def test_systemd_custom_home_without_override(self):
        self.properties["Environment"]='HOME="'+str(self.root/"custom home")+'"'
        self.assertEqual(self.systemd().path,self.root/"custom home"/".ollama"/"models")

    def test_systemd_environment_file_overrides_environment_property(self):
        env=self.root/"service.env"
        env.write_text('OLLAMA_MODELS="'+(self.root/"env weights").as_posix()+'"\n')
        self.properties["Environment"]='OLLAMA_MODELS="'+str(self.root/"wrong")+'"'
        self.properties["EnvironmentFiles"]=str(env)+" (ignore_errors=no)"
        self.assertEqual(self.systemd().path,self.root/"env weights")

    def test_multiline_unrelated_environment_value_cannot_inject_model_assignment(self):
        env=self.root/"multiline.env"
        env.write_text("UNRELATED='multiline\nOLLAMA_MODELS="+(self.root/"wrong-disk").as_posix()+"\n'\n")
        self.properties["EnvironmentFiles"]=str(env)+" (ignore_errors=no)"
        self.assertIsNone(self.systemd().path)

    def test_image_mount_is_not_mapped_to_host_directory(self):
        self.properties["MountImages"]="/image.raw:/model-storage"
        self.assertIsNone(self.systemd().path)

    def test_unreadable_environment_file_does_not_guess(self):
        self.properties["EnvironmentFiles"]=str(self.root/"missing")+" (ignore_errors=no)"
        self.assertIsNone(self.systemd().path)

    def test_stale_service_configuration_is_not_treated_as_running_environment(self):
        self.proc.create_time.return_value=self.unit.stat().st_mtime-10
        self.assertIsNone(self.systemd().path)

    def test_environment_wrapper_requires_manual_detection(self):
        self.properties["ExecStart"]="{ path=/usr/bin/env ; argv[]=env OLLAMA_MODELS=elsewhere ollama serve ; }"
        self.assertIsNone(self.systemd().path)

    def test_mismatching_service_pid_does_not_override_endpoint_owner(self):
        self.properties["MainPID"]="99"
        self.assertIsNone(self.systemd().path)

    def test_systemd_other_endpoint_does_not_claim_default_endpoint(self):
        self.properties["Environment"]="OLLAMA_HOST=127.0.0.1:12345"
        self.assertIsNone(self.systemd().path)

    def test_private_root_is_not_mapped_to_host_disk(self):
        self.properties["RootDirectory"]=str(self.root/"chroot")
        self.assertIsNone(self.systemd().path)

    def test_restricted_namespace_metadata_uses_verified_systemd_configuration(self):
        self.proc.environ.side_effect=psutil.AccessDenied(44)
        with patch("redvector_ollama_storage.same_namespace",return_value=None):
            self.assertEqual(self.detect().path,self.home/".ollama"/"models")

    def test_inherited_service_environment_cannot_be_silently_ignored(self):
        self.properties["PassEnvironment"]="OLLAMA_MODELS"
        self.assertIsNone(self.systemd().path)

    def test_configured_unset_override_is_respected(self):
        self.properties["Environment"]='OLLAMA_MODELS="'+str(self.root/"unused")+'"'
        self.properties["UnsetEnvironment"]="OLLAMA_MODELS"
        self.assertEqual(self.systemd().path,self.home/".ollama"/"models")

    def test_optional_missing_environment_file_cannot_reconstruct_old_process(self):
        self.properties["EnvironmentFiles"]=str(self.root/"missing")+" (ignore_errors=yes)"
        self.assertIsNone(self.systemd().path)

    def test_multiple_listeners_are_ambiguous(self):
        with patch("redvector_ollama_storage.listener_pids",return_value={44,55}):
            self.assertIsNone(self.detect().path)

    def test_forwarded_endpoint_cannot_claim_forwarders_home(self):
        self.proc.cmdline.return_value=["ssh","-L","11434:elsewhere:11434"]
        result=self.detect()
        self.assertIsNone(result.path)
        self.assertFalse(result.manual_allowed)

    def test_remote_endpoint_rejects_local_disk_checks(self):
        result=detect_storage("remote.invalid",11434)
        self.assertFalse(result.manual_allowed)
        with self.assertRaises(SetupError):Ollama("http://remote.invalid:11434")

    def test_permission_restricted_process_and_no_service_is_unknown(self):
        with patch("redvector_ollama_storage.unit_properties",return_value={}):
            self.assertIsNone(self.systemd().path)

class StorageFilesystem(unittest.TestCase):
    def test_missing_directory_measures_nearest_existing_parent_without_creating(self):
        with tempfile.TemporaryDirectory() as d:
            model=Path(d)/"nested"/"models"
            self.assertEqual(filesystem_path(StorageInfo(model,"test")),Path(d))
            self.assertFalse(model.exists())

    def test_file_is_not_accepted_as_model_directory(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"file";p.write_text("unchanged")
            with self.assertRaises(StorageError):filesystem_path(StorageInfo(p,"test"))
            self.assertEqual(p.read_text(),"unchanged")

    def test_permission_error_is_clear_and_never_falls_back_to_other_disk(self):
        with patch("pathlib.Path.stat",side_effect=PermissionError("denied")):
            with self.assertRaisesRegex(StorageError,"access"):
                filesystem_path(StorageInfo(Path.cwd()/"private","test"))

    def test_unknown_path_prompts_and_cancel_prevents_download(self):
        api=Mock();api.host="127.0.0.1";api.port=11434
        wizard=Wizard(api,Terminal(io.StringIO()),lambda:"")
        with patch("redvector_ollama_setup.detect_storage",return_value=StorageInfo(None,"unknown","restricted")):
            with self.assertRaisesRegex(SetupError,"cancel"):
                wizard.storage_path()
        api.pull.assert_not_called()

    def test_known_path_never_prompts_and_is_displayed(self):
        with tempfile.TemporaryDirectory() as d:
            api=Mock();api.host="127.0.0.1";api.port=11434
            read=Mock(side_effect=AssertionError("must not prompt"))
            wizard=Wizard(api,Terminal(io.StringIO()),read)
            with patch("redvector_ollama_setup.detect_storage",return_value=StorageInfo(Path(d),"process")):
                self.assertEqual(wizard.storage_path(),Path(d))
            self.assertIn(str(Path(d)),wizard.term.stream.getvalue())
            read.assert_not_called()

    def test_known_readonly_filesystem_fails_before_download(self):
        with tempfile.TemporaryDirectory() as d:
            with patch("os.statvfs",create=True,return_value=SimpleNamespace(f_flag=1)):
                with self.assertRaisesRegex(StorageError,"read-only"):
                    filesystem_path(StorageInfo(Path(d),"test"))

    def test_capacity_path_does_not_require_service_file_access(self):
        metadata=SimpleNamespace(st_mode=0o40700,st_uid=2001,st_gid=2001)
        with patch("pathlib.Path.stat",return_value=metadata),patch("os.statvfs",create=True,return_value=SimpleNamespace(f_flag=0)),patch("redvector_ollama_storage.directory_permissions",side_effect=AssertionError("Capacity must not inspect file-access ACLs")):
            self.assertEqual(filesystem_path(StorageInfo(Path.cwd(),"test",uid=2002,gids=(2002,))),Path.cwd())

    def test_known_service_user_without_write_access_is_not_repaired(self):
        metadata=SimpleNamespace(st_mode=0o40700,st_uid=2001,st_gid=2001)
        with patch("pathlib.Path.stat",return_value=metadata),patch("os.statvfs",create=True,return_value=SimpleNamespace(f_flag=0)):
            self.assertNotEqual(directory_permissions(Path.cwd(),metadata,2002,(2002,)),7)
            self.assertEqual(filesystem_path(StorageInfo(Path.cwd(),"test",uid=2002,gids=(2002,))),Path.cwd())

    def test_remote_environment_endpoint_is_not_silently_replaced_with_localhost(self):
        with patch.dict(os.environ,{"OLLAMA_HOST":"http://remote.invalid:11434"}):
            with self.assertRaisesRegex(SetupError,"Remote"):
                Ollama()

    def test_actual_supplementary_groups_are_read_from_proc_status(self):
        from redvector_ollama_storage import ids
        proc=Mock();proc.pid=44
        proc.uids.return_value=SimpleNamespace(effective=2001)
        proc.gids.return_value=SimpleNamespace(real=2001,effective=2001,saved=2001)
        with patch("pathlib.Path.read_text",return_value="Name: ollama\nGroups: 2001 3001\n"):
            uid,gids=ids(proc)
        self.assertEqual(uid,2001);self.assertIn(3001,gids)

    def test_named_acl_grant_is_respected(self):
        import struct
        # Owner rwx; explicit service-user rwx; no group/other grants.
        acl=struct.pack("<I",2)+b"".join(struct.pack("<HHI",tag,perm,ident) for tag,perm,ident in [
            (1,7,0xffffffff),(2,7,2002),(4,0,0xffffffff),(16,7,0xffffffff),(32,0,0xffffffff)])
        metadata=SimpleNamespace(st_mode=0o40770,st_uid=2001,st_gid=2001)
        with patch("pathlib.Path.stat",return_value=metadata),patch("os.statvfs",create=True,return_value=SimpleNamespace(f_flag=0)),patch("os.getxattr",create=True,return_value=acl):
            self.assertEqual(directory_permissions(Path.cwd(),metadata,2002,(2002,)),7)

    def test_split_group_acl_permissions_do_not_invent_combined_access(self):
        import struct
        acl=struct.pack("<I",2)+b"".join(struct.pack("<HHI",tag,perm,ident) for tag,perm,ident in [
            (1,7,0xffffffff),(4,5,0xffffffff),(8,2,3001),(16,7,0xffffffff),(32,0,0xffffffff)])
        metadata=SimpleNamespace(st_mode=0o40770,st_uid=2001,st_gid=3000)
        with patch("pathlib.Path.stat",return_value=metadata),patch("os.statvfs",create=True,return_value=SimpleNamespace(f_flag=0)),patch("os.getxattr",create=True,return_value=acl):
            self.assertNotEqual(directory_permissions(Path.cwd(),metadata,2002,(3000,3001)),7)

    def test_qwen_preset_uses_existing_model_and_exact_english_label(self):
        api=Mock();api.models.return_value=[{"name":"qwen3:8b"}]
        term=Terminal(io.StringIO())
        result=Wizard(api,term,lambda:"1").select_model()
        self.assertEqual(result,"qwen3:8b")
        self.assertRegex(term.stream.getvalue(),r"1\. Qwen3 8B\s+\| Approx\. 5.2 GB \| Tool Calling")
        api.pull.assert_not_called()

class ServiceManagerDiscovery(unittest.TestCase):
    def test_custom_user_unit_is_discovered_from_verified_process_cgroup(self):
        from redvector_ollama_storage import unit_properties
        data="0::/user.slice/user-4007.slice/user@4007.service/app.slice/research-model.service"
        response=SimpleNamespace(returncode=0,stdout="ActiveState=active\nMainPID=44\n")
        with patch("pathlib.Path.read_text",return_value=data),patch("shutil.which",return_value="/discovered/systemctl"),patch("subprocess.run",return_value=response) as run:
            properties=unit_properties(44)
        args=run.call_args.args[0]
        self.assertIn("--user",args)
        self.assertIn("research-model.service",args)
        self.assertEqual(properties["_UserManager"],"yes")

class ConcreteListenerDiscovery(unittest.TestCase):
    def listener(self,address,pid):
        return SimpleNamespace(status=psutil.CONN_LISTEN,laddr=SimpleNamespace(ip=address,port=11434),pid=pid)

    def test_ipv6_wildcard_is_not_assumed_to_serve_ipv4(self):
        from redvector_ollama_storage import listener_pids
        with patch("psutil.net_connections",return_value=[self.listener("::",11),self.listener("127.0.0.1",22)]):
            self.assertEqual(listener_pids("127.0.0.1",11434),{22})

    def test_ipv4_mapped_concrete_listener_is_recognized(self):
        from redvector_ollama_storage import listener_pids
        with patch("psutil.net_connections",return_value=[self.listener("::ffff:127.0.0.1",33)]):
            self.assertEqual(listener_pids("127.0.0.1",11434),{33})
