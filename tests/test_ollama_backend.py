"""Process/HTTP boundaries are isolated; source and path validation are real."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import psutil

class CompatibleBackendTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.current=self.root/"new checkout"
        self.other=self.root/"another account"/"older checkout"
        for directory in (self.current,self.other):
            directory.mkdir(parents=True)
            (directory/"redvector_server.py").write_bytes(b"# trusted backend\n")
            (directory/"redvector_banner.py").write_bytes(b"# trusted banner\n")
        self.process=Mock()
        self.process.pid=4242
        self.process.create_time.return_value=10**12
        self.process.cmdline.return_value=[sys.executable,"-u",str(self.other/"redvector_server.py")]
        self.process.exe.return_value=sys.executable
        self.process.cwd.return_value=str(self.other)
        self.connection=SimpleNamespace(status=psutil.CONN_LISTEN,pid=4242,
            laddr=SimpleNamespace(ip="127.0.0.1",port=8888))
        self.process.net_connections.return_value=[self.connection]

    def inspect(self,connections=None,health=False):
        from redvector_ollama_backend import inspect_backend
        real_link=os.readlink
        def link(path):
            value=str(path)
            if "/ns/" in value:return value.rsplit("/",1)[1]+":[1]"
            if value.endswith("/root"):return "/"
            return real_link(path)
        with patch("psutil.net_connections",return_value=connections if connections is not None else [self.connection]),patch("psutil.Process",return_value=self.process),patch("os.readlink",side_effect=link):
            return inspect_backend(self.current,"127.0.0.1",8888,health=health)

    def test_other_checkout_with_trusted_identical_sources_is_reused(self):
        proof=self.inspect()
        self.assertEqual(proof.pid,4242)
        self.assertEqual(proof.script,self.other/"redvector_server.py")

    def test_current_checkout_is_reused(self):
        self.process.cmdline.return_value=[sys.executable,str(self.current/"redvector_server.py")]
        self.process.cwd.return_value=str(self.current)
        self.assertEqual(self.inspect().script,self.current/"redvector_server.py")

    def test_crlf_checkout_matches_equivalent_linux_source(self):
        (self.other/"redvector_server.py").write_bytes(b"# trusted backend\r\n")
        self.assertEqual(self.inspect().pid,4242)

    def test_changed_backend_cannot_use_matching_health_as_identity(self):
        from redvector_ollama_backend import BackendReuseError
        (self.other/"redvector_server.py").write_text("# unrelated or incompatible")
        with patch("redvector_ollama_backend.verify_api",side_effect=AssertionError("HTTP must not establish identity")):
            with self.assertRaisesRegex(BackendReuseError,"source"):
                self.inspect(health=True)

    def test_changed_local_import_is_rejected(self):
        from redvector_ollama_backend import BackendReuseError
        (self.other/"redvector_banner.py").write_text("# changed configuration")
        with self.assertRaisesRegex(BackendReuseError,"source"):
            self.inspect()

    def test_unreadable_process_fails_with_reason(self):
        from redvector_ollama_backend import BackendReuseError
        self.process.cwd.side_effect=psutil.AccessDenied(4242)
        with self.assertRaisesRegex(BackendReuseError,"identity.*unavailable"):
            self.inspect()

    def test_unrelated_command_is_rejected(self):
        from redvector_ollama_backend import BackendReuseError
        self.process.cmdline.return_value=[sys.executable,"-c","print('healthy')"]
        with self.assertRaisesRegex(BackendReuseError,"script"):
            self.inspect()

    def test_public_listener_is_not_reused(self):
        from redvector_ollama_backend import BackendReuseError
        self.connection.laddr.ip="0.0.0.0"
        with self.assertRaisesRegex(BackendReuseError,"loopback"):
            self.inspect()

    def test_unknown_socket_owner_is_rejected(self):
        from redvector_ollama_backend import BackendReuseError
        self.connection.pid=None
        with self.assertRaisesRegex(BackendReuseError,"owner"):
            self.inspect()

    def test_different_network_namespace_is_rejected(self):
        from redvector_ollama_backend import BackendReuseError,inspect_backend
        with patch("psutil.net_connections",return_value=[self.connection]),patch("psutil.Process",return_value=self.process),patch("os.readlink",side_effect=lambda p:str(p)):
            with self.assertRaisesRegex(BackendReuseError,"namespace"):
                inspect_backend(self.current,"127.0.0.1",8888,health=False)

    def test_file_modified_since_startup_is_unverifiable(self):
        from redvector_ollama_backend import BackendReuseError
        self.process.create_time.return_value=1
        with self.assertRaisesRegex(BackendReuseError,"startup"):
            self.inspect()

    def test_process_restart_during_verification_is_rejected(self):
        from redvector_ollama_backend import BackendReuseError
        self.process.create_time.side_effect=[10**12,10**12+1]
        with self.assertRaisesRegex(BackendReuseError,"changed"):
            self.inspect()

    def test_hidden_occupied_port_is_not_reported_free(self):
        from redvector_ollama_backend import BackendReuseError
        import socket
        with socket.socket() as listener:
            listener.bind(("127.0.0.1",0));listener.listen()
            from redvector_ollama_backend import inspect_backend
            with patch("psutil.net_connections",return_value=[]),self.assertRaisesRegex(BackendReuseError,"occupied"):
                inspect_backend(self.current,"127.0.0.1",listener.getsockname()[1])

    def test_matching_process_requires_healthy_compatible_api(self):
        from redvector_ollama_backend import BackendReuseError
        with patch("redvector_ollama_backend.verify_api",side_effect=BackendReuseError("Incompatible API version")):
            with self.assertRaisesRegex(BackendReuseError,"version"):self.inspect(health=True)

    def test_authentication_failures_are_not_silently_accepted(self):
        from redvector_ollama_backend import verify_api,BackendReuseError
        class Response:
            def __init__(self,status,data=None):self.status_code=status;self.data=data
            def json(self):return self.data
        for responses,reason in [
            ([Response(200,{"status":"healthy","version":"7.0.0"})],"version"),
            ([Response(200,{"status":"healthy","version":"8.0.0"}),Response(200)],"authentication"),
            ([Response(200,{"status":"healthy","version":"8.0.0"}),Response(401),Response(403)],"token")]:
            with self.subTest(reason=reason):
                session=Mock();session.get.side_effect=responses
                with patch("requests.Session",return_value=session),self.assertRaisesRegex(BackendReuseError,reason):
                    verify_api("127.0.0.1",8888)

    def test_valid_authentication_and_version_are_accepted(self):
        from redvector_ollama_backend import verify_api
        session=Mock()
        session.get.side_effect=[SimpleNamespace(status_code=200,json=lambda:{"status":"healthy","version":"8.0.0"}),
                                 SimpleNamespace(status_code=401),SimpleNamespace(status_code=200)]
        with patch("requests.Session",return_value=session):
            verify_api("127.0.0.1",8888)
        self.assertFalse(session.trust_env)

    def test_renamed_script_directory_cannot_substitute_another_installation(self):
        from redvector_ollama_backend import BackendReuseError
        moved=self.root/"moved original"
        self.other.rename(moved)
        self.process.cwd.return_value=str(moved)
        self.other.mkdir()
        for name in ("redvector_server.py","redvector_banner.py"):
            shutil.copyfile(self.current/name,self.other/name)
        with self.assertRaisesRegex(BackendReuseError,"working directory"):
            self.inspect()

    def test_retargeted_script_symlink_is_rejected(self):
        from redvector_ollama_backend import _script_path,BackendReuseError
        import stat
        path=self.other/"redvector_server.py"
        real=os.lstat
        def metadata(candidate,*args,**kwargs):
            if Path(candidate)==path:
                return SimpleNamespace(st_mode=stat.S_IFLNK,st_ctime=200,st_mtime=200)
            return real(candidate,*args,**kwargs)
        with patch("os.lstat",side_effect=metadata),self.assertRaisesRegex(BackendReuseError,"symlink"):
            _script_path(path,100)

    def test_retargeted_local_banner_symlink_is_rejected(self):
        from redvector_ollama_backend import BackendReuseError
        import stat
        real=os.lstat
        target=self.other/"redvector_banner.py"
        def metadata(candidate,*args,**kwargs):
            if Path(candidate)==target:
                return SimpleNamespace(st_mode=stat.S_IFLNK,st_ctime=10**12+1,st_mtime=10**12+1)
            return real(candidate,*args,**kwargs)
        with patch("os.lstat",side_effect=metadata),self.assertRaisesRegex(BackendReuseError,"symlink"):
            self.inspect()

    def test_startup_clock_sampling_delay_does_not_expand_trust_window(self):
        from redvector_ollama_backend import _source_start_limit
        import time
        moments=iter([0,10])
        fields="44 (python) "+" ".join(["S"]+["0"]*18+["100"])
        with patch("pathlib.Path.read_text",return_value=fields),patch("os.sysconf",create=True,return_value=100),patch.object(time,"CLOCK_BOOTTIME",7,create=True),patch("time.time",side_effect=lambda:1000+next(moments)),patch("time.clock_gettime",create=True,side_effect=lambda _:100+next(moments)):
            self.assertLessEqual(_source_start_limit(44,0),901.01)

    def test_pinned_existing_backend_cannot_trigger_replacement_startup(self):
        from redvector_ollama_backend import verify_pin,BackendReuseError
        with self.assertRaisesRegex(BackendReuseError,"disappeared"):
            verify_pin(None,"42:100.0")
        with self.assertRaisesRegex(BackendReuseError,"changed"):
            verify_pin(SimpleNamespace(pid=43,started=100.0),"42:100.0")
        self.assertIsNone(verify_pin(None,None))
