"""Artifact store and typed options; no production artifact is executed."""
import hashlib
import pytest
import redvector_reviewed_artifacts as a

def test_staging_is_session_bound_and_verifies_digest(tmp_path):
    store=a.ArtifactStore(tmp_path)
    data=b"owned artifact"
    session="a"*32
    token=store.put(session,data,hashlib.sha256(data).hexdigest())
    assert store.read(token)==data
    with pytest.raises(a.ArtifactError):store.read(token.replace(session,"b"*32,1))
    with pytest.raises(a.ArtifactError):store.put(session,data,"0"*64)

def test_staged_mutation_is_refused(tmp_path):
    store=a.ArtifactStore(tmp_path);data=b"owned"
    token=store.put("a"*32,data,hashlib.sha256(data).hexdigest())
    path=store.path(token);path.write_bytes(b"other")
    with pytest.raises(a.ArtifactError):store.read(token)

def test_options_are_bounded_and_no_freeform_arguments():
    assert a.options("strings_extract",{"min_len":4})==["-a","-n","4","-t","x","/work/input"]
    with pytest.raises(a.ArtifactError):a.options("strings_extract",{"additional_args":"--anything"})
    with pytest.raises(a.ArtifactError):a.options("xxd_hexdump",{"length":"4097"})

@pytest.mark.parametrize("offset,length",[(0,1),(0,17),(7,17)])
def test_hex_display_matches_exact_requested_byte_window(tmp_path,monkeypatch,offset,length):
    data=bytes(range(64));store=a.ArtifactStore(tmp_path);monkeypatch.setattr(a,"_STORE",store)
    token=store.put("a"*32,data,hashlib.sha256(data).hexdigest())
    result=a.run_profile("xxd_hexdump",{"file_path":token,"offset":str(offset),"length":str(length)})
    assert result["success"]
    shown=bytes.fromhex("".join(line.split(": ",1)[1][:39].replace(" ","") for line in result["stdout"].splitlines()))
    assert shown==data[offset:offset+length]
    assert result["facts"]["returned_bytes"]==len(shown)

def test_untrusted_native_parser_is_isolated_to_its_capability(monkeypatch):
    from redvector_reviewed_profiles import ProfileError
    def untrusted(*args,**kwargs):raise ProfileError("Runtime must be administrator-owned")
    monkeypatch.setattr(a,"sandbox_command",untrusted)
    result=a.capabilities()
    assert result[a.PROFILE+":strings_extract"]["state"]=="Unsupported"
    assert "administrator-owned" in result[a.PROFILE+":strings_extract"]["detail"]
    assert result[a.PROFILE+":xxd_hexdump"]["state"]=="Ready"
