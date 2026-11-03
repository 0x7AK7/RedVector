"""Install only the pinned reviewed Nuclei dependency into an explicit directory."""
import argparse,hashlib,io,os,platform,sys,urllib.request,zipfile
from pathlib import Path
VERSION="3.11.1"
ARCHIVE_SHA256="ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6"
BINARY_SHA256="c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251"

def install(directory):
    if not sys.platform.startswith("linux") or platform.machine() not in ("x86_64","amd64"):
        raise ValueError("Reviewed package currently supports Linux amd64 only.")
    directory=Path(directory).expanduser()
    if not directory.is_absolute() or directory.is_symlink():
        raise ValueError("Choose an absolute non-symlink dependency directory.")
    target=directory/"nuclei"
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest()!=BINARY_SHA256:
            raise ValueError("Existing destination differs; nothing was overwritten.")
        return target
    base="https://github.com/projectdiscovery/nuclei/releases/download/v"+VERSION+"/"
    archive="nuclei_"+VERSION+"_linux_amd64.zip"
    with urllib.request.urlopen(base+archive,timeout=120) as response:payload=response.read(60_000_001)
    if len(payload)>60_000_000 or hashlib.sha256(payload).hexdigest()!=ARCHIVE_SHA256:
        raise ValueError("Official archive checksum/size validation failed.")
    with zipfile.ZipFile(io.BytesIO(payload)) as package:binary=package.read("nuclei")
    if hashlib.sha256(binary).hexdigest()!=BINARY_SHA256:raise ValueError("Binary checksum mismatch.")
    directory.mkdir(parents=True,exist_ok=True)
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o700)
    with os.fdopen(fd,"wb") as stream:stream.write(binary)
    return target

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory",required=True,help="Private dependency directory; existing files are never replaced.")
    args=parser.parse_args()
    try:print("Installed verified dependency. Set REDVECTOR_NUCLEI_BIN to:",install(args.directory))
    except (OSError,ValueError,zipfile.BadZipFile) as exc:parser.exit(1,str(exc)+"\n")
