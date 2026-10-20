"""Create short-lived, private test certificates; never prints private key data."""
from pathlib import Path
import os
import subprocess
import sys
import zlib

openssl, directory = sys.argv[1:]
root = Path(directory).resolve()
root.mkdir(parents=True, exist_ok=True)
if os.name != "nt":
    root.chmod(0o700)

def run(*args):
    result = subprocess.run([openssl, *map(str, args)], cwd=root, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError("OpenSSL fixture creation failed: " + result.stderr[-2000:])

ready = root / "ready"
valid = ready.exists() and ready.read_text() == "iiNetwork-TLS-v1\n"
for filename in ("ca.pem", "server.pem", "client.pem", "untrusted.pem"):
    if not valid:
        break
    valid = subprocess.run([openssl, "x509", "-in", str(root / filename), "-checkend", "3600", "-noout"], capture_output=True).returncode == 0
if not valid:
    for name in ("ca", "untrusted"):
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-sha256", "-subj", "/CN=iiNetwork " + name,
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout", name + ".key", "-out", name + ".pem")
    for name, usage in (("server", "serverAuth"), ("client", "clientAuth")):
        run("req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", "/CN=" + ("localhost" if name == "server" else "iiNetwork client"),
            "-keyout", name + ".key", "-out", name + ".csr")
        extension = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=" + usage + "\n"
        if name == "server":
            extension += "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n"
        (root / (name + ".ext")).write_text(extension)
        run("x509", "-req", "-in", name + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "2", "-sha256",
            "-extfile", name + ".ext", "-out", name + ".pem")
    ready.write_text("iiNetwork-TLS-v1\n")
for key in root.glob("*.key"):
    if os.name != "nt":
        key.chmod(0o600)
compressor = zlib.compressobj(wbits=31)
(root / "gzip.bin").write_bytes(compressor.compress(b"compressed response") + compressor.flush())
print("Local CA/server/client fixtures ready")
