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
request_config = root / "request.cnf"
request_config.write_text("[req]\ndistinguished_name=subject\nprompt=no\n[subject]\nCN=iiNetwork fixture\n")

def run(*args):
    if args[0] == "req":
        # A relocated/static OpenSSL tool can have no default openssl.cnf.
        # Certificate requests use only this private fixture configuration.
        args = (args[0], "-config", str(request_config), *args[1:])
    result = subprocess.run([openssl, *map(str, args)], cwd=root, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError("OpenSSL fixture creation failed: " + result.stderr[-2000:])

ready = root / "ready"
valid = ready.exists() and ready.read_text() == "iiNetwork-TLS-v3\n" and (root / "expired.pem").exists()
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
    (root / "expired-index").write_text("")
    (root / "expired-serial").write_text("1000\n")
    (root / "expired-ca.cnf").write_text(
        "[ca]\ndefault_ca=local\n[local]\ndatabase=expired-index\nnew_certs_dir=.\n"
        "certificate=ca.pem\nprivate_key=ca.key\nserial=expired-serial\ndefault_md=sha256\n"
        "policy=subject\n[subject]\ncommonName=supplied\n")
    run("ca", "-batch", "-config", "expired-ca.cnf", "-in", "server.csr", "-startdate", "20000101000000Z",
        "-enddate", "20010101000000Z", "-extfile", "server.ext", "-notext", "-out", "expired.pem")
    ready.write_text("iiNetwork-TLS-v3\n")
for key in root.glob("*.key"):
    if os.name != "nt":
        key.chmod(0o600)
compressor = zlib.compressobj(wbits=31)
(root / "gzip.bin").write_bytes(compressor.compress(b"compressed response") + compressor.flush())
print("Local CA/server/client fixtures ready")
