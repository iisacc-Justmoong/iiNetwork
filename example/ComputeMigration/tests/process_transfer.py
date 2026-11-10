"""Run the sender and receiver as separate processes over real loopback TCP."""
import select
import subprocess
import sys

server = subprocess.Popen([sys.argv[1], "--server"], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
try:
    ready, _, _ = select.select([server.stdout], [], [], 10)
    if not ready:
        raise RuntimeError("receiver did not announce its port")
    line = server.stdout.readline().strip()
    if not line.startswith("PORT "):
        raise RuntimeError(f"unexpected receiver announcement: {line}")
    client = subprocess.run([sys.argv[1], "--client", line.split()[1]],
                            capture_output=True, text=True, timeout=20)
    if client.returncode or "PROCESS_WORK_OK" not in client.stdout:
        raise RuntimeError(f"sender failed: {client.stdout} {client.stderr}")
    _, errors = server.communicate(timeout=10)
    if server.returncode:
        raise RuntimeError(f"receiver failed: {errors}")
    print("CROSS_PROCESS_WORK_OK")
finally:
    if server.poll() is None:
        server.kill()
        server.communicate()
