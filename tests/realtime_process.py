"""Exercise real UDP across independent processes, with private pipe admission."""
from concurrent.futures import ThreadPoolExecutor
import queue
import subprocess
import sys
import threading


def check(binary):
    # Neither the private admission records nor child stdin are logged.
    server = subprocess.Popen([binary, "server"], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    messages = queue.Queue()
    reader = threading.Thread(target=lambda: [messages.put(line) for line in server.stdout], daemon=True)
    reader.start()
    try:
        admissions = [messages.get(timeout=30).strip() for _ in range(2)]
        fields = [record.split() for record in admissions]
        if any(len(record) != 5 for record in fields):
            raise AssertionError("Invalid private admission record")
        if fields[0][0] != fields[1][0] or fields[0][2] == fields[1][2]:
            raise AssertionError("Independent participants require one server and distinct IDs")

        def client(index):
            record = admissions[index] + " " + fields[1 - index][2] + "\n"
            process = subprocess.run([binary, "client"], input=record,
                                     capture_output=True, text=True, timeout=30)
            if process.returncode or process.stdout.strip() != "CLIENT_OK":
                raise AssertionError("Independent UDP participant failed")

        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(client, range(2)))
        if server.wait(timeout=10) or messages.get(timeout=5).strip() != "SERVER_OK":
            raise AssertionError("Independent UDP server did not settle both participants")
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
        reader.join(timeout=1)
        server.stdout.close()
        server.stderr.close()
    print("Native realtime relay passed across one server and two independent client processes")


if __name__ == "__main__":
    check(sys.argv[1])
