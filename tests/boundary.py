"""Enforce the native SDK boundary and public dependency direction."""
from pathlib import Path
import re
import sys

root = Path(sys.argv[1]).resolve()
errors = []
for directory in ("src",):
    for path in sorted((root / directory).rglob("*")):
        if path.suffix not in (".h", ".cpp"):
            continue
        text = path.read_text()
        if re.search(r'#\s*include\s*[<"](?:Qt|Q[A-Z])', text):
            errors.append(f"{path.relative_to(root)}: Qt dependency")
        if path.name in ("Layers.h", "Layers.cpp", "Address.h", "Address.cpp", "ByteStream.h", "ByteStream.cpp",
                         "Transport.h", "Transport.cpp", "Local.h", "Local.cpp", "Security.h", "Security.cpp",
                         "Tls.h", "Tls.cpp", "Session.h", "Session.cpp", "Presentation.h", "Presentation.cpp"):
            if re.search(r'#\s*include\s*[<"]iiNetwork/(?:Application|Server|Stack|Peer)\.h', text):
                errors.append(f"{path.relative_to(root)}: lower layer imports application/orchestration")
        if path.name in ("Session.h", "Session.cpp"):
            if re.search(r'#\s*include\s*[<"]iiNetwork/Presentation\.h', text):
                errors.append(f"{path.relative_to(root)}: session imports presentation")
if re.search(r'find_package\s*\(\s*Qt', (root / "CMakeLists.txt").read_text(), re.I):
    errors.append("CMakeLists.txt: Qt package import")
if errors:
    raise SystemExit("\n".join(errors))
print("PASS native dependency and layer boundaries")
