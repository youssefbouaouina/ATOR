import hashlib
import os
import sys

import requests

DEST = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "dfir-refs", "cti", "enterprise-attack", "enterprise-attack.json",
)
URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def update(dest=DEST):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    print(f"downloading ATT&CK enterprise JSON -> {dest}")
    with requests.get(URL, stream=True, timeout=120) as r:
        r.raise_for_status()
        tmp = dest + ".tmp"
        with open(tmp, "wb") as fh:
            for chunk in r.iter_content(chunk_size=1 << 20):
                fh.write(chunk)
    sha = hashlib.sha256()
    with open(tmp, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha.update(chunk)
    os.replace(tmp, dest)
    size_mb = os.path.getsize(dest) / (1024 * 1024)
    print(f"done: {size_mb:.1f} MB sha256={sha.hexdigest()}")
    return dest


if __name__ == "__main__":
    try:
        update(sys.argv[1] if len(sys.argv) > 1 else DEST)
    except Exception as exc:
        print(f"update failed: {exc}")
        sys.exit(1)
