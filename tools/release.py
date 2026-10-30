#!/usr/bin/env python3
"""Build two archives into dist/.

  shibito-decomp_PUBLIC.zip   safe for GitHub (no game data) - guard-checked
  shibito-decomp_DEV_PRIVATE.zip  public tree + private/ dump + dev/ full dumps. NEVER publish.
"""
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
TOP = "shibito-decomp"
SKIP_DIRS = {".git", "dist", "dev", "__pycache__"}
SKIP_SUFFIX = {".pyc", ".gzf", ".iso", ".elf", ".bin", ".img", ".cue"}
DEV_README = """# DEV / PRIVATE - do not publish

Contains game data (private/) and full dumps (dev/). Keep offline.

- private/   your ELF, Ghidra C export, headers, .gzf project
- dev/       functions_full.csv, symbols_full.txt, stubs_all.c, strings_full.txt
             (regenerate: python tools/shibito.py report --full)

Publish only shibito-decomp_PUBLIC.zip. .gitignore already excludes private/ and dev/.
"""


def public_files():
    for p in sorted(ROOT.rglob("*")):
        rel = p.relative_to(ROOT)
        if not p.is_file() or set(rel.parts) & SKIP_DIRS or p.suffix in SKIP_SUFFIX:
            continue
        if rel.parts[0] == "private" and rel.name != "README.md":
            continue
        if p.name.startswith("SCUS_"):
            continue
        yield p, rel


def write_zip(path, entries):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for src, arc in entries:
            if isinstance(src, bytes):
                z.writestr(f"{TOP}/{arc}", src)
            else:
                z.write(src, f"{TOP}/{arc}")
    print(f"{path.name}: {path.stat().st_size / 1e6:.2f} MB")


def main():
    DIST.mkdir(exist_ok=True)
    pub = list(public_files())

    # guard: stage the public tree and scan it
    with tempfile.TemporaryDirectory() as d:
        for src, rel in pub:
            t = Path(d) / rel
            t.parent.mkdir(parents=True, exist_ok=True)
            t.write_bytes(src.read_bytes())
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "shibito.py"),
                            "check-public", d])
        if r.returncode:
            sys.exit("refusing to build: public tree failed the safety check")

    write_zip(DIST / "shibito-decomp_PUBLIC.zip", [(s, str(r)) for s, r in pub])

    dev = [(s, str(r)) for s, r in pub]
    for p in sorted((ROOT / "private").glob("*")):
        if p.name != "README.md":
            dev.append((p, f"private/{p.name}"))
    for p in sorted((ROOT / "dev").glob("*")):
        dev.append((p, f"dev/{p.name}"))
    dev.append((DEV_README.encode(), "dev/README.md"))
    write_zip(DIST / "shibito-decomp_DEV_PRIVATE.zip", dev)


if __name__ == "__main__":
    main()
