"""elfkit - minimal ELF32 / MIPS (R5900) helpers. Standard library only."""
from __future__ import annotations

import hashlib
import json
import re
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SYSCALL_TABLE = json.loads((ROOT / "config" / "syscalls.json").read_text())
SYSCALLS = {int(k): v for k, v in SYSCALL_TABLE["syscalls"].items()}

OP_JAL = 0x03
LI_V1 = 0x2403          # addiu $v1, $zero, imm
SYSCALL = 0x0000000C
JR_RA = 0x03E00008

SDK_LIBS = {  # string prefix -> SDK library
    "sceGs": "libgraph", "sceDma": "libdma", "sceSif": "libsif",
    "sceCd": "libcdvd", "sceMc": "libmc", "sceMpeg": "libmpeg",
    "sceIpu": "libipu", "sceSd": "libsd", "libpad": "libpad",
    "libipu": "libipu", "libcdvd": "libcdvd", "sceVif": "libvu0/vif",
}


@dataclass
class Segment:
    vaddr: int
    offset: int
    filesz: int
    memsz: int
    flags: int


@dataclass
class Elf:
    path: Path
    data: bytes
    entry: int
    machine: int
    flags: int
    segments: list[Segment]
    sections: list[dict] = field(default_factory=list)
    comment: list[str] = field(default_factory=list)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def code(self) -> Segment:
        """Main executable LOAD segment."""
        return next(s for s in self.segments if s.filesz)

    def words(self):
        """Yield (vaddr, word) for every aligned word of the code segment."""
        s = self.code
        blob = self.data[s.offset:s.offset + s.filesz]
        n = len(blob) // 4
        for i, w in enumerate(struct.unpack(f"<{n}I", blob[: n * 4])):
            yield s.vaddr + i * 4, w

    def word_at(self, vaddr: int) -> int | None:
        s = self.code
        if not s.vaddr <= vaddr < s.vaddr + s.filesz:
            return None
        o = s.offset + (vaddr - s.vaddr)
        return struct.unpack_from("<I", self.data, o)[0]

    def in_code(self, vaddr: int) -> bool:
        s = self.code
        return s.vaddr <= vaddr < s.vaddr + s.filesz and vaddr % 4 == 0


def parse_elf(path: str | Path) -> Elf:
    path = Path(path)
    d = path.read_bytes()
    if d[:4] != b"\x7fELF" or d[4] != 1 or d[5] != 1:
        raise ValueError("not a little-endian ELF32 file")
    (_, machine, _, entry, phoff, shoff, flags, _, phentsize, phnum,
     shentsize, shnum, shstrndx) = struct.unpack_from("<HHIIIIIHHHHHH", d, 16)
    segs = []
    for i in range(phnum):
        p_type, off, va, _, fsz, msz, fl, _ = struct.unpack_from(
            "<IIIIIIII", d, phoff + i * phentsize)
        if p_type == 1:
            segs.append(Segment(va, off, fsz, msz, fl))
    secs = []
    for i in range(shnum):
        n, t, fl, addr, off, sz = struct.unpack_from(
            "<IIIIII", d, shoff + i * shentsize)
        secs.append({"name_off": n, "type": t, "flags": fl,
                     "addr": addr, "offset": off, "size": sz})
    if shstrndx < len(secs):
        so = secs[shstrndx]["offset"]
        for s in secs:
            end = d.find(b"\0", so + s["name_off"])
            s["name"] = d[so + s["name_off"]:end].decode("ascii", "replace")
    comment = []
    for s in secs:
        if s.get("name") == ".comment":
            raw = d[s["offset"]:s["offset"] + s["size"]]
            comment = [x.decode("ascii", "replace") for x in raw.split(b"\0") if x]
    return Elf(path, d, entry, machine, flags, segs, secs, comment)


# --------------------------------------------------------------- syscalls
def scan_syscalls(elf: Elf) -> list[dict]:
    """Find `li $v1,N ; syscall` sequences. A trailing `jr $ra` marks a wrapper."""
    out = []
    prev = None
    for pc, w in elf.words():
        if w == SYSCALL and prev and (prev[1] >> 16) == LI_V1:
            n = prev[1] & 0xFFFF
            n = n - 0x10000 if n & 0x8000 else n
            nxt = elf.word_at(pc + 4)
            out.append({
                "addr": prev[0], "number": n,
                "name": SYSCALLS.get(n, f"syscall_{n}"),
                "known": n in SYSCALLS,
                "wrapper": nxt == JR_RA,
            })
        prev = (pc, w)
    return out


# ------------------------------------------------------------- call graph
def scan_calls(elf: Elf) -> Counter:
    """Count `jal` targets that land inside the code segment."""
    c: Counter = Counter()
    for pc, w in elf.words():
        if (w >> 26) == OP_JAL:
            t = ((pc + 4) & 0xF0000000) | ((w & 0x03FFFFFF) << 2)
            if elf.in_code(t):
                c[t] += 1
    return c


def scan_prologues(elf: Elf) -> set[int]:
    """Addresses starting with `addiu $sp,$sp,-N` (typical non-leaf prologue)."""
    return {pc for pc, w in elf.words()
            if (w >> 16) == 0x27BD and (w & 0x8000) and (w & 0xFFFF) != 0xFFFF}


# ---------------------------------------------------------------- strings
_STR = re.compile(rb"[\x20-\x7e]{6,}")


def scan_strings(elf: Elf):
    s = elf.code
    blob = elf.data[s.offset:s.offset + s.filesz]
    for m in _STR.finditer(blob):
        yield s.vaddr + m.start(), m.group().decode("ascii")


def is_sdk_string(text: str) -> bool:
    """Library-owned strings (error messages, lib markers) - safe to publish."""
    return bool(re.match(r"^(sce[A-Z]|lib[a-z]|PsIIlib|Libcdvd|Need to re-setup lib)", text)) \
        or "does not terminate" in text


def detect_sdk_libs(elf: Elf) -> dict[str, int]:
    found: Counter = Counter()
    for _, t in scan_strings(elf):
        if not is_sdk_string(t):
            continue
        for pre, lib in SDK_LIBS.items():
            if t.startswith(pre) or f" {pre}" in t:
                found[lib] += 1
                break
    return dict(found)
