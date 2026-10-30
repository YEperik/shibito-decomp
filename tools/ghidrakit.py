"""ghidrakit - parse a Ghidra "Export Program as C/C++" file. Standard library only.

Only signatures and metadata are read; function bodies are never copied out.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

ADDR_RE = re.compile(r"^FUN_([0-9a-fA-F]{8})$")
SYS_RE = re.compile(r"syscall\((0x[0-9a-fA-F]+|\d+)\)")

# types that compile with tools-owned stubs/include/types.h
SCALARS = {
    "void", "int", "uint", "long", "ulong", "short", "ushort", "char", "uchar",
    "bool", "byte", "word", "dword", "float", "double",
    "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
}


@dataclass
class Func:
    name: str
    ret: str
    params: str
    line: int
    body_lines: int
    addr: int | None = None
    syscall: int | None = None

    @property
    def kind(self) -> str:
        if self.name == "entry":
            return "entry"
        if self.name.startswith("thunk_"):
            return "thunk"
        if self.name.startswith("FUN_"):
            return "unnamed"
        return "sdk"

    @property
    def signature(self) -> str:
        return f"{self.ret} {self.name}({self.params})"

    @property
    def stub_safe(self) -> bool:
        if "(" in self.ret or "(" in self.params or "[" in self.params:
            return False
        toks = re.findall(r"[A-Za-z_]\w*", self.ret + " " + self.params)
        return all(t in SCALARS or t.startswith("param_") or t.startswith("unk")
                   for t in toks)


def _split_head(head: str):
    m = re.match(r"^(?P<ret>.*?[\s\*])(?P<name>[A-Za-z_]\w*)\((?P<params>.*)\)$", head, re.S)
    if not m:
        return None
    ret = m.group("ret").strip()
    stars = len(m.group("ret")) - len(m.group("ret").rstrip("*"))
    return ret, m.group("name"), m.group("params").strip(), stars


def parse_functions(c_path: str | Path) -> list[Func]:
    lines = Path(c_path).read_text(encoding="latin1").splitlines()
    funcs: list[Func] = []
    i, n = 0, len(lines)
    while i < n:
        if lines[i] == "{" and i > 0:
            # walk back to the signature (non-blank lines above, skipping one blank)
            j = i - 1
            while j >= 0 and not lines[j].strip():
                j -= 1
            end = j
            while j > 0 and lines[j - 1].strip():
                j -= 1
            head = " ".join(x.strip() for x in lines[j:end + 1])
            k = i + 1
            while k < n and lines[k] != "}":
                k += 1
            sp = _split_head(head) if "(" in head and not head.endswith(";") else None
            if sp:
                ret, name, params, stars = sp
                ret = ret + (" " + "*" * stars if stars else "")
                body = lines[i + 1:k]
                f = Func(name, ret.strip(), params, j + 1, len(body))
                m = ADDR_RE.search(name)
                if m:
                    f.addr = int(m.group(1), 16)
                if len(body) <= 6:
                    s = SYS_RE.search("\n".join(body))
                    if s:
                        v = int(s.group(1), 0)
                        f.syscall = v - (1 << 64) if v >= 1 << 63 else v
                funcs.append(f)
            i = k
        i += 1
    return funcs
