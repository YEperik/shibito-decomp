"""analyze - combine direct ELF scans with a Ghidra C export into one model."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import elfkit
import ghidrakit


@dataclass
class Row:
    addr: int
    name: str
    kind: str          # sdk | thunk | unnamed
    span: int
    callers: int
    syscall: int | None
    func: ghidrakit.Func


def _resolve(funcs, elf, wrappers, calls):
    """Give SDK-named functions and thunks an address.

    Ghidra's export is address-ordered, so each unresolved function must sit
    between its nearest resolved neighbours; the ELF scan supplies candidates.
    """
    by_num: dict[int, list[int]] = {}
    for w in wrappers:
        by_num.setdefault(w["number"], []).append(w["addr"])
    used: set[int] = set()
    known = [f.addr for f in funcs if f.addr]
    for idx, f in enumerate(funcs):
        if f.addr is not None:
            continue
        if f.name == "entry":
            f.addr = elf.entry
            used.add(f.addr)
            continue
        lo = next((g.addr for g in reversed(funcs[:idx]) if g.addr), 0)
        hi = next((g.addr for g in funcs[idx + 1:] if g.addr), 1 << 32)
        if f.syscall is not None:
            cands = [a for a in by_num.get(f.syscall, []) if lo < a < hi and a not in used]
        elif f.kind == "thunk":
            tgt = int(f.name[-8:], 16)
            word = 0x08000000 | ((tgt >> 2) & 0x03FFFFFF)
            cands = [pc for pc, w in elf.words()
                     if w == word and lo < pc < hi and pc not in used] if lo else []
        else:
            cands = []
        if cands:
            f.addr = cands[0]
            used.add(f.addr)
    return known


def build(elf_path, c_path):
    elf = elfkit.parse_elf(elf_path)
    funcs = ghidrakit.parse_functions(c_path)
    wrappers = [w for w in elfkit.scan_syscalls(elf) if w["wrapper"]]
    calls = elfkit.scan_calls(elf)
    _resolve(funcs, elf, wrappers, calls)

    placed = sorted((f for f in funcs if f.addr), key=lambda f: f.addr)
    addrs = [f.addr for f in placed]
    end = elf.code.vaddr + elf.code.filesz
    rows = []
    dup = {n for n, c in Counter(f.name for f in placed).items() if c > 1}
    for i, f in enumerate(placed):
        nxt = addrs[i + 1] if i + 1 < len(addrs) else end
        uname = f"{f.name}_{f.addr:08x}" if f.name in dup else f.name
        rows.append(Row(f.addr, uname, f.kind, nxt - f.addr,
                        calls.get(f.addr, 0), f.syscall, f))
    unplaced = [f for f in funcs if not f.addr]
    return {"elf": elf, "funcs": funcs, "rows": rows, "unplaced": unplaced,
            "wrappers": wrappers, "calls": calls}


def coverage(model):
    """How well do raw `jal` targets agree with the Ghidra function list?"""
    known = {r.addr for r in model["rows"]}
    targets = set(model["calls"])
    hit = len(targets & known)
    return {
        "jal_targets": len(targets),
        "targets_in_ghidra": hit,
        "ghidra_with_direct_callers": sum(1 for r in model["rows"] if r.callers),
        "ghidra_functions": len(model["rows"]),
    }


def pick_sample(model, n_unnamed=120, n_hot=25, stub_only=False, span_max=0x100):
    """Deterministic, spread-out sample: all SDK + hotspots + evenly spaced rest."""
    rows = model["rows"]
    chosen: dict[int, Row] = {}
    if not stub_only:
        for r in rows:
            if r.kind == "sdk":
                chosen[r.addr] = r
        for r in sorted(rows, key=lambda r: -r.callers)[:n_hot]:
            chosen[r.addr] = r
    pool = [r for r in rows if r.kind == "unnamed" and r.func.stub_safe
            and 8 <= r.span <= span_max and r.addr not in chosen]
    if pool and n_unnamed:
        step = max(1, len(pool) // n_unnamed)
        for r in pool[::step][:n_unnamed]:
            chosen[r.addr] = r
    return sorted(chosen.values(), key=lambda r: r.addr)
