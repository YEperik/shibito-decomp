"""Self-contained tests: build a tiny synthetic MIPS ELF, no game data needed."""
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import elfkit      # noqa: E402
import ghidrakit   # noqa: E402

BASE = 0x100000
CODE = [
    0x24030020, 0x0000000C, 0x03E00008, 0x00000000,   # li v1,0x20 ; syscall ; jr ra ; nop
    0x0C000000 | (BASE >> 2), 0, 0x0C000000 | (BASE >> 2), 0,  # 2x jal BASE
    0x27BDFFE0, 0x03E00008, 0, 0,                      # prologue + return
]


def make_elf(path: Path):
    code = struct.pack(f"<{len(CODE)}I", *CODE)
    ident = b"\x7fELF\x01\x01\x01" + b"\0" * 9
    hdr = ident + struct.pack("<HHIIIIIHHHHHH", 2, 8, 1, BASE, 52, 0, 0, 52, 32, 1, 40, 0, 0)
    ph = struct.pack("<IIIIIIII", 1, 0x80, BASE, BASE, len(code), len(code) + 64, 7, 0x80)
    path.write_bytes(hdr + ph + b"\0" * (0x80 - 52 - 32) + code)


class ElfTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.elf_path = Path(self.tmp.name) / "t.elf"
        make_elf(self.elf_path)
        self.elf = elfkit.parse_elf(self.elf_path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_header(self):
        self.assertEqual(self.elf.entry, BASE)
        self.assertEqual(self.elf.code.filesz, len(CODE) * 4)

    def test_syscall_wrapper(self):
        s = elfkit.scan_syscalls(self.elf)
        self.assertEqual(len(s), 1)
        self.assertTrue(s[0]["wrapper"])
        self.assertEqual(s[0]["name"], "CreateThread")

    def test_calls(self):
        self.assertEqual(elfkit.scan_calls(self.elf)[BASE], 2)

    def test_prologue(self):
        self.assertIn(BASE + 8 * 4, elfkit.scan_prologues(self.elf))


class GhidraTests(unittest.TestCase):
    SRC = (
        "int g;\n\n"
        "void FUN_00100230(void)\n\n{\n  return;\n}\n\n\n"
        "void CreateThread(void)\n\n{\n  syscall(0x20);\n  return;\n}\n\n\n"
        "undefined4 * FUN_00100400(int param_1,\n                         uint param_2)\n\n{\n  return 0;\n}\n"
    )

    def test_parse(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.c"
            p.write_text(self.SRC)
            f = ghidrakit.parse_functions(p)
        self.assertEqual([x.name for x in f], ["FUN_00100230", "CreateThread", "FUN_00100400"])
        self.assertEqual(f[0].addr, 0x100230)
        self.assertEqual(f[1].syscall, 0x20)
        self.assertEqual(f[1].kind, "sdk")
        self.assertTrue(f[2].stub_safe)


class GuardTests(unittest.TestCase):
    def run_guard(self, d):
        return subprocess.run([sys.executable, str(ROOT / "tools" / "shibito.py"),
                               "check-public", d], capture_output=True, text=True).returncode

    def test_blocks_elf_and_passes_clean(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "ok.md").write_text("hello")
            self.assertEqual(self.run_guard(d), 0)
            make_elf(Path(d) / "leak.dat")
            self.assertEqual(self.run_guard(d), 1)

    def test_blocks_decompiler_output(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.c").write_text("void f(void){ int iVar1; }")
            self.assertEqual(self.run_guard(d), 1)


if __name__ == "__main__":
    unittest.main()
