#!/usr/bin/env python3
"""Dev tool: locate subs.db decryption in the Happ binary, take 2.

OpenSSL cipher objects reference the name string by pointer from a struct:
1. scan .data/.rodata for a pointer to the "aes-128-gcm" string -> cipher struct
2. find lea referencing the struct -> EVP_aes_128_gcm thunk
3. find call sites of the thunk -> decryption users
4. dump strings referenced near those users (key material candidates)

Run: .venv/bin/python scripts/happ-re-aes.py
"""

import struct

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from elftools.elf.elffile import ELFFile

BIN = "/opt/happ/bin/Happ"


def find_string_va(elf, needle: bytes) -> int:
    for sec in elf.iter_sections():
        if sec.name not in (".rodata", ".data.rel.ro", ".data"):
            continue
        idx = sec.data().find(needle)
        if idx >= 0:
            return sec["sh_addr"] + idx
    return -1


def scan_pointers(sec, target: int) -> list[int]:
    """VAs in section whose 8-byte content == target."""
    data = sec.data()
    needle = struct.pack("<Q", target)
    out, pos = [], 0
    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            return out
        out.append(sec["sh_addr"] + pos)
        pos += 1


def main() -> None:
    f = open(BIN, "rb")
    elf = ELFFile(f)
    text = elf.get_section_by_name(".text")
    text_addr, text_data = text["sh_addr"], text.data()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    name_va = find_string_va(elf, b"aes-128-gcm\x00")
    print(f'"aes-128-gcm" string VA: {hex(name_va)}')

    # 1) pointer to the name string = inside the EVP_CIPHER struct
    struct_holders = []
    for sec in elf.iter_sections():
        if sec.name in (".data", ".data.rel.ro", ".rodata", ".bss"):
            struct_holders += scan_pointers(sec, name_va)
    print(f"pointers to the name ({len(struct_holders)}): {[hex(a) for a in struct_holders[:8]]}")

    # struct address: name is the first field of EVP_CIPHER
    struct_vas = [a for a in struct_holders]

    # 2) lea references to the struct -> EVP_aes_128_gcm thunk
    thunks = []
    for insn in md.disasm(text_data, text_addr):
        if insn.mnemonic != "lea":
            continue
        va = insn.address + insn.size + insn.operands[1].mem.disp
        if va in struct_vas:
            thunks.append(insn.address)
    print(f"EVP thunks: {[hex(a) for a in thunks]}")

    # 3) call sites of the thunks
    callers = set()
    for insn in md.disasm(text_data, text_addr):
        if insn.mnemonic == "call" and insn.operands[0].imm in thunks:
            callers.add(insn.address)
    print(f"callers: {[hex(a) for a in sorted(callers)]}")

    # 4) dump rodata strings referenced around callers
    rodata = elf.get_section_by_name(".rodata")
    rdata, raddr = rodata.data(), rodata["sh_addr"]

    def rodata_at(va: int) -> bytes:
        off = va - raddr
        if 0 <= off < len(rdata):
            end = rdata.find(b"\x00", off)
            return rdata[off : off + min(end - off, 96) if end > 0 else off + 96]
        return b""

    for caller in sorted(callers):
        print(f"\n=== caller {hex(caller)} (window -0x500..+0x300)")
        start = caller - 0x500
        try:
            insns = md.disasm(text_data[start - text_addr :], start)
            for insn in insns:
                if insn.address > caller + 0x300:
                    break
                if insn.mnemonic == "lea" and insn.operands[1].mem.disp:
                    va = insn.address + insn.size + insn.operands[1].mem.disp
                    if raddr <= va < raddr + len(rdata):
                        s = rodata_at(va)
                        if s and all(32 <= c < 127 for c in s):
                            print(f"  {hex(insn.address)}: -> {s.decode(errors='replace')!r}")
        except Exception as e:
            print("  disasm error:", e)
    f.close()


if __name__ == "__main__":
    main()
