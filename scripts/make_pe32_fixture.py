"""Build independently authored, import-free PE32 entry-return fixtures.

These are narrow process exit-status experiments, not an application corpus.
"""

import sys
from pathlib import Path


def put(data: bytearray, offset: int, value: int, width: int) -> None:
    data[offset : offset + width] = value.to_bytes(width, "little")


def mov_eax(value: int) -> bytes:
    return bytes([0xB8]) + value.to_bytes(4, "little")


def add_eax(value: int) -> bytes:
    return bytes([0x05]) + value.to_bytes(4, "little")


CASES = {
    "sum12": mov_eax(7) + add_eax(5) + b"\xC3",
    "wrap2": mov_eax(0xFFFFFFFF) + add_eax(3) + b"\xC3",
    "xor9": b"\x31\xC0" + add_eax(9) + b"\xC3",
    "zero": mov_eax(0) + b"\xC3",
    "max255": mov_eax(255) + b"\xC3",
    "out_of_range": mov_eax(256) + b"\xC3",
}


def branch_case(prefix: bytes, opcode: int) -> bytes:
    return prefix + bytes([opcode, 6]) + mov_eax(11) + b"\xC3" + mov_eax(22) + b"\xC3"


for name, prefix, opcode in [
    ("jc_taken", mov_eax(0xFFFFFFFF) + add_eax(1), 0x72),
    ("jc_clear", mov_eax(1) + add_eax(1), 0x72),
    ("jnc_taken", mov_eax(1) + add_eax(1), 0x73),
    ("jnc_clear", mov_eax(0xFFFFFFFF) + add_eax(1), 0x73),
    ("jz_taken", mov_eax(0xFFFFFFFF) + add_eax(1), 0x74),
    ("jz_clear", mov_eax(1) + add_eax(1), 0x74),
    ("jnz_taken", mov_eax(1) + add_eax(1), 0x75),
    ("jnz_clear", mov_eax(0xFFFFFFFF) + add_eax(1), 0x75),
    ("mov_flags", b"\x31\xC0" + mov_eax(7), 0x74),
    ("xor_carry", b"\x31\xC0", 0x72),
]:
    CASES[name] = branch_case(prefix, opcode)


def build(case: str) -> bytes:
    if case not in CASES:
        raise ValueError(f"unknown fixture case: {case}")
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    put(data, 0x3C, 0x80, 4)
    data[0x80:0x84] = b"PE\0\0"

    coff = 0x84
    put(data, coff + 0, 0x14C, 2)  # x86
    put(data, coff + 2, 1, 2)  # one section
    put(data, coff + 16, 0xE0, 2)  # PE32 optional header size
    put(data, coff + 18, 0x0102, 2)  # executable, 32-bit

    optional = 0x98
    put(data, optional + 0, 0x10B, 2)  # PE32
    put(data, optional + 4, 0x200, 4)  # SizeOfCode
    put(data, optional + 16, 0x1000, 4)  # AddressOfEntryPoint
    put(data, optional + 20, 0x1000, 4)  # BaseOfCode
    put(data, optional + 24, 0x1000, 4)  # BaseOfData
    put(data, optional + 28, 0x400000, 4)  # ImageBase
    put(data, optional + 32, 0x1000, 4)  # SectionAlignment
    put(data, optional + 36, 0x200, 4)  # FileAlignment
    put(data, optional + 40, 4, 2)  # MajorOperatingSystemVersion
    put(data, optional + 48, 4, 2)  # MajorSubsystemVersion
    put(data, optional + 56, 0x2000, 4)  # SizeOfImage
    put(data, optional + 60, 0x200, 4)  # SizeOfHeaders
    put(data, optional + 68, 3, 2)  # console subsystem
    put(data, optional + 72, 0x100000, 4)  # stack reserve
    put(data, optional + 76, 0x1000, 4)  # stack commit
    put(data, optional + 80, 0x100000, 4)  # heap reserve
    put(data, optional + 84, 0x1000, 4)  # heap commit
    put(data, optional + 92, 16, 4)  # NumberOfRvaAndSizes

    section = 0x178
    data[section : section + 5] = b".text"
    put(data, section + 8, 0x100, 4)  # virtual size
    put(data, section + 12, 0x1000, 4)  # virtual address
    put(data, section + 16, 0x200, 4)  # raw size
    put(data, section + 20, 0x200, 4)  # raw offset
    put(data, section + 36, 0x60000020, 4)  # code, execute, read

    code = CASES[case]
    data[0x200 : 0x200 + len(code)] = code
    return bytes(data)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: make_pe32_fixture.py CASE OUTPUT.exe")
    Path(sys.argv[2]).write_bytes(build(sys.argv[1]))
