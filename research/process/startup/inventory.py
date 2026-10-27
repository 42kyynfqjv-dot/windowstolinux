"""Bounded static evidence from a previously measured artifact; no execution proof."""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys


def mapped_bytes(data, address, size):
    """Read only a uniquely file-backed range in the retained PE32 image."""
    pe = struct.unpack_from('<I', data, 60)[0]
    base = struct.unpack_from('<I', data, pe+52)[0]
    count = struct.unpack_from('<H', data, pe+6)[0]
    optional = struct.unpack_from('<H', data, pe+20)[0]
    start = pe+24+optional
    if not 0 < size <= 512 or not base <= address < address+size <= 2**32:
        raise ValueError('invalid requested range')
    rva = address-base
    matches = []
    for index in range(count):
        at = start+40*index
        virtual, va, raw_size, raw = struct.unpack_from('<IIII', data, at+8)
        if va <= rva and rva+size <= va+min(virtual, raw_size):
            offset = raw+rva-va
            if offset+size > len(data):
                raise ValueError('truncated file-backed range')
            matches.append(data[offset:offset+size])
    if len(matches) != 1:
        raise ValueError('missing or ambiguous file-backed range')
    return matches[0]


def focus(data, disassembly):
    """Pinned measurement addresses only; never converter dispatch or eligibility."""
    scope = mapped_bytes(data, 0x5191f8, 16)
    ranges = []
    requested = [(0x475ba0, 96), (0x47b290, 512), (0x475c79, 192), (0x47b250, 64)]
    dependencies = []
    # Actual call sites observed in the pinned handler. Resolve direct thunks
    # from bytes; no symbol name is used to manufacture a destination.
    for site in [0x47b2a9, 0x47b2cf, 0x47b312, 0x47b34f,
                 0x47b3b2, 0x47b3e8, 0x47d02b, 0x47cfe8]:
        call = mapped_bytes(data, site, 5)
        if call[0] != 0xe8:
            raise ValueError('pinned call-site bytes changed')
        target = (site+5+int.from_bytes(call[1:], 'little', signed=True)) % 2**32
        chain = [target]
        for _ in range(4):
            thunk = mapped_bytes(data, target, 5)
            if thunk[0] != 0xe9:
                break
            target = (target+5+int.from_bytes(thunk[1:], 'little', signed=True)) % 2**32
            if target in chain:
                raise ValueError('cyclic direct thunk')
            chain.append(target)
        else:
            raise ValueError('direct thunk budget exhausted')
        dependencies.append(dict(call_site=hex(site), chain=[hex(x) for x in chain]))
        requested.append((target,512))
    for start, size in requested:
        raw = mapped_bytes(data, start, size)
        rows = []
        for line in disassembly.splitlines():
            m = re.match(r'\s*([0-9a-fA-F]{8}): ((?:[0-9a-fA-F]{2} )+)', line)
            if not m or not start <= int(m[1],16) < start+size:
                continue
            address = int(m[1],16)
            instruction = bytes.fromhex(m[2])
            if mapped_bytes(data,address,len(instruction)) != instruction:
                raise ValueError('disassembly bytes differ from original PE')
            rows.append(line)
        ranges.append(dict(start=hex(start), size=size, bytes_hex=raw.hex(), lines=rows))
    return dict(kind='bounded original ranges; adjacent code may be included; not CFG closure',
                scope_va='0x5191f8', scope_header_hex=scope.hex(),
                scope_header_signed_words=list(struct.unpack('<iiii',scope)),
                ranges=ranges, direct_dependencies=dependencies, emission_allowed=False)


def inventory(data, disassembly, expected_hash):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_hash:
        raise ValueError('artifact identity mismatch')
    def u16(at):
        return struct.unpack_from('<H', data, at)[0]
    def u32(at):
        return struct.unpack_from('<I', data, at)[0]
    pe = u32(60)
    if data[:2] != b'MZ' or data[pe:pe+4] != b'PE\0\0' or u16(pe+4) != 0x14c or u16(pe+24) != 0x10b:
        raise ValueError('expected previously validated x86 PE32')
    entry, base = u32(pe+40), u32(pe+52)
    lines = disassembly.splitlines()
    addresses = {}
    for i, line in enumerate(lines):
        m = re.match(r'\s*([0-9A-Fa-f]{8}):', line)
        if m:
            address = int(m[1], 16)
            if address in addresses:
                raise ValueError('ambiguous disassembly address')
            addresses[address] = i
    pending, seen, excerpts = [base+entry], set(), []
    # This is an excerpt collector, NOT CFG recovery. Branch fallthrough, indirect
    # targets and code/data boundaries must be reviewed with the original bytes.
    while pending and len(seen) < 12:
        target = pending.pop(0)
        if target in seen:
            continue
        seen.add(target)
        if target not in addresses:
            excerpts.append({'va': hex(target), 'missing': True})
            continue
        window = []
        for line in lines[addresses[target]:addresses[target]+64]:
            window.append(line)
            m = re.match(r'\s*([0-9A-Fa-f]{8}): ((?:[0-9A-Fa-f]{2} )+)', line)
            if not m:
                continue
            raw = bytes.fromhex(m[2])
            va = int(m[1], 16)
            if len(raw) == 5 and raw[0] in (0xe8, 0xe9):
                pending.append((va+5+int.from_bytes(raw[1:], 'little', signed=True)) % 2**32)
            if raw[0] in (0xc3, 0xc2, 0xe9, 0xeb):
                break
        excerpts.append({'va': hex(target), 'lines': window})
    return dict(kind='static excerpts; no reachability or effect closure',
                pe_sha256=digest, entry_rva=hex(entry), preferred_base=hex(base),
                excerpts=excerpts, capped=bool(pending), emission_allowed=False)


if __name__ == '__main__':
    root = Path(sys.argv[1])
    report = json.loads((root/'report.json').read_text())
    result = inventory((root/'rcedit.exe').read_bytes(),
                       (root/'rcedit-disasm.txt').read_text(errors='replace'),
                       report['utility_sha256'])
    result['source_commit'] = report['source_commit']
    result['toolchain'] = report['toolchain']
    if report['utility_sha256'] != 'ce252fb1eddd05c3ea6acd73871995b1badd32446d76c6df07abaf8fa44fd22f':
        raise ValueError('focus addresses require the pinned original artifact')
    result['record_binding'] = focus((root/'rcedit.exe').read_bytes(),
                                     (root/'rcedit-disasm.txt').read_text(errors='replace'))
    (root/'startup-inventory.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
