"""Bounded static evidence from a previously measured artifact; no execution proof."""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys


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
        window = lines[addresses[target]:addresses[target]+64]
        excerpts.append({'va': hex(target), 'lines': window})
        for line in window:
            m = re.search(r'\b(?:call|jmp)\s+([0-9a-fA-F]{8})\b', line)
            if m:
                pending.append(int(m[1], 16))
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
    (root/'startup-inventory.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
