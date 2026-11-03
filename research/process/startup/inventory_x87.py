"""Read-only objdump inventory; linear decoding is not reachability or admission."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def inventory(binary):
    raw = binary.read_bytes()
    disassembly = subprocess.run(['objdump', '-d', '-Mintel', str(binary)],
                                 check=True, capture_output=True, text=True).stdout
    operations = []
    for line in disassembly.splitlines():
        fields = line.split('\t')
        # Objdump wraps long byte strings onto address/bytes-only lines. Those
        # are not additional instructions (e.g. an orphan "ff" is not x87).
        if len(fields) < 3 or not re.fullmatch(r'\s*[0-9a-f]+:', fields[0]):
            continue
        assembly = fields[2].strip().split(None, 1)
        if not assembly:
            continue
        mnemonic = assembly[0]
        if not (mnemonic.startswith('f') or mnemonic in ('ldmxcsr', 'stmxcsr', 'xsave', 'xrstor')):
            continue
        operations.append(dict(address='0x'+fields[0].strip()[:-1],
                               bytes=''.join(fields[1].split()), operation=mnemonic,
                               operands=assembly[1] if len(assembly) > 1 else ''))
    return dict(scope='linear executable-section objdump inventory; not all entries reachable from startup and no admission implied',
                pe_sha256=hashlib.sha256(raw).hexdigest(), operations=operations)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(inventory(args.binary), indent=2)+'\n')
