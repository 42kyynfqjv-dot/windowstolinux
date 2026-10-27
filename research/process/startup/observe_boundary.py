"""Feed unchanged original slices to the real production graph decoder.

Never execute extracted code. Success is structural only, not API binding,
ownership proof, CFG closure, emission eligibility or a translated pair.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from inventory import mapped_bytes

PIN = 'ce252fb1eddd05c3ea6acd73871995b1badd32446d76c6df07abaf8fa44fd22f'
# Independently selected from byte-checked original disassembly, not decoder output.
CASES = [('filter_callback',0x47cfc0,23,None),
         ('nonlocal_transfer',0x47cff7,2,'unsupported instruction Jmp'),
         ('thread_stack_validation',0x47cceb,7,'prefix'),
         ('floating_point_state',0x4f4168,4,'unsupported instruction Stmxcsr')]

def main(root, decoder):
    data = (root/'rcedit.exe').read_bytes()
    if hashlib.sha256(data).hexdigest() != PIN:
        raise ValueError('original artifact identity mismatch')
    rows = []
    report = dict(kind='original byte slices through production graph decoder; no execution',
                  pe_sha256=PIN, translated_pairs=0, observations=rows)
    for name, address, size, rejection in CASES:
        raw = mapped_bytes(data,address,size)
        path = root/(name+'.slice')
        path.write_bytes(raw)
        result = subprocess.run([str(decoder), str(path),str(address),str(address)],
                                capture_output=True, timeout=10)
        stdout, stderr = result.stdout.decode(), result.stderr.decode()
        rows.append(dict(name=name, address=hex(address), size=size,
                         slice_sha256=hashlib.sha256(raw).hexdigest(),
                         exit=result.returncode, stdout=stdout, stderr=stderr,
                         emission_allowed=False))
        (root/'execution-boundary.json').write_text(json.dumps(report,indent=2)+'\n')
        if rejection is None:
            if result.returncode != 0 or 'emission_eligible=false' not in stdout:
                raise ValueError('expected structural-only callback graph')
            # CALL ECX at +16 has only ordinary fallthrough +18. This is the
            # concrete shape being measured, not a claim that it is sufficient.
            if 'successors: [4706258]' not in stdout: # 0x47cfd2
                raise ValueError('callback successor changed; re-review boundary')
        elif result.returncode != 1 or rejection not in stderr:
            raise ValueError('expected explicit unsupported boundary')
    print(json.dumps(report,indent=2))

if __name__ == '__main__': main(Path(sys.argv[1]), Path(sys.argv[2]).resolve())
