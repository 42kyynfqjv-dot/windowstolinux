"""Frozen-artifact/model checks, separate from actual native conversion evidence.

Uses the existing independent permissioned-intake model for PE envelope extraction;
expected instructions, relocation fields, scalar contents and outcomes are literals.
No production module, decoder or original fixture generator supplies expectations.
"""
import hashlib
import json
import sys
from pathlib import Path
from permissioned_intake import Image as Envelope
from image_read_model import Image, Section, Relocation, Rejected

root = Path(sys.argv[1])
records = json.loads((root/'heldout-x86.json').read_text())
for name, expected_exit, expected_code, expected_data, expected_sites in [
    ('array',9,'8b0d04304000 a108304000 03c8 a100304000 03c1 c3',
     '02000000 03000000 04000000',[(0x1002,0x3004),(0x1007,0x3008),(0x100e,0x3000)]),
    ('loop',10,'33c0 33c9 390500304000 760f 0f1f4000 03c1 41 3b0d00304000 72f5 c3',
     '05000000',[(0x1006,0x3000),(0x1015,0x3000)])]:
    kind = 'held_'+name
    r = next(x for x in records if x['kind']==kind)
    blob = (root/(kind+'.exe')).read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    assert digest == r['sha256'] and r['conversion_accepted']==(name=='array')
    assert r['freeze_commit']=='cf042295303dccedb8506564f1e466ef9d353acd'
    assert hashlib.sha256(Path('compiler/heldout/'+name+'.c').read_bytes()).hexdigest()==r['source_sha256']
    assert json.loads((root/(kind+'-baseline.json')).read_text())==dict(stdout_hex='',stderr_hex='',exit=expected_exit,files={})
    envelope = Envelope(blob)
    assert envelope.base==0x400000 and envelope.entry==0x1000 and envelope.extent==0x5000
    assert envelope.metadata_closed and set(envelope.dirs)=={5,6}
    assert [(s.rva,s.role) for s in envelope.sections]==[(0x1000,'code'),(0x2000,'immutable'),(0x3000,'writable'),(0x4000,'discardable-metadata')]
    code, _, data, reloc = envelope.sections
    assert blob[code.raw:code.raw+code.virtual]==bytes.fromhex(expected_code)
    assert blob[data.raw:data.raw+data.virtual]==bytes.fromhex(expected_data)
    assert [(p['site'],p['rva']) for p in envelope.pointers]==expected_sites
    expected_reloc = ('00100000 10000000 0230 0730 0e30 0000' if name=='array'
                      else '00100000 0c000000 0630 1530')
    assert blob[reloc.raw:reloc.raw+reloc.virtual]==bytes.fromhex(expected_reloc)
    sections = [Section(s.rva,s.virtual,s.raw,blob[s.raw:s.raw+s.size],
                        'metadata' if s.role=='discardable-metadata' else s.role) for s in envelope.sections]
    model = Image(envelope.base,envelope.extent,envelope.entry,sections,
                  [Relocation(p['site']) for p in envelope.pointers],
                  [(a,b-a) for a,b,_ in envelope.metadata],envelope.dirs)
    if name=='array':
        result=model.prove()
        assert result['model_exit']==9 and not result['emission_allowed']
        assert result['reads']==[(0x1002,0x3004,3),(0x1007,0x3008,4),(0x100e,0x3000,2)]
        outcome='model_exit=9'
    else:
        # Explicit independently checked back edge +0x19 -> +0x10. No claim the
        # model reaches this diagnostic: its narrower language rejects XOR first.
        assert bytes.fromhex(expected_code)[25:27]==b'\x72\xf5'
        assert 27+int.from_bytes(b'\xf5','little',signed=True)==16
        try:
            model.prove()
        except Rejected as error:
            assert str(error)=='unsupported effect/form at +0x0'
        else:
            raise AssertionError('loop model must reject')
        outcome='model_rejected=unsupported-effect-at-entry backedge=+25-to-+16'
    assert hashlib.sha256((root/(kind+'.exe')).read_bytes()).hexdigest()==digest
    print('IMAGE_READ_CONTRACT',kind,digest,outcome,'production_conversion='+('accepted native_execution=separate_check' if name=='array' else 'rejected native_execution=not_added'))
