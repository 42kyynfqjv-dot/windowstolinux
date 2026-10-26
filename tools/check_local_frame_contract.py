"""Design evidence for the exact unchanged compiler artifact, not translation."""
import hashlib
import json
from pathlib import Path
import struct
import sys
from local_frame_model import Model
root=Path(sys.argv[1])
b=(root/'held_structure.exe').read_bytes()
reports=json.loads((root/'heldout-x86.json').read_text())
r=next(x for x in reports if x['kind']=='held_structure')
assert hashlib.sha256(b).hexdigest()==r['sha256'] and not r['conversion_accepted']
assert r['freeze_commit']=='cf042295303dccedb8506564f1e466ef9d353acd'
assert hashlib.sha256(Path('compiler/heldout/structure.c').read_bytes()).hexdigest()==r['source_sha256']
p=struct.unpack_from('<I',b,60)[0];o=p+24;s=o+struct.unpack_from('<H',b,p+20)[0]
assert struct.unpack_from('<I',b,o+16)[0]==0x1000
assert struct.unpack_from('<IIII',b,s+8)==(29,0x1000,512,512)
# Independently recorded dumpbin instruction bytes; never edit the input to match.
assert b[512:541]==bytes.fromhex('83ec08 c7042407000000 c744240405000000 8b442404 030424 83c408 c3')
assert json.loads((root/'held_structure-baseline.json').read_text())==dict(stdout_hex='',stderr_hex='',exit=12,files={})
m=Model();m.allocate8();m.store(0,7);m.store(4,5);m.load4();m.add0();m.cleanup8()
assert m.ret()==12 and m.steps==7
assert hashlib.sha256((root/'held_structure.exe').read_bytes()).hexdigest()==r['sha256']
print('LOCAL_FRAME_DESIGN_ONLY',r['sha256'],'literal_trace_exit=12 production_conversion=rejected')
