"""Unchanged loop artifact model evidence, not native translation."""
import hashlib,json,sys
from pathlib import Path
from permissioned_intake import Image as Envelope
from image_read_model import Image,Section,Relocation
from finite_loop_model import prove,eligible
root=Path(sys.argv[1]);blob=(root/'held_loop.exe').read_bytes()
r=next(x for x in json.loads((root/'heldout-x86.json').read_text()) if x['kind']=='held_loop')
assert hashlib.sha256(blob).hexdigest()==r['sha256'] and r['conversion_accepted']
assert r['freeze_commit']=='cf042295303dccedb8506564f1e466ef9d353acd'
assert hashlib.sha256(Path('compiler/heldout/loop.c').read_bytes()).hexdigest()==r['source_sha256']
assert json.loads((root/'held_loop-baseline.json').read_text())==dict(stdout_hex='',stderr_hex='',exit=10,files={})
e=Envelope(blob)
assert e.metadata_closed and set(e.dirs)=={5,6} and e.entry==0x1000 and e.base==0x400000
code,_,data,reloc=e.sections
assert blob[code.raw:code.raw+code.virtual]==bytes.fromhex('33c0 33c9 390500304000 760f 0f1f4000 03c1 41 3b0d00304000 72f5 c3')
assert blob[data.raw:data.raw+data.virtual]==b'\x05\0\0\0'
assert blob[reloc.raw:reloc.raw+reloc.virtual]==bytes.fromhex('00100000 0c000000 0630 1530')
assert [(p['site'],p['rva']) for p in e.pointers]==[(0x1006,0x3000),(0x1015,0x3000)]
m=Image(e.base,e.extent,e.entry,[Section(s.rva,s.virtual,s.raw,blob[s.raw:s.raw+s.size],'metadata' if s.role=='discardable-metadata' else s.role) for s in e.sections],[Relocation(p['site']) for p in e.pointers],[(a,b-a) for a,b,_ in e.metadata],e.dirs)
p=prove(m);result=eligible(p)
assert (p.bound,p.steps,p.result)==(5,26,10)
assert result['headers']==[(0,0,5),(1,0,4),(2,1,3),(3,3,2),(4,6,1)] and not result['emission_allowed']
assert hashlib.sha256((root/'held_loop.exe').read_bytes()).hexdigest()==r['sha256']
print('FINITE_LOOP_CONTRACT',r['sha256'],'rank=N-i bound=5 steps=26 model_exit=10 production_conversion=accepted native_execution=separate_check')
