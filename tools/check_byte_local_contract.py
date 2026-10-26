"""Exact unchanged-artifact/model evidence only; production buffer still rejects."""
import hashlib,json,struct,sys
from pathlib import Path
from byte_local_model import Model
root=Path(sys.argv[1]);b=(root/'held_buffer.exe').read_bytes()
r=next(x for x in json.loads((root/'heldout-x86.json').read_text()) if x['kind']=='held_buffer')
assert hashlib.sha256(b).hexdigest()==r['sha256'] and not r['conversion_accepted']
assert r['freeze_commit']=='cf042295303dccedb8506564f1e466ef9d353acd'
assert hashlib.sha256(Path('compiler/heldout/buffer.c').read_bytes()).hexdigest()==r['source_sha256']
p=struct.unpack_from('<I',b,60)[0];o=p+24;t=o+struct.unpack_from('<H',b,p+20)[0]
assert struct.unpack_from('<I',b,o+16)[0]==0x1000
assert struct.unpack_from('<IIII',b,t+8)==(34,0x1000,512,512)
assert b[512:546]==bytes.fromhex('51 c6042441 c644240142 0fb6442401 fec0 88442401 0fb64c2401 0fb60424 03c1 59 c3')
assert json.loads((root/'held_buffer-baseline.json').read_text())==dict(stdout_hex='',stderr_hex='',exit=132,files={})
m=Model()
for action in [('push_ecx',),('store',0,65),('store',1,66),('movzx','eax',1),('inc_al',),('store_al',1),('movzx','ecx',1),('movzx','eax',0),('add',),('pop_ecx',)]:m.step(*action)
assert m.step('ret')==132 and m.reg['ecx']==(65,67,None,None) and m.steps==11
print('BYTE_LOCAL_DESIGN_ONLY',r['sha256'],'literal_trace_exit=132 production_conversion=rejected')
