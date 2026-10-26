"""Independent small graph expectations, unrelated to CRT compiler output."""
import json,struct,subprocess,tempfile
from pathlib import Path
exe=Path('target/debug/examples/crt_graph').resolve()
def pe(code):
 b=bytearray(1024);b[:2]=b'MZ';struct.pack_into('<I',b,60,128);b[128:132]=b'PE\0\0'
 struct.pack_into('<H',b,134,1);struct.pack_into('<H',b,148,224);struct.pack_into('<H',b,152,0x10b)
 struct.pack_into('<I',b,168,4096);struct.pack_into('<I',b,180,0x400000)
 for off,v in [(8,len(code)),(12,4096),(16,512),(20,512),(36,0x60000020)]:struct.pack_into('<I',b,376+off,v)
 b[512:512+len(code)]=code;return b
cases=[('return','c3',1,[],[]),('cycle','ebfe',1,[],[]),('indirect','ffd0c3',2,[4096],[]),('outside','eb7f',2,[],[4225]),('trap','cc',1,[],[4096])]
with tempfile.TemporaryDirectory() as d:
 p=Path(d)/'a.exe'
 for name,code,count,indirect,gaps in cases:
  p.write_bytes(pe(bytes.fromhex(code)));r=subprocess.run([exe,p],capture_output=True,timeout=5,check=True);x=json.loads(r.stdout)
  assert (x['normal_flow_nodes'],x['indirect_sites'],x['unresolved_or_trap_sites'])==(count,indirect,gaps),name
  assert not x['complete_effect_proof'] and not x['emission_allowed']
 p.write_bytes(pe(bytes.fromhex('7401b801000000c3')))
 r=subprocess.run([exe,p],capture_output=True,timeout=5);assert r.returncode!=0 and b'overlapping instruction targets' in r.stderr
print('CRT_GRAPH_EXPECTATIONS 5 incomplete graphs; 1 overlapping-target rejection')
