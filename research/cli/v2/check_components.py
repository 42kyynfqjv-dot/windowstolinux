"""Bound frozen originals to structural graph and native COMPONENT comparisons.
No PE translation or emission authority; compiler binaries remain untouched.
"""
import hashlib,json,os,struct,subprocess,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve();windows='--windows' in sys.argv
src=Path(__file__).resolve().parent;repo=src.parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(cmd,**kw):return subprocess.run(cmd,capture_output=True,timeout=30,**kw)
def number(b,at):return struct.unpack_from('<I',b,at)[0]
report=json.loads((root/'report.json').read_text());cases=json.loads((src/'cases.json').read_text())
manifest=json.loads((src/'frozen.json').read_text())
for name,h in manifest['sha256'].items():assert sha(src/name)==h,(name,'freeze')
assert report['manifest']==manifest and len(report['programs'])==2
suffix='.exe' if windows else ''
graph=repo/'target/debug/examples'/('stream_graph'+suffix)
results=[]
for row in report['programs']:
 stem='uppercase_v2_'+row['config'];pe=root/(stem+'.exe');b=pe.read_bytes();assert sha(pe)==row['pe_sha256']
 for kind in ['observations','pipe_observations']:
  assert row[kind]==[{k:v[k] for k in ['name','exit','stdout_hex','stderr_hex']} for v in cases]
 # Trusted compiler evidence extraction; not a substitute for production PE intake.
 at=number(b,60);o=at+24;table=o+struct.unpack_from('<H',b,at+20)[0];code=[]
 for i in range(struct.unpack_from('<H',b,at+6)[0]):
  s=table+40*i
  if number(b,s+36)==0x60000020:
   size=min(number(b,s+8),number(b,s+16));raw=number(b,s+20);assert raw+size<=len(b)
   code.append((number(b,s+12),b[raw:raw+size]))
 assert len(code)==1
 origin,data=code[0];path=root/(stem+'.code');path.write_bytes(data)
 p=run([str(graph),str(path),str(origin),str(number(b,o+16))]);assert p.returncode==0,p.stderr
 assert b'emission_eligible=false' in p.stdout
 graph_path=root/(stem+'-graph.txt')
 if windows:graph_path.write_bytes(p.stdout.replace(b'\r\n',b'\n'))
 else:assert graph_path.read_bytes()==p.stdout
 assert sha(pe)==row['pe_sha256']
 results.append(dict(config=row['config'],pe_sha256=sha(pe),graph_sha256=sha(graph_path),summary=p.stdout.splitlines()[0].decode()))
if not windows:
 core=repo/'target/debug/examples/stream_core';observations=[]
 for kind in ['file','pipe']:
  for v in cases:
   b=bytes.fromhex(v['input_hex']);path=root/'component-input.bin';path.write_bytes(b)
   p=run([str(core),kind]+([str(path)] if kind=='file' else []),**({'input':b} if kind=='pipe' else {}))
   actual=dict(name=v['name'],exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex())
   assert actual=={k:v[k] for k in actual},actual
   observations.append(dict(kind=kind,**actual))
 path=root/'component-input.bin';path.write_bytes(b'a')
 for mode,expected in [('read-failure',11),('write-failure',12)]:
  p=run([str(core),mode,str(path)]);assert (p.returncode,p.stdout,p.stderr)==(expected,b'',b'');assert path.read_bytes()==b'a'
  observations.append(dict(kind=mode,exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex()))
 (root/'component-native.json').write_text(json.dumps(dict(kind='authored component consumer, NOT PE translation',graphs=results,observations=observations),indent=2)+'\n')
 print('28 file/pipe + 2 failure component cases match frozen expectations and both originals; zero CLI PE translations')
print(json.dumps(results,indent=2))
