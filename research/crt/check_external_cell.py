"""Research Rust state effects; existing Windows records support zero-input alias cases only."""
import argparse,json,os,subprocess,tempfile,struct
from pathlib import Path
from check_commode import bind,sha,REPO,SOURCE

def run(cmd):
 p=subprocess.run([str(x) for x in cmd],capture_output=True,timeout=30)
 assert p.returncode==0 and not p.stderr,(p.returncode,p.stdout,p.stderr)
 return p.stdout

def main():
 ap=argparse.ArgumentParser();ap.add_argument('evidence',nargs='?',type=Path,default=Path(os.environ.get('RUNNER_TEMP','/tmp'))/'w2l-compiler-measurement');ap.add_argument('--compare',action='store_true');a=ap.parse_args();root=a.evidence.resolve();binding=bind(root);pe=root/'held_crt.exe'
 subprocess.run(['cargo','build','--locked','--example','crt_external_cell'],cwd=REPO,check=True)
 binary=REPO/'target/debug/examples'/('crt_external_cell.exe' if os.name=='nt' else 'crt_external_cell')
 blocked=json.loads(run([binary,pe]));assert not blocked['stored'] and blocked['cell_after'] is None
 results=[]
 for value in ['0','64','4294967295','unknown']:
  raw=run([binary,pe,'--isolated',value]);assert raw==run([binary,pe,'--isolated',value]);r=json.loads(raw)
  assert r['stored'] and r['cell_after']==0 and r['same_owner_alias'] and r['esi']==0
  assert r['ecx'] is None and r['edx'] is None and r['arithmetic_flags'] is None
  assert not r['accessor_effects_closed'] and not r['complete_startup_proof'] and not r['emission_allowed']
  results.append(dict(before=value,result=r,windows_observation_applies=value=='0'))
 for value in ['-1','0.5','4294967296','true']:
  p=subprocess.run([str(binary),str(pe),'--isolated',value],capture_output=True,timeout=30)
  assert p.returncode==1 and not p.stdout
 b=pe.read_bytes();o=struct.unpack_from('<I',b,60)[0]+24;t=o+224
 sections=[struct.unpack_from('<IIII',b,t+40*i+8) for i in range(4)]
 def raw(r):
  return next(p+r-v for size,v,n,p in sections if v<=r< v+min(size,n))
 mutations=[]
 with tempfile.TemporaryDirectory() as tmp:
  bad=Path(tmp)/'bad.exe'
  for start,n in [(0x1043,21),(0x16c0,3),(0x1d06,6)]:
   for i in range(n):
    data=bytearray(b);data[raw(start+i)]^=1;bad.write_bytes(data)
    p=subprocess.run([str(binary),str(bad)],capture_output=True,timeout=30)
    assert p.returncode==1 and not p.stdout,(start,i)
    mutations.append(start+i)
 out=dict(binding=binding,source_hashes={p:sha(REPO/p) for p in ['examples/crt_external_cell.rs','examples/crt_sentinel.rs','research/crt/check_external_cell.py']},blocked=blocked,vectors=results,byte_rejections=mutations,emission_allowed=False)
 path=root/'crt-external-cell.json'
 if a.compare:assert json.loads(path.read_text())==out
 else:path.write_text(json.dumps(out,indent=2)+'\n')
 evidence=json.loads((root/'crt-commode.json').read_text());assert evidence['binding']==binding and len(evidence['observations'])==4
 for v in evidence['observations']:
  assert v['exit']==0 and v['values'][0]==v['values'][1]==v['values'][2]
  assert v['values'][4:]==[0,0,0,0,0] # fixed observed domain; no invented nonzero CPU evidence
 assert sha(pe)==binding['pe_sha256']
 print('EXTERNAL_CELL: blocked default; four isolated vectors; 30 exact-byte and four integer rejections; existing Windows zero-only observations')
if __name__=='__main__':main()
