"""Frozen baseline first; converter outcomes are measured only afterward."""
import hashlib,json,os,platform,shutil,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'heap'))
from measure import run,save,sha
out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=True)
repo=HERE.parents[2]
m=json.loads((HERE/'frozen.json').read_text());cases=json.loads((HERE/'cases.json').read_text())
for name,digest in m['sha256'].items():assert sha(HERE/name)==digest
r=dict(manifest=m,platform=platform.platform(),programs=[],toolchain={k:os.environ.get(k) for k in ['VCToolsVersion','WindowsSDKVersion']})
for tool in ['cl.exe','link.exe','dumpbin.exe']:
 p=Path(shutil.which(tool));r['toolchain'][tool]=dict(path=str(p),sha256=sha(p))
for name in m['programs']:
 p=dict(name=name,observations=[]);r['programs'].append(p)
 p['commands']=[['cl']+m['compile_flags']+m['configurations']['O2']+[str(HERE/(name+'.c')),'/Fo'+name+'.obj'],['link']+m['link_flags']+[name+'.obj']+m['libraries']+['/out:'+name+'.exe']]
 for i,c in enumerate(p['commands']):assert run(c,out/(name+'-build'+str(i)),cwd=out,timeout=30)['exit']==0
 pe=out/(name+'.exe');p['pe_sha256']=sha(pe)
 for kind in ['headers','imports','disasm']:assert run(['dumpbin','/'+kind,str(pe)],out/(name+'-'+kind),timeout=30)['exit']==0
 for c in cases[name]:
  data=out/'input.bin';data.write_bytes(bytes.fromhex(c['input_hex']))
  with data.open('rb') as f:o=run([str(pe)],out/(name+'-'+c['name']),stdin=f)
  p['observations'].append(dict(name=c['name'],**o));save(out/'report.json',r)
  assert (o['exit'],o['stdout_hex'],o['stderr_hex'])==(c['exit'],c['stdout_hex'],'')
for p in r['programs']:
 name=p['name'];target=out/(name+'.rs');target.write_text('preserve')
 o=run([str(repo/'target/debug/w2l.exe'),str(out/(name+'.exe')),str(target)],out/(name+'-conversion'),timeout=60)
 p['conversion']=dict(exit=o['exit'],stderr=bytes.fromhex(o['stderr_hex']).decode())
 assert sha(out/(name+'.exe'))==p['pe_sha256']
 if o['exit']==0:p['conversion']['rust_sha256']=sha(target)
 else:assert o['exit']==1 and target.read_text()=='preserve'
 save(out/'report.json',r)
assert all(p['conversion']['exit']==0 for p in r['programs']), 'Buffer production proof/emission failed'
print('12 frozen original Windows observations; both untouched PEs converted; Linux comparison required')
