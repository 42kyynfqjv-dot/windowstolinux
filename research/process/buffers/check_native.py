"""Validate original provenance and measure actual translation independently."""
from pathlib import Path
import hashlib,json,subprocess,sys
here=Path(__file__).resolve().parent;repo=here.parents[2];out=Path(sys.argv[1]).resolve()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
m=json.loads((here/'frozen.json').read_text());cases=json.loads((here/'cases.json').read_text());r=json.loads((out/'report.json').read_text())
assert r['manifest']==m and {p['name'] for p in r['programs']}==set(m['programs']) and len(r['programs'])==2
for name,h in m['sha256'].items():assert sha(here/name)==h
result=[]
for p in r['programs']:
 name=p['name'];pe=out/(name+'.exe');rust=out/(name+'-linux.rs');exe=out/(name+'-elf')
 assert sha(pe)==p['pe_sha256']
 assert len(p['observations'])==len(cases[name])
 observations={x['name']:x for x in p['observations']};assert len(observations)==len(cases[name])
 for c in cases[name]:
  o=observations[c['name']];assert o['executed_sha256']==p['pe_sha256'] and not o['timeout']
  assert (o['exit'],o['stdout_hex'],o['stderr_hex'])==(c['exit'],c['stdout_hex'],'')
 rust.write_text('preserve')
 q=subprocess.run([str(repo/'target/debug/w2l'),str(pe),str(rust)],capture_output=True,timeout=120)
 row=dict(program=name,pe_sha256=sha(pe),conversion_exit=q.returncode,diagnostic=q.stderr.decode(),comparisons=[]);result.append(row)
 if q.returncode:
  assert q.returncode==1 and rust.read_text()=='preserve'
  continue
 assert p['conversion']['exit']==0 and sha(rust)==p['conversion']['rust_sha256'] and rust.read_bytes()==(out/(name+'.rs')).read_bytes()
 row['rust_sha256']=sha(rust)
 subprocess.run(['rustc','--edition=2021','-Awarnings',str(rust),'-o',str(exe)],check=True,timeout=60)
 row['elf_sha256']=sha(exe)
 for c in cases[name]:
  data=out/'native-input.bin';data.write_bytes(bytes.fromhex(c['input_hex']))
  with data.open('rb') as f:q=subprocess.run([str(exe)],stdin=f,capture_output=True,timeout=15)
  assert (q.returncode,q.stdout.hex(),q.stderr.hex())==(c['exit'],c['stdout_hex'],'')
  row['comparisons'].append(dict(case=c['name'],exit=q.returncode,stdout_hex=q.stdout.hex(),stderr_hex=q.stderr.hex()))
(out/'native.json').write_text(json.dumps(result,indent=2)+'\n')
if '--require-translation' in sys.argv:assert all(x['conversion_exit']==0 for x in result)
print(sum(len(x['comparisons']) for x in result),'actual Windows/ELF pairs;',sum(x['conversion_exit']!=0 for x in result),'rejected programs')
