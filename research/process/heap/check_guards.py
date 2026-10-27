"""Independent guard/copy omissions must be detected by literal heap regressions."""
from pathlib import Path
import shutil
import subprocess
import tempfile

repo=Path(__file__).resolve().parents[3]
source=(repo/'src/guest_memory.rs').read_text()
mutations=[
 ('heap-identity','heap.process != self.identity','false'),
 ('allocation-origin','&& r.heap_allocation',''),
 ('zero-tail-preserves-unknown-prefix','defined[..n].copy_from_slice(&self.regions[i].defined[..n]);',''),
 ('copied-prefix','bytes[..n].copy_from_slice(&self.regions[i].bytes[..n]);',''),
 ('same-address-generation','self.regions[i] = Region {','let capability = Capability { generation: self.regions[i].capability.generation, ..capability };\nself.regions[i] = Region {'),
]
with tempfile.TemporaryDirectory() as tmp:
    d=Path(tmp)
    for f in ['guest_memory_tests.rs','guest_heap_tests.rs']:
        shutil.copyfile(repo/'src'/f,d/f)
    for name,old,new in mutations:
        assert source.count(old)==1,(name,source.count(old))
        (d/'core.rs').write_text(source.replace(old,new))
        p=subprocess.run(['rustc','--edition=2021','--test',str(d/'core.rs'),'-o',str(d/'core')],capture_output=True,timeout=45)
        assert p.returncode==0,(name,p.stderr.decode())
        p=subprocess.run([str(d/'core'),'heap_tests::'],capture_output=True,timeout=15)
        assert p.returncode!=0 and b'test result: FAILED' in p.stdout,(name,p.stdout,p.stderr)
print('Five heap guard/copy mutations detected; existing ten heap test functions reused, not five new tests')


# Regression for a reproduced false-positive report: an empty program list used
# to print 32 comparisons with exit0. Inventory gates run before cargo or PE reads.
import copy
import json
import sys
sys.path.insert(0,str(repo/'research/process/heap'))
from evidence import validate_report
manifest=json.loads((repo/'research/process/heap/frozen.json').read_text())
cases=json.loads((repo/'research/process/heap/cases.json').read_text())
report=dict(manifest=manifest,programs=[])
for name in manifest['programs']:
    digest='0'*64  # metadata-only unit vector; executable bytes are checked separately
    row=dict(name=name,pe_sha256=digest,conversion=dict(exit=1),observations=[])
    for c in cases:
        row['observations'].append(dict(name=c['name'],exit=0,stdout_hex=c['expected'][name],stderr_hex='',timeout=False,executed_sha256=digest))
    for key,code in [('read_failure',11),('write_failure',14)]:
        row[key]=dict(exit=code,stdout_hex='',stderr_hex='',timeout=False,executed_sha256=digest)
    report['programs'].append(row)
validate_report(report,manifest,cases)
bad=[]
r=copy.deepcopy(report);r['programs']=[];bad.append(r)
r=copy.deepcopy(report);r['programs'][1]=r['programs'][0];bad.append(r)
r=copy.deepcopy(report);r['programs'][0]['observations'].pop();bad.append(r)
r=copy.deepcopy(report);r['programs'][0]['observations'][0]['timeout']=True;bad.append(r)
r=copy.deepcopy(report);r['programs'][0]['observations'][0]['executed_sha256']='1'*64;bad.append(r)
r=copy.deepcopy(report);r['programs'][0]['write_failure']['exit']=0;bad.append(r)
for r in bad:
    try: validate_report(r,manifest,cases)
    except AssertionError: pass
    else: raise AssertionError('Malformed evidence accepted')
print('Six malformed metadata reports rejected; no execution or translation counted')
