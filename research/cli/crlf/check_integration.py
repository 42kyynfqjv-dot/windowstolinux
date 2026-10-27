"""Frozen scripted expectations exercised through emitted application code.

These backend substitutions are separate from actual Windows/ELF OS pairs.
"""
import json, subprocess, sys, tempfile
from pathlib import Path
root=Path(sys.argv[1]).resolve()
src=Path(__file__).resolve().parent
report=json.loads((root/'report.json').read_text())
expected=json.loads((src/'probe-expectations.json').read_text())
assert len(report['programs'])==2
records=[]
with tempfile.TemporaryDirectory() as td:
 d=Path(td)
 for row in report['programs']:
  assert row['conversion']['exit']==0, row['conversion']
  stem=row['name']+'_'+row['config']
  (d/'generated.rs').write_bytes((root/(stem+'.rs')).read_bytes())
  (d/'scripted.rs').write_bytes((src/'scripted_native.rs').read_bytes())
  p=subprocess.run(['rustc','--edition=2021',str(d/'scripted.rs'),'-o',str(d/'scripted')],capture_output=True,timeout=30)
  assert p.returncode==0,p.stderr
  p=subprocess.run([str(d/'scripted')],capture_output=True,timeout=30)
  assert p.returncode==0 and not p.stderr,p.stderr
  actual=[]
  for line in p.stdout.decode().splitlines():
   a,b,c,e,h=line.split(' ',4)
   actual.append(dict(mode=int(a),exit=int(b),reads=int(c),writes=int(e),stdout_hex=h))
  assert len(actual)==24
  for a,b in zip(actual,expected):assert {k:a[k] for k in b}==b,(stem,a,b)
  (d/'partition.rs').write_bytes((src/'partition_native.rs').read_bytes())
  p=subprocess.run(['rustc','--edition=2021',str(d/'partition.rs'),'-o',str(d/'partition')],capture_output=True,timeout=30)
  assert p.returncode==0,p.stderr
  p=subprocess.run([str(d/'partition')],capture_output=True,timeout=30)
  assert p.returncode==0 and not p.stderr and p.stdout.strip()==b'37450',p.stderr
  records.append(dict(program=stem,scripted=actual,native_partition_executions=37450))
(root/'integration.json').write_text(json.dumps(records,indent=2)+'\n')
print('2 emitted programs x 24 frozen scripted schedules/failures + 74900 exhaustive short-input/partition/EOF executions; separate from 78 real OS pairs')
