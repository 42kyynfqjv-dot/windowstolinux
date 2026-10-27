"""Linux-only partition/EOF checks of the actual emitted applications, not Windows pairs."""
import json,subprocess,sys,tempfile
from pathlib import Path
root=Path(sys.argv[1]).resolve();src=Path(__file__).resolve().parent;rows=[]
with tempfile.TemporaryDirectory() as td:
 d=Path(td)
 for row in json.loads((root/'report.json').read_text())['programs']:
  assert row['conversion']['exit']==0
  stem=row['name']+'_'+row['config'];(d/'generated.rs').write_bytes((root/(stem+'.rs')).read_bytes());(d/'partitions.rs').write_text((src/'partitions_native.rs').read_text().replace('"FILTER"',json.dumps(row['name'])))
  p=subprocess.run(['rustc','--edition=2021',str(d/'partitions.rs'),'-o',str(d/'partitions')],capture_output=True,timeout=30);assert p.returncode==0,p.stderr
  p=subprocess.run([str(d/'partitions')],capture_output=True,timeout=60);assert p.returncode==0 and p.stdout.strip()==b'37498' and not p.stderr,p.stderr
  rows.append(dict(program=stem,native_partitions=37498));print(stem,37498,flush=True)
(root/'partitions.json').write_text(json.dumps(rows,indent=2)+'\n')
