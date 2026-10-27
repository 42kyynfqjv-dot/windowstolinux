"""Exact original artifact/source evidence; accepted native runs or preserved rejection."""
import hashlib,json,subprocess,sys,tempfile
from pathlib import Path
here=Path(__file__).resolve().parent;repo=here.parents[2];root=Path(sys.argv[1]).resolve()
report=json.loads((root/'report.json').read_text());m=json.loads((here/'frozen.json').read_text());cases=json.loads((here/'cases.json').read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(cmd,**kw):return subprocess.run(cmd,timeout=40,stderr=subprocess.PIPE,stdout=kw.pop('stdout',subprocess.PIPE),**kw)
assert report['manifest']==m and len(report['programs'])==2
for f,h in m['sha256'].items():assert sha(here/f)==h
rows=[]
with tempfile.TemporaryDirectory() as tmp:
    d=Path(tmp)
    for row in report['programs']:
        name=row['name'];stem=name+'_O2';pe=root/(stem+'.exe');target=d/(stem+'.rs');assert sha(pe)==row['pe_sha256'];assert row['source_sha256']==m['sha256'][name+'.c']
        assert len(row['observations'])==len(cases)
        for obs,case in zip(row['observations'],cases):assert obs==dict(name=case['name'],exit=0,stdout_hex=case['expected'][name],stderr_hex='')
        target.write_text('preserve');p=run([str(repo/'target/debug/w2l'),str(pe),str(target)])
        got=dict(name=name,pe_sha256=sha(pe),conversion_exit=p.returncode,stderr=p.stderr.decode(errors='replace'));rows.append(got)
        assert p.returncode==row['conversion']['exit']
        if p.returncode:
            assert p.returncode==1 and target.read_text()=='preserve'
            assert got['stderr']==row['conversion']['stderr'],(got,row['conversion'])
            continue
        assert sha(target)==row['conversion']['rust_sha256'] and target.read_bytes()==(root/(stem+'.rs')).read_bytes()
        p=run([str(repo/'target/debug/w2l'),str(pe),str(target)]);assert p.returncode==0 and sha(target)==row['conversion']['rust_sha256']
        exe=d/stem;p=run(['rustc','--edition=2021',str(target),'-o',str(exe)]);assert p.returncode==0,p.stderr
        got['rust_sha256']=sha(target);got['observations']=[]
        for case,obs in zip(cases,row['observations']):
            path=d/'input.bin';path.write_bytes(bytes.fromhex(case['input_hex']))
            with path.open('rb') as f:p=run([str(exe)],stdin=f)
            actual=dict(name=case['name'],exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex());assert actual==obs;got['observations'].append(actual)
        with path.open('wb') as f:p=run([str(exe)],stdin=f)
        assert dict(exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex())==row['read_failure']
        path.write_bytes(b'abc')
        with path.open('rb') as f,path.open('rb') as dest:p=run([str(exe)],stdin=f,stdout=dest)
        assert dict(exit=p.returncode,stderr_hex=p.stderr.hex(),destination_hex=path.read_bytes().hex())==row['write_failure']
        got['real_failure_comparisons']=2
(root/'native.json').write_text(json.dumps(rows,indent=2)+'\n');print(json.dumps(rows,indent=2))
