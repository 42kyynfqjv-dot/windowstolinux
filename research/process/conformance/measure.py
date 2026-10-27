"""Frozen custom-entry memory programs. Windows baseline precedes conversion."""
import hashlib, json, os, platform, shutil, subprocess, sys, time
from pathlib import Path
from types import SimpleNamespace
here=Path(__file__).resolve().parent
repo=here.parents[2]
sys.path.insert(0,str(repo/'corpus'))
from launch import capture_process_state
out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=True)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n',encoding='utf-8')
def run(cmd,**kwargs):
    record=dict(command=list(map(str,cmd)),platform=platform.platform(),started=time.time())
    save(out/'stage.json',record)
    with (out/'stdout.tmp').open('wb') as stdout,(out/'stderr.tmp').open('wb') as stderr:
        child=subprocess.Popen(cmd,stdout=kwargs.pop('stdout',stdout),stderr=stderr,**kwargs)
        record['pid']=child.pid;save(out/'stage.json',record)
        try: code=child.wait(timeout=30)
        except subprocess.TimeoutExpired:
            record['process_state']=capture_process_state(child.pid,out)
            record['poll']=child.poll();save(out/'timeout.json',record)
            if Path(cmd[0]).is_file():shutil.copyfile(cmd[0],out/'timeout-program.bin')
            child.kill();child.wait(timeout=5);raise
    return SimpleNamespace(returncode=code,stdout=(out/'stdout.tmp').read_bytes(),stderr=(out/'stderr.tmp').read_bytes())
m=json.loads((here/'frozen.json').read_text());cases=json.loads((here/'cases.json').read_text())
for f,h in m['sha256'].items():assert sha(here/f)==h,(f,sha(here/f),h)
report=dict(manifest=m,platform=platform.platform(),toolchain={k:os.environ.get(k) for k in ['VCToolsVersion','WindowsSDKVersion']},programs=[])
for tool in ['cl.exe','link.exe']:
    path=Path(shutil.which(tool));report['toolchain'][tool]=dict(path=str(path),sha256=sha(path))
for name in m['programs']:
    stem=name+'_O2';pe=out/(stem+'.exe');row=dict(name=name,config='O2',observations=[]);report['programs'].append(row)
    commands=[['cl']+m['compile_flags']+m['configurations']['O2']+[str(here/(name+'.c')),'/Fo'+stem+'.obj'],['link']+m['link_flags']+[stem+'.obj']+m['libraries']+['/out:'+stem+'.exe']]
    row['commands']=commands;save(out/'report.json',report)
    for i,cmd in enumerate(commands):
        p=run(cmd,cwd=out);(out/(stem+'-build'+str(i)+'.txt')).write_bytes(p.stdout+p.stderr);assert p.returncode==0,p.stderr
    row.update(pe_sha256=sha(pe),source_sha256=sha(here/(name+'.c')))
    for kind in ['headers','imports','disasm']:
        p=run(['dumpbin','/'+kind,str(pe)]);assert p.returncode==0;(out/(stem+'-'+kind+'.txt')).write_bytes(p.stdout)
    for case in cases:
        path=out/'input.bin';path.write_bytes(bytes.fromhex(case['input_hex']))
        with path.open('rb') as f:p=run([str(pe)],stdin=f)
        obs=dict(name=case['name'],exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex());row['observations'].append(obs);save(out/'report.json',report)
        assert (p.returncode,p.stdout.hex(),p.stderr)==(0,case['expected'][name],b'')
    path=out/'input.bin';path.write_bytes(b'abc')
    with path.open('wb') as f:p=run([str(pe)],stdin=f)
    row['read_failure']=dict(exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex());assert row['read_failure']==dict(exit=11,stdout_hex='',stderr_hex='')
    path.write_bytes(b'abc')
    with path.open('rb') as f,path.open('rb') as dest:p=run([str(pe)],stdin=f,stdout=dest)
    row['write_failure']=dict(exit=p.returncode,stderr_hex=p.stderr.hex(),destination_hex=path.read_bytes().hex());assert row['write_failure']==dict(exit=12,stderr_hex='',destination_hex='616263')
    save(out/'report.json',report)
# No converter queries until source/configuration/expectations and baseline are fixed.
for row in report['programs']:
    stem=row['name']+'_O2';pe=out/(stem+'.exe');target=out/(stem+'.rs');target.write_text('preserve')
    p=run([str(repo/'target/debug/w2l.exe'),str(pe),str(target)])
    row['conversion']=dict(exit=p.returncode,stderr=p.stderr.decode(errors='replace'))
    if p.returncode==0:row['conversion']['rust_sha256']=sha(target)
    else:assert p.returncode==1 and target.read_text()=='preserve'
    assert sha(pe)==row['pe_sha256'];save(out/'report.json',report)
print('Two unchanged custom-entry programs; 24 file observations + four real I/O failures; conversion outcomes in report.json')
