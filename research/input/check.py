"""Frozen independent expectations: original Windows vs separate native prototype."""
import argparse, hashlib, json, os, subprocess
from pathlib import Path
ap=argparse.ArgumentParser();ap.add_argument('evidence',type=Path);ap.add_argument('--compare',action='store_true');a=ap.parse_args()
repo=Path(__file__).resolve().parents[2];src=repo/'research/input';root=a.evidence
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
vectors=json.loads((src/'vectors.json').read_text());sources={n:sha(src/n) for n in ['program.c','prototype.rs','vectors.json','check.py']}
def run(args,**kw):return subprocess.run(args,capture_output=True,timeout=30,**kw)
if not a.compare:
    flags=['/nologo','/Bv','/O2','/W4','/GS-','/Zl','/c',str(src/'program.c'),'/Foinput.obj']
    link=['/nologo','/machine:x86','/subsystem:console','/nodefaultlib','/entry:entry@0','input.obj','kernel32.lib','/out:input.exe']
    for name,args in [('compile',['cl']+flags),('link',['link']+link),('disassembly',['dumpbin','/disasm','input.exe']),('imports',['dumpbin','/imports','input.exe'])]:
        p=run(args,cwd=root);(root/('input-'+name+'.txt')).write_bytes(p.stdout+p.stderr);assert p.returncode==0,(name,p.stderr)
    exe=root/'input.exe';before=sha(exe)
else:
    old=json.loads((root/'input-contract.json').read_text());assert old['sources']==sources and sha(root/'input.exe')==old['pe_sha256']
    exe=root/'input-prototype';p=run(['rustc','--edition=2021',str(src/'prototype.rs'),'-o',str(exe)]);assert p.returncode==0,p.stderr
results=[]
for v in vectors:
    env={k:value for k,value in os.environ.items() if k.upper() in ('SYSTEMROOT','WINDIR','TEMP','TMP','PATH','COMSPEC')}
    if v['value'] is not None:env['W2L_INPUT']=v['value']
    p=run([str(exe)],env=env)
    actual=dict(name=v['name'],exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex())
    assert actual==dict(name=v['name'],exit=v['exit'],stdout_hex='',stderr_hex=''),actual
    results.append(actual)
if a.compare:
    assert results==old['observations'];print('INPUT_CONTRACT: 17 separate native prototype comparisons, not translations')
else:
    assert sha(exe)==before
    converter=run([str(repo/'target/debug/w2l.exe'),str(exe),str(root/'input-generated.rs')])
    assert converter.returncode==1,('expected explicit rejection',converter.returncode,converter.stderr)
    report=dict(sources=sources,pe_sha256=before,compile_flags=flags,link_flags=link,observations=results,conversion_accepted=False,converter_error=converter.stderr.decode(errors='replace'),emission_allowed=False)
    (root/'input-contract.json').write_text(json.dumps(report,indent=2)+'\n');print('INPUT_CONTRACT: 17 original observations; production rejected')
