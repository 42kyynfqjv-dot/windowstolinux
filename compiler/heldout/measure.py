"""Frozen authored-program measurement. No converter/model implementation imports."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

FREEZE='cf042295303dccedb8506564f1e466ef9d353acd'
repo=Path.cwd()
manifest=json.loads((repo/'compiler/heldout/cases.json').read_text())
root=Path(os.environ['RUNNER_TEMP'])/'w2l-compiler-measurement'
arch=sys.argv[1]
assert arch in ('x86','x64')
results=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def command(args,label):
    p=subprocess.run(args,cwd=root,capture_output=True,timeout=180)
    text=(p.stdout+p.stderr).decode(errors='replace')
    (root/(label+'.txt')).write_text(text)
    assert p.returncode==0,(label,text)
    return text
for case in manifest:
    if case['arch']!=arch:continue
    name=case['kind'];source=repo/case['source'];original_source=source.read_bytes()
    frozen=subprocess.run(['git','show',FREEZE+':'+case['source']],capture_output=True,check=True).stdout
    assert original_source==frozen and b'\r' not in original_source,'frozen LF source mismatch'
    flags=['/nologo','/Bv','/O2','/W4','/c',str(source),'/Fo'+name+'.obj']
    flags+=['/GS-','/Zl'] if case['profile']=='custom' else ['/MD']
    link=['/nologo','/machine:'+arch,'/subsystem:console',name+'.obj','/out:'+name+'.exe']
    if case['profile']=='custom':link+=['/nodefaultlib','/entry:entry@0']
    version=command(['cl']+flags,name+'-compile')
    command(['link']+link,name+'-link')
    command(['dumpbin','/headers','/imports',name+'.exe'],name+'-headers')
    command(['dumpbin','/disasm',name+'.exe'],name+'-disassembly')
    pe=root/(name+'.exe');before=pe.read_bytes()
    nt=struct.unpack_from('<I',before,60)[0];opt=nt+24
    count=struct.unpack_from('<H',before,nt+6)[0]
    table=opt+struct.unpack_from('<H',before,nt+20)[0]
    sections=[]
    for i in range(count):
        at=table+40*i
        sections.append(dict(name=before[at:at+8].rstrip(b'\0').decode(errors='replace'),
            virtual_size=struct.unpack_from('<I',before,at+8)[0],rva=struct.unpack_from('<I',before,at+12)[0],
            flags=hex(struct.unpack_from('<I',before,at+36)[0])))
    with tempfile.TemporaryDirectory(dir=root) as temporary:
        work=Path(temporary)
        with (work/'stdout').open('wb') as out,(work/'stderr').open('wb') as err:
            p=subprocess.run([str(pe)]+case['args'],cwd=work,stdout=out,stderr=err,timeout=15)
        observation=dict(stdout_hex=(work/'stdout').read_bytes().hex(),stderr_hex=(work/'stderr').read_bytes().hex(),exit=p.returncode)
        files={n:(work/n).read_bytes().hex() for n in case['files']}
        baseline=dict(case,**{k:v for k,v in observation.items() if k not in case})
        actual=dict(observation,files=files)
        (root/(name+'-baseline.json')).write_text(json.dumps(actual,indent=2)+'\n')
        print('HELD_BASELINE',name,json.dumps(actual),flush=True)
        assert observation=={k:case[k] for k in observation} and files==case['files'],(name,actual)
    rust=root/(name+'.rs');rust.write_bytes(b'preserve')
    p=subprocess.run([str(repo/'target/debug/w2l.exe'),str(pe),str(rust)],capture_output=True,timeout=15)
    assert p.returncode in (0,1),p.stderr
    accepted=p.returncode==0
    expected_accepted=json.loads((repo/'compiler/heldout/conversion.json').read_text())['accepted']
    assert accepted == (name in expected_accepted),(name,p.stderr)
    if not accepted:
        assert rust.read_bytes()==b'preserve';rust.unlink()
    result=dict(case,freeze_commit=FREEZE,source_sha256=sha(original_source),sha256=sha(before),
        rust_sha256=sha(rust.read_bytes()) if accepted else None,conversion_accepted=accepted,
        converter_stderr=p.stderr.decode(),compile_flags=flags,link_flags=link,sections=sections,
        machine=hex(struct.unpack_from('<H',before,nt+4)[0]),optional_magic=hex(struct.unpack_from('<H',before,opt)[0]))
    assert source.read_bytes()==original_source and pe.read_bytes()==before
    results.append(result)
    (root/('heldout-'+arch+'.json')).write_text(json.dumps(results,indent=2)+'\n')
    print('HELD_MEASUREMENT '+json.dumps(result),flush=True)
assert len(results)==(7 if arch=='x86' else 1)
