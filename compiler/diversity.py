"""Frozen four-source measurement. No source rewriting or compiler flag search."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

repo=Path.cwd()
root=Path(os.environ['RUNNER_TEMP'])/'w2l-compiler-measurement'
cases=json.loads((repo/'compiler/variations/cases.json').read_text())
results=[]
for case in cases:
    name=case['kind']; source=repo/case['source']; original_source=source.read_bytes()
    assert b'\r' not in original_source, 'source checkout must be LF'
    flags=['/nologo','/Bv','/O2','/W4','/c',str(source),'/Fo'+name+'.obj','/DFREESTANDING','/GS-','/Zl']
    link=['/nologo','/machine:x86','/subsystem:console',name+'.obj','/out:'+name+'.exe','/nodefaultlib','/entry:entry@0','legacy.lib']
    for label,command in [('compile',['cl']+flags),('link',['link']+link),('disassembly',['dumpbin','/disasm',name+'.exe']),('relocations',['dumpbin','/relocations',name+'.exe']),('headers',['dumpbin','/headers','/imports',name+'.exe'])]:
        p=subprocess.run(command,cwd=root,capture_output=True,timeout=180)
        text=(p.stdout+p.stderr).decode(errors='replace')
        (root/(name+'-'+label+'.txt')).write_text(text)
        print(name+' '+label+'\n'+text)
        assert p.returncode==0,(name,label,p.returncode)
    pe=root/(name+'.exe'); before=pe.read_bytes()
    with (root/(name+'.stdout')).open('wb') as out,(root/(name+'.stderr')).open('wb') as err:
        p=subprocess.run([str(pe)],stdout=out,stderr=err,timeout=15)
    observation=((root/(name+'.stdout')).read_bytes().hex(),(root/(name+'.stderr')).read_bytes().hex(),p.returncode)
    assert observation==(case['stdout_hex'],case['stderr_hex'],case['exit']),(name,observation)
    rust=root/(name+'.rs')
    rust.write_bytes(b'preserve rejected output')
    converter=subprocess.run([str(repo/'target/debug/w2l.exe'),str(pe),str(rust)],capture_output=True,timeout=15)
    assert converter.returncode in (0,1),converter.stderr
    accepted=converter.returncode==0
    if not accepted:
        assert rust.read_bytes()==b'preserve rejected output'
        rust.unlink()
    result=dict(case,sha256=hashlib.sha256(before).hexdigest(),source_sha256=hashlib.sha256(original_source).hexdigest(),
                rust_sha256=hashlib.sha256(rust.read_bytes()).hexdigest() if accepted else None,
                conversion_accepted=accepted,converter_stderr=converter.stderr.decode(),compile_flags=flags,link_flags=link)
    assert source.read_bytes()==original_source and pe.read_bytes()==before
    print('DIVERSITY_MEASUREMENT '+json.dumps(result))
    results.append(result)
(root/'diversity-report.json').write_text(json.dumps(results,indent=2)+'\n')
assert len(results)==4
