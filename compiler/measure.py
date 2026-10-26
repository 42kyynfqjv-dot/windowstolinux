"""Measure unmodified MSVC output. No existing fixture/production imports."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from linker_intake import Candidate
from dumpbin_relocations import highlow_words

repo=Path.cwd()
root=Path(os.environ['RUNNER_TEMP'])/'w2l-compiler-measurement'
root.mkdir(exist_ok=True)

def command(args, name):
    p=subprocess.run(args,cwd=root,capture_output=True,timeout=180)
    text=(p.stdout+p.stderr).decode('utf-8',errors='replace')
    (root/(name+'.txt')).write_text(text)
    print(name+':\n'+text)
    assert p.returncode==0,(args,p.returncode)
    return text

# /Bv with a real compile records the front/back-end versions without a no-input failure.
command(['lib','/nologo','/machine:x86','/def:'+str(repo/'compiler/msvcrt.def'),'/out:legacy.lib'],'authored-import-library')
command(['cl','/nologo','/W4','/O2',str(repo/'compiler/observe_base.c'),'/Feobserver.exe'],'observer-build')
results=[]
for kind in ['freestanding','crt']:
    obj=kind+'.obj';exe=kind+'.exe'
    flags=['/nologo','/Bv','/O2','/W4','/c',str(repo/'compiler/program.c'),'/Fo'+obj]
    if kind=='freestanding': flags+=['/DFREESTANDING','/GS-','/Zl']
    else: flags+=['/MD']
    command(['cl']+flags,kind+'-compile')
    link=['link','/nologo','/machine:x86','/subsystem:console',obj,'/out:'+exe]
    if kind=='freestanding': link+=['/nodefaultlib','/entry:entry@0','legacy.lib']
    command(link,kind+'-link')
    command(['dumpbin','/headers','/imports',exe],kind+'-headers-imports')
    # Disassemble only our freestanding authored program, not linked CRT startup code.
    if kind=='freestanding':
        command(['dumpbin','/disasm',exe],kind+'-disassembly')
        relocation_listing = command(['dumpbin','/relocations',exe],kind+'-relocations')
    b=(root/exe).read_bytes();pe=struct.unpack_from('<I',b,60)[0];o=pe+24
    assert b[pe:pe+4]==b'PE\0\0' and struct.unpack_from('<H',b,o)[0]==0x10b
    sections=struct.unpack_from('<H',b,pe+6)[0]
    with open(root/(kind+'.stdout'),'wb') as out,open(root/(kind+'.stderr'),'wb') as err:
        p=subprocess.run([str(root/exe)],stdout=out,stderr=err,timeout=15)
    observation=((root/(kind+'.stdout')).read_bytes().hex(),(root/(kind+'.stderr')).read_bytes().hex(),p.returncode)
    assert observation==('48656c6c6f','',0),(kind,observation)
    converter=subprocess.run([str(repo/'target/debug/w2l.exe'),str(root/exe),str(root/(kind+'.rs'))],capture_output=True,timeout=15)
    if kind == 'freestanding':
        assert converter.returncode == 1
        assert 'linker intake validated; unsupported entry at RVA 0x1000 (opcode 0x56)' in converter.stderr.decode()
        assert not (root/(kind+'.rs')).exists()
    result=dict(kind=kind,sha256=hashlib.sha256(b).hexdigest(),sections=sections,
        coff_characteristics=hex(struct.unpack_from('<H',b,pe+22)[0]),dll_characteristics=hex(struct.unpack_from('<H',b,o+70)[0]),
        directories=[dict(index=i,rva=hex(struct.unpack_from('<I',b,o+96+8*i)[0]),size=struct.unpack_from('<I',b,o+100+8*i)[0]) for i in range(16) if any(struct.unpack_from('<II',b,o+96+8*i))],
        expected_stdout_hex='48656c6c6f',stdout_hex=observation[0],stderr_hex=observation[1],exit=observation[2],
        converter_exit=converter.returncode,converter_stderr=converter.stderr.decode(errors='replace'),
        conversion_accepted=converter.returncode==0,compile_flags=flags,link_flags=link[1:])
    print('MEASUREMENT '+json.dumps(result))
    results.append(result)
    if kind=='freestanding':
        # Separate test-only structural model; the production rejection above remains.
        # No file patching, decoder bypass or compiled-program equivalence claim.
        candidate = Candidate(b)
        intake = candidate.report()
        tool_words = highlow_words(relocation_listing)
        model_words = [(p.site, candidate.base + p.rva) for p in candidate.pointers]
        assert tool_words == model_words, (tool_words, model_words)
        intake['dumpbin_highlow_agrees'] = True
        assert candidate.blob == b
        (root/'linker-intake-prototype.json').write_text(json.dumps(intake,indent=2)+'\n')
        print('TEST_ONLY_LINKER_INTAKE '+json.dumps(intake))
        # Separate instrumented run. Original non-debug execution above remains baseline.
        with open(root/'observed.stdout','wb') as out,open(root/'observed.stderr','wb') as err:
            observed=subprocess.run([str(root/'observer.exe'),str(root/exe),str(root/'actual-base.txt')],
                                    stdout=out,stderr=err,timeout=15)
        assert observed.returncode == 0
        assert (root/'observed.stdout').read_bytes() == b'Hello'
        assert (root/'observed.stderr').read_bytes() == b''
        actual_base=int((root/'actual-base.txt').read_text().strip())
        assert (root/exe).read_bytes() == b
        base_report=dict(instrumentation='DEBUG_ONLY_THIS_PROCESS child creation event',
                         actual_base=actual_base,preferred_base=candidate.base,
                         relocated=actual_base != candidate.base,pe_sha256=hashlib.sha256(b).hexdigest(),
                         stdout_hex='48656c6c6f',stderr_hex='',exit=observed.returncode)
        candidate.rebase_words(actual_base)  # Check observed base is inside design domain.
        (root/'observed-base.json').write_text(json.dumps(base_report,indent=2)+'\n')
        print('OBSERVED_LOAD_BASE '+json.dumps(base_report))
(root/'report.json').write_text(json.dumps(results,indent=2)+'\n')
print('Compiler experiment: two originals verified; acceptance is reported, never assumed.')
