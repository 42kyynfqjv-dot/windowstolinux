"""Same unchanged Windows PE -> native ELF, with frozen independent expectations."""
import hashlib,json,os,subprocess,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve();repo=Path(__file__).resolve().parents[2]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
prior=json.loads((root/'input-contract.json').read_text(encoding='utf-8'))
assert prior['conversion_accepted'] is True
assert sha(root/'input.exe')==prior['pe_sha256']
converter=repo/'target/debug/w2l';source=root/'input-native.rs';exe=root/'input-native'
for value in ['7','42']:
    # Converter environment must not affect output bytes or acceptance.
    env=dict(os.environ,W2L_INPUT=value)
    p=subprocess.run([str(converter),str(root/'input.exe'),str(source)],env=env,capture_output=True,timeout=15)
    assert p.returncode==0,p.stderr
    assert sha(source)==prior['generated_sha256']==sha(root/'input-generated.rs')
p=subprocess.run(['rustc','--edition=2021','-D','warnings',str(source),'-o',str(exe)],capture_output=True,timeout=60)
assert p.returncode==0,p.stderr
vectors=json.loads((repo/'research/input/vectors.json').read_text(encoding='utf-8'))
results=[]
for v in vectors:
    p=subprocess.run([str(exe)],env={} if v['value'] is None else {'W2L_INPUT':v['value']},capture_output=True,timeout=10)
    actual=dict(name=v['name'],exit=p.returncode,stdout_hex=p.stdout.hex(),stderr_hex=p.stderr.hex())
    assert actual==dict(name=v['name'],exit=v['exit'],stdout_hex='',stderr_hex=''),actual
    results.append(actual)
assert results==prior['observations']
# Independent valid-input boundaries and all decimal values: expected from Python's
# integer contract, not a production decoder/emitter/model/helper.
extra=['/',';',chr(0xffff),'\U00010000','09','90','9/','/9','\t7','7\n']+[f'{i:02d}' for i in range(100)]
for v in extra:
    expected=int(v) if v.isascii() and v.isdecimal() else 202
    p=subprocess.run([str(exe)],env={'W2L_INPUT':v},capture_output=True,timeout=10)
    assert (p.returncode,p.stdout,p.stderr)==(expected,b'',b''),(repr(v),p.returncode,expected)
negative=[{b'W2L_INPUT':b'\xff'},{b'w2l_input':b'7'},{b'W2L_INPUT':b'7',b'w2l_input':b'42'},{b'OTHER':b'x'*4097},{b'W2L_\xc4\xb1NPUT':b'7'}]
for env in negative:
    p=subprocess.run([os.fsencode(exe)],env=env,capture_output=True,timeout=10)
    assert (p.returncode,p.stdout,p.stderr)==(203,b'',b'')
assert sha(root/'input.exe')==prior['pe_sha256']
report=dict(pe_sha256=sha(root/'input.exe'),source_sha256=sha(source),elf_sha256=sha(exe),observations=results,
            additional_native_cases=len(extra),host_rejections=len(negative),conversion_accepted=True,
            same_elf_multiple_inputs=True,same_source_windows_linux=True,converter_environment_independent=True,
            assumptions='genuine available procfs; stable initial ASCII-key environment; UTF8 target; bounded host domain; valid stack/no fault')
(root/'input-translation.json').write_text(json.dumps(report,indent=2)+'\n')
print(f'INPUT TRANSLATION: 17 unchanged PE Windows/ELF pairs; {len(extra)} additional native cases; {len(negative)} host rejections')
