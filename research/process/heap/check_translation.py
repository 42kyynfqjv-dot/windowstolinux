"""Production PE safety mutations and emitted-code scripted API failures.

Mutated PEs are converter inputs only, NEVER executed on Windows or Linux.
Scripted allocation failures are native conformance evidence, not Windows OOM.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

here = Path(__file__).resolve().parent
repo = here.parents[2]
out = Path(sys.argv[1]).resolve()
cases = json.loads((here / 'cases.json').read_text())
report = json.loads((out / 'report.json').read_text())
results = dict(scripted=[], additional_native=[], rejected=[])


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def code_range(image):
    pe = struct.unpack_from('<I', image, 0x3c)[0]
    count, opt = struct.unpack_from('<H', image, pe+6)[0], struct.unpack_from('<H', image, pe+20)[0]
    for i in range(count):
        at = pe+24+opt+40*i
        if image[at:at+8].rstrip(b'\0') == b'.text':
            size, _, _, raw = struct.unpack_from('<IIII', image, at+8)
            assert raw+size <= len(image)
            return raw, size
    raise AssertionError('missing code')


for name in ['grow', 'shrink']:
    source = (out/(name+'-linux.rs')).read_text()
    assert sha(out/(name+'-linux.rs')) == next(p for p in report['programs'] if p['name'] == name)['conversion']['rust_sha256']
    driver = 'mod program {\n'+source+'\n}\n'+r'''
struct Script { input:Vec<u8>, output:Vec<u8>, allocations:usize, fail:usize, mode:u8 }
impl program::StreamIo for Script {
 fn standard(&mut self,s:u32)->u32 { if s==0xfffffff6 {1} else {2} }
 fn heap_available(&mut self)->bool {self.allocations+=1;self.allocations!=self.fail}
 fn read(&mut self,_:u32,b:&mut[u8])->Result<usize,u32> {
   if self.mode==1 {return Err(6)}
   let n=if self.mode==2 {1} else {2};b[..n].copy_from_slice(&self.input[..n]);Ok(n)
 }
 fn write(&mut self,_:u32,b:&[u8])->Result<usize,u32> {
   if self.mode==3 {return Ok(0)}
   if self.mode==4 && !self.output.is_empty() {return Err(1117)}
   let n=b.len().min(1);self.output.extend_from_slice(&b[..n]);Ok(n)
 }
}
fn main(){
'''
    checks = 0
    max_alloc = 2 if name == 'grow' else 3
    for c in cases:
        data = list(bytes.fromhex(c['input_hex']))
        expected = list(bytes.fromhex(c['expected'][name]))
        schedules = [(0, 0, 0, expected), (0, 1, 11, []), (0, 2, 11, []),
                     (0, 3, 15, []), (0, 4, 14 if len(expected)>1 else 0, expected[:1])]
        for failure in range(1, max_alloc+1):
            schedules.append((failure, 0, 13 if failure == max_alloc else 12, []))
        for fail, mode, exit_code, output in schedules:
            checks += 1
            driver += (f'{{let mut io=Script{{input:vec!{data!r},output:vec![],allocations:0,fail:{fail},mode:{mode}}};'
                       f'assert_eq!(program::run(&mut io),{exit_code},"{name}/{c["name"]}/{fail}/{mode} exit");'
                       f'assert_eq!(io.output,vec!{output!r},"{name}/{c["name"]}/{fail}/{mode} bytes");}}\n')
    frozen_inputs={c['input_hex'] for c in cases}
    additional=0
    for a in range(256):
        b=255-a
        if bytes([a,b]).hex() in frozen_inputs:
            continue
        n=1+(a%32)
        expected=([(17*i+a)%256 for i in range(n)]+[0]*(1+(b%16))) if name=='grow' else [((b+3*i)%256) for i in reversed(range(n//2+1))]
        driver += (f'{{let mut io=Script{{input:vec![{a},{b}],output:vec![],allocations:0,fail:0,mode:0}};'
                   f'assert_eq!(program::run(&mut io),0);assert_eq!(io.output,vec!{expected!r});}}\n')
        additional+=1
    results['additional_native'].append(dict(program=name,cases=additional,windows_comparison=False))
    driver += '}\n' 
    path = out/(name+'-scripted.rs'); path.write_text(driver)
    exe = out/(name+'-scripted')
    subprocess.run(['rustc','--edition=2021','-Awarnings',str(path),'-o',str(exe)],check=True,timeout=60)
    subprocess.run([str(exe)],check=True,timeout=30)
    results['scripted'].append(dict(program=name,cases=checks,source_sha256=sha(path),binary_sha256=sha(exe)))

# Literal disassembly-derived edits with independently specified unsafe effects.
# Unique patterns make compiler drift fail loudly rather than mutating a guessed RVA.
mutations = [
 ('unsupported-alloc-flags','grow','6a0046538974242c','6a0146538974242c'),
 ('unknown-alloc-flags','grow','6a0046538974242c','569046538974242c'),
 ('invalid-size-including-zero','grow','83e71f4783e60f','83e71f4f83e60f'),
 ('uninitialized-new-tail','grow','55526a0853','55526a0053'),
 ('skip-null-result-guard','grow','85d2750b','85d2eb0b'),
 ('overrun-fill-bound','grow','413bcf72ed','413bce72ed'),
 ('pointer-layout-observation','grow','f6c207','f6c2ff'),
 ('null-free-on-allocation-failure','shrink','565055ff1510204000','505055ff1510204000'),
 ('uninitialized-first-allocation','shrink','6a08d1ef5547','6a00d1ef5547'),
 ('unsupported-pointer-increment-at-resize','shrink','57566a0055','57466a0055'),
 ('stale-alias-after-resize','shrink','895c241485db','8974241485db'),
 ('pointer-alignment-upper-bits','shrink','0bc6a807','0bc6a8ff'),
]
for label,name,old,new in mutations:
    original = (out/(name+'.exe')).read_bytes()
    image = bytearray(original)
    raw, size = code_range(image)
    code = bytes(image[raw:raw+size])
    old,new = bytes.fromhex(old),bytes.fromhex(new)
    assert len(old)==len(new) and code.count(old)==1, (label,code.count(old))
    at = raw+code.index(old)
    image[at:at+len(old)] = new
    pe = out/(label+'.exe');pe.write_bytes(image)
    rust = out/(label+'.rs');rust.write_text('preserve')
    p = subprocess.run([str(repo/'target/debug/w2l'),str(pe),str(rust)],capture_output=True,timeout=60)
    assert p.returncode==1 and rust.read_text()=='preserve', (label,p.returncode,p.stderr.decode())
    results['rejected'].append(dict(case=label,sha256=sha(pe),diagnostic=p.stderr.decode()))
# Solver budget exhaustion remains a rejection and never produces source.
import os
env = dict(os.environ, W2L_Z3_RLIMIT='1')
rust=out/'solver-budget.rs';rust.write_text('preserve')
p=subprocess.run([str(repo/'target/debug/w2l'),str(out/'grow.exe'),str(rust)],env=env,capture_output=True,timeout=60)
assert p.returncode==1 and rust.read_text()=='preserve' and (b'stream proof rejected' in p.stderr or b'stream solver failed/output outside policy' in p.stderr)
results['rejected'].append(dict(case='solver-budget',diagnostic=p.stderr.decode()))
(out/'translation-checks.json').write_text(json.dumps(results,indent=2)+'\n')
print(sum(r['cases'] for r in results['scripted']), 'emitted-code scripted cases;',sum(r['cases'] for r in results['additional_native']), 'additional native inputs;', len(results['rejected']), 'production rejections')
