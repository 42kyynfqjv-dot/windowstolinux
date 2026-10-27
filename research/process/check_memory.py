"""Independent guard-omission mutations and actual emitted-frame checks.

Mutations live in temporary copies. No production source is edited by this check.
These are core/runtime contract checks, not original Windows comparisons.
"""
import json, os, shutil, subprocess, tempfile
from pathlib import Path
repo=Path(__file__).resolve().parents[2]
source=(repo/'src/guest_memory.rs').read_text()
def run(cmd):return subprocess.run(cmd,capture_output=True,timeout=45)
def compile_(src,out,test=False):
    p=run(['rustc','--edition=2021']+(['--test'] if test else [])+[str(src),'-o',str(out)])
    assert p.returncode==0,p.stderr.decode()
mutations=[
 ('process','cap.process != self.identity || cap.owner != owner','cap.owner != owner'),
 ('generation','r.capability == cap','r.capability.base == cap.base'),
 ('defined','!r.defined[s.clone()].iter().all(|&b| b)','false'),
 ('freshness','self.regions[i].epoch != fact.epoch','false'),
 ('top-range','end > (1u64 << 32)','false'),
 ('writable','!r.permissions.write','false'),
 ('wx','permissions.write && permissions.execute','false'),
]
rows=[]
with tempfile.TemporaryDirectory() as tmp:
    d=Path(tmp);shutil.copyfile(repo/'src/guest_memory_tests.rs',d/'guest_memory_tests.rs')
    src=d/'core.rs';exe=d/('core.exe' if os.name=='nt' else 'core')
    src.write_text(source);compile_(src,exe,True);p=run([str(exe)]);assert p.returncode==0,p.stdout
    for name,old,new in mutations:
        assert old in source,name
        src.write_text(source.replace(old,new,1));compile_(src,exe,True);p=run([str(exe)])
        assert p.returncode!=0 and b'test result: FAILED' in p.stdout,(name,p.stdout,p.stderr)
        rows.append(dict(omitted_guard=name,detected=True))
    core=source.split('\n#[cfg(test)]')[0]
    runtime=(repo/'src/linker/stream/runtime.txt').read_text().replace('// CHECKED_MEMORY_MODULE','#[allow(dead_code)]\nmod guest_memory {\n'+core+'\n}')
    vectors=[
      ('aliases', 'let mut f=Frame::new();f.put(8,4,0x78563412);f.put(10,1,0xab);assert_eq!(f.get(8,4),0x78ab3412);',0),
      ('fresh-prefix','let mut f=Frame::new();f.put(8,4,0x78563412);f.invalidate(8,4);f.destination(8,4)[0]=9;f.initialize(8,1);assert_eq!(f.get(8,1),9);assert_eq!(f.memory.read(0x10009,3).unwrap(),&[0x34,0x56,0x78]);',0),
      ('stale-tail','let mut f=Frame::new();f.put(8,4,0x78563412);f.invalidate(8,4);f.destination(8,4)[0]=9;f.initialize(8,1);f.get(9,1);',125),
      ('failed-read','let mut f=Frame::new();f.put(8,4,0x78563412);f.invalidate(8,4);let _=f.destination(8,4);f.get(8,4);',125),
      ('full-bound','let mut f=Frame::new();f.put(4095,4,0);',125),
      ('unknown','Frame::new().get(8,1);',125),
      ('zero-one-past','let mut f=Frame::new();assert!(f.destination(4096,0).is_empty());assert!(f.source(4096,0).is_empty());',0),
      ('zero-outside','Frame::new().source(4097,0);',125),
      ('count-alias','Frame::new().pair(12,8,16);',125),
      ('invalid-width','Frame::new().get(8,3);',125),
    ]
    arms=''.join(f'"{name}"=>{{{body}}},' for name,body,_ in vectors)
    src=d/'frame.rs';exe=d/('frame.exe' if os.name=='nt' else 'frame')
    src.write_text(runtime+'\nfn main(){match std::env::args().nth(1).unwrap().as_str(){'+arms+'_=>panic!("unknown vector")}}\n')
    compile_(src,exe)
    for name,_,code in vectors:
        p=run([str(exe),name]);assert p.returncode==code,(name,p.returncode,p.stdout,p.stderr)
        assert p.stdout==b'' and p.stderr==(b'stream runtime contract violation\n' if code else b''),(name,p.stderr)
print(json.dumps(dict(unique_core_tests=7,guard_mutations=rows,emitted_frame_vectors=len(vectors)),indent=2))
