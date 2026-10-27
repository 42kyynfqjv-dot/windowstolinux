"""Independent literal vectors against the exact emitted memory adapter."""
from pathlib import Path
import subprocess,tempfile,json
repo=Path(__file__).resolve().parents[3]
core=(repo/'src/guest_memory.rs').read_text().split('\n#[cfg(test)]')[0]
runtime=(repo/'src/linker/stream/runtime.txt').read_text().replace('// CHECKED_MEMORY_MODULE','mod guest_memory {\n'+core+'\n}')
program=runtime+r'''
fn main(){
 let mode=std::env::args().nth(1).unwrap();let mut m=Frame::new();
 let p=m.heap_alloc(0,8,true);assert_ne!(p,0);
 m.destination(p,8).copy_from_slice(&[1,2,3,4,5,6,7,8]);m.initialize(p,8);
 assert_eq!(m.get(p,4),0x04030201);assert_eq!(m.get(p+4,4),0x08070605);
 if mode=="word" {m.put(p+1,4,0xaabbccdd);assert_eq!(m.source(p,8),[1,0xdd,0xcc,0xbb,0xaa,6,7,8]);return;}
 if mode=="cross" {m.get(p+5,4);return;}
 if mode=="count" {m.pair(p,4,p+4);return;}
 m.invalidate(p,8);
 if mode=="failure" {m.get(p,1);return;}
 m.destination(p,8)[..2].copy_from_slice(&[0xfe,0x80]);m.initialize(p,2);
 assert_eq!(m.get(p,2),0x80fe);
 if mode=="short" {m.get(p,4);return;}
 let q=m.heap_resize(8,p,12,true);
 assert_eq!(m.get(q,2),0x80fe);
 if mode=="resize" {m.get(q+2,1);return;}
 assert_eq!(m.get(q+8,4),0);
}
'''
with tempfile.TemporaryDirectory() as folder:
 p=Path(folder);(p/'test.rs').write_text(program)
 subprocess.run(['rustc','--edition=2021','-Awarnings',str(p/'test.rs'),'-o',str(p/'test')],check=True)
 for mode,expected in [('word',0),('cross',125),('count',125),('failure',125),('short',125),('resize',125),('tail',0)]:
  r=subprocess.run([str(p/'test'),mode],capture_output=True,timeout=5)
  assert r.returncode==expected,(mode,r.returncode,r.stderr)
  assert r.stdout==b''
  assert r.stderr==(b'' if expected==0 else b'stream runtime contract violation\n')
print('Seven emitted-adapter boundary/freshness vectors passed; these are not PE translations')
