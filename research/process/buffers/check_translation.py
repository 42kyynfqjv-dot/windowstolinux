"""Actual emitted programs with independent schedules; unsafe PE edits never execute."""
from pathlib import Path
import json,subprocess,hashlib,os
import sys
here=Path(__file__).resolve().parent;repo=here.parents[2];out=Path(sys.argv[1]).resolve()
results={'scripted':[],'rejected':[]}
for name in ['stream','record']:
 source=(out/(name+'-linux.rs')).read_text()
 driver='mod guest {\n'+source+'\n}\n'+r'''
struct Io{data:Vec<u8>,at:usize,out:Vec<u8>,chunk:usize,write:usize,mode:u8,reads:usize}
impl guest::StreamIo for Io{
 fn heap_available(&mut self)->bool{self.mode!=1}
 fn standard(&mut self,s:u32)->u32{if s==0xfffffff6 {1}else{2}}
 fn read(&mut self,_:u32,b:&mut[u8])->Result<usize,u32>{
  self.reads+=1;if self.mode==2 || (self.mode==3 && self.reads==2){return Err(1117)}
  let n=b.len().min(self.chunk).min(self.data.len()-self.at);
  b[..n].copy_from_slice(&self.data[self.at..self.at+n]);self.at+=n;Ok(n)
 }
 fn write(&mut self,_:u32,b:&[u8])->Result<usize,u32>{
  if self.mode==4{return Err(1117)}if self.mode==5{return Ok(0)}
  let n=b.len().min(self.write);self.out.extend_from_slice(&b[..n]);Ok(n)
 }
}
fn main(){
'''
 count=0
 inputs=[b'',bytes(7),bytes.fromhex('ffffffff01000000'),bytes(range(65)),bytes(range(256))*2+b'\xff\x00']
 for data in inputs:
  for chunk in [1,3,8,63,64]:
   for write in [1,7]:
    for mode in range(6):
     n=min(len(data),chunk,64 if name=='stream' else 8)
     if mode==1:code,expected=12,b''
     elif mode==2:code,expected=11,b''
     elif name=='record' and n!=8:code,expected=11,b''
     else:
      if name=='record':expected=((int.from_bytes(data[:4],'little')+int.from_bytes(data[4:8],'little'))%(2**32)).to_bytes(4,'little');code=0
      else:expected=bytes(x^32 for x in (data[:n] if mode==3 else data));code=11 if mode==3 and n else 0
      if expected and mode in [4,5]:code,expected=(14 if mode==4 else 15),b''
     driver+=f'{{let mut io=Io{{data:vec!{list(data)!r},at:0,out:vec![],chunk:{chunk},write:{write},mode:{mode},reads:0}};assert_eq!(guest::run(&mut io),{code},"{name}/{count}");assert_eq!(io.out,vec!{list(expected)!r},"bytes {name}/{count}");}}\n'
     count+=1
 driver+='}\n';path=out/(name+'-scripted.rs');path.write_text(driver);exe=out/(name+'-scripted')
 subprocess.run(['rustc','--edition=2021','-Awarnings',str(path),'-o',str(exe)],check=True,timeout=60)
 subprocess.run([str(exe)],check=True,timeout=30)
 results['scripted'].append(dict(program=name,cases=count,windows_observations=False))
mutations=[
 ('record','incomplete-word','837c241008','837c241004',0),
 ('record','crossing-word','8b43040103','8b43050103',0),
 ('record','oversize-read','6a085357','6a095357',0),
 ('record','opaque-field','8b43040103','8b4304892b',0),
 ('stream','stale-count','6a008d442414506a4057ff742428','6a008d442420506a4057ff742428',1),
]
for name,label,old,new,index in mutations:
 b=(out/(name+'.exe')).read_bytes();a=bytes.fromhex(old);v=bytes.fromhex(new);positions=[];start=0
 while (at:=b.find(a,start))!=-1:positions.append(at);start=at+1
 assert len(positions)==(2 if label=='stale-count' else 1),(label,positions)
 at=positions[index];changed=b[:at]+v+b[at+len(a):];pe=out/(label+'.exe');pe.write_bytes(changed);target=out/(label+'.rs');target.write_text('preserve')
 r=subprocess.run([str(repo/'target/debug/w2l'),str(pe),str(target)],capture_output=True,timeout=120)
 assert r.returncode==1 and target.read_text()=='preserve',(label,r.returncode,r.stderr)
 results['rejected'].append(dict(case=label,sha256=hashlib.sha256(changed).hexdigest(),diagnostic=r.stderr.decode()))
(out/'translation.json').write_text(json.dumps(results,indent=2)+'\n');print(results)
