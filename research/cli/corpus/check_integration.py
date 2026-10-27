"""Independent emitted-program backend cases and unsafe original-byte mutations."""
import json,re,struct,subprocess,tempfile
from pathlib import Path
import sys
root=Path(sys.argv[1]).resolve();repo=Path(__file__).resolve().parents[3]
report=json.loads((root/'report.json').read_text());assert len(report['programs'])==6 and all(x['conversion']['exit']==0 for x in report['programs'])
records=[]
def run(cmd,**kw):return subprocess.run(cmd,capture_output=True,timeout=35,**kw)
payload=bytes(range(256))*3+b'a\0NZm'
with tempfile.TemporaryDirectory() as td:
 d=Path(td)
 for row in report['programs']:
  stem=row['name']+'_'+row['config'];source=(root/(stem+'.rs')).read_bytes();(d/'generated.rs').write_bytes(source)
  if row['name']=='rot13':expected=payload.translate(bytes.maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',b'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
  elif row['name']=='xor':expected=bytes(x^90 for x in payload)
  else:expected=payload.replace(b'\0',b'')
  code='''#[path="generated.rs"] mod g;
struct Io { input:Vec<u8>, output:Vec<u8>, pos:usize, read:usize, write:usize, error:Option<u32> }
impl g::StreamIo for Io {
 fn standard(&mut self,s:u32)->u32 {if s==0xfffffff6 {1}else{2}}
 fn read(&mut self,_:u32,b:&mut[u8])->Result<usize,u32>{if let Some(e)=self.error{return Err(e)}let n=self.read.min(b.len()).min(self.input.len()-self.pos);if n==0{return Err(109)}b[..n].copy_from_slice(&self.input[self.pos..self.pos+n]);self.pos+=n;Ok(n)}
 fn write(&mut self,_:u32,b:&[u8])->Result<usize,u32>{let n=self.write.min(b.len());self.output.extend_from_slice(&b[..n]);Ok(n)}
}
fn main(){
 for e in [0,1,108,109,110,0x7fffffff,0x80000000,0xffffffff] {let mut io=Io{input:vec![],output:vec![],pos:0,read:1,write:1,error:Some(e)};assert_eq!(g::run(&mut io),if e==109{0}else{11});assert!(io.output.is_empty());}
 for (r,w) in [(1,1),(7,3),(129,2),(400,17)] {let mut io=Io{input:vec![PAYLOAD],output:vec![],pos:0,read:r,write:w,error:None};assert_eq!(g::run(&mut io),0);assert_eq!(io.output,vec![EXPECTED]);}
}
'''.replace('PAYLOAD',','.join(map(str,payload))).replace('EXPECTED',','.join(map(str,expected)))
  (d/'check.rs').write_text(code);p=run(['rustc','--edition=2021',str(d/'check.rs'),'-o',str(d/'check')]);assert p.returncode==0,p.stderr
  p=run([str(d/'check')]);assert p.returncode==0 and not p.stderr,p.stderr
  records.append(dict(program=stem,scripted_error_classes=8,scripted_partial_io=4))
  original=(root/(stem+'.exe')).read_bytes();pe=struct.unpack_from('<I',original,60)[0];table=pe+24+224;raw=struct.unpack_from('<I',original,table+20)[0]
  dis=(root/(stem+'-disasm.txt')).read_text(errors='replace');specs=[]
  # Assert original bytes; mutate only separate negative copies, never baselines.
  at=original.find(b'\x83\xe8\x6d',raw);assert at>=raw and original.find(b'\x83\xe8\x6d',at+1)==-1
  specs.append(('wrong-error-class',at+2,109,108))
  if row['name']=='xor':
   match=re.search(r'([0-9A-F]{8}):\s+(4[89])\s+dec',dis);assert match
   offset=raw+int(match[1],16)-0x401000;old=int(match[2],16);specs.append(('reverse-loop-becomes-increment',offset,old,old-8))
  if row['name']=='compact':
   matches=re.findall(r'([0-9A-F]{8}):\s+72\s+[0-9A-F]{2}\s+jb\s+([0-9A-F]{8})',dis)
   pc,target=next((int(a,16),int(b,16)) for a,b in matches if int(b,16)<int(a,16));specs.append(('inclusive-compaction-read',raw+pc-0x401000,0x72,0x76))
  for name,at,old,new in specs:
   assert original[at]==old;changed=bytearray(original);changed[at]=new;(d/'unsafe.exe').write_bytes(changed);(d/'unsafe.rs').write_text('preserve')
   p=run([str(repo/'target/debug/w2l'),str(d/'unsafe.exe'),str(d/'unsafe.rs')]);assert p.returncode==1 and (d/'unsafe.rs').read_text()=='preserve',(stem,name,p.stderr)
   records.append(dict(program=stem,rejection=name,diagnostic=p.stderr.decode(errors='replace')))
(root/'integration.json').write_text(json.dumps(records,indent=2)+'\n');print('6 emitted programs:48 scripted error classes +24 forced partial-I/O runs;10 unsafe mutations rejected')
