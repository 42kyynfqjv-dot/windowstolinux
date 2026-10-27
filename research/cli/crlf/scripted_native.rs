// Independent backend schedules around mechanically emitted application code.
// Expected bytes are frozen separately in probe-expectations.json.
#[path="generated.rs"] mod translated;
struct Io { data:Vec<u8>, output:Vec<u8>, pos:usize, mode:usize, reads:usize, writes:usize }
impl translated::StreamIo for Io {
 fn standard(&mut self,s:u32)->u32 { match s {0xfffffff6=>1,0xfffffff5=>2,_=>panic!("selector")} }
 fn read(&mut self,h:u32,b:&mut[u8])->Result<usize,u32> {
  assert_eq!(h,1);self.reads+=1;
  if self.mode==20 || (self.mode==21 && self.pos>=1) { return Err(1117) }
  let chunk=if self.mode<20 {[1,2,3,127,128][self.mode/4]}else if self.mode==21 {1}else{128};
  let n=chunk.min(b.len()).min(self.data.len()-self.pos);
  if n==0 && self.mode<20 && self.mode%2==1 {return Err(109)}
  b[..n].copy_from_slice(&self.data[self.pos..self.pos+n]);self.pos+=n;Ok(n)
 }
 fn write(&mut self,h:u32,b:&[u8])->Result<usize,u32> {
  assert_eq!(h,2);self.writes+=1;
  if self.mode==22 && self.output.len()>=2 {return Err(1117)}
  if self.mode==23 {return Ok(0)}
  let chunk=if self.mode<20 && (self.mode/2)%2==1 {7}else{1};
  let mut n=chunk.min(b.len());if self.mode==22 {n=n.min(2-self.output.len());}
  self.output.extend_from_slice(&b[..n]);Ok(n)
 }
}
fn main(){
 for mode in 0..24 {
  let data=[vec![13,65,13,10,0,10],(0..=255).collect(),(0..=255).collect(),vec![13]].concat();
  let mut io=Io{data,output:vec![],pos:0,mode,reads:0,writes:0};let code=translated::run(&mut io);
  let hex:String=io.output.iter().map(|b|format!("{b:02x}")).collect();
  println!("{mode} {code} {} {} {hex}",io.reads,io.writes);
 }
}
