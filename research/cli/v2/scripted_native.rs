// Harness around mechanically emitted application blocks. These substituted
// backends are labelled separately from real Windows/ELF I/O comparisons.
#[path = "generated.rs"]
mod translated;
use translated::StreamIo;
struct Script { mode:u8, at:usize, output:Vec<u8>, reads:usize, writes:usize }
impl StreamIo for Script {
 fn standard(&mut self,s:u32)->u32{assert!([0xfffffff6,0xfffffff5].contains(&s));if self.mode==1{0}else if s==0xfffffff6{1}else{2}}
 fn read(&mut self,h:u32,b:&mut[u8])->Result<usize,u32>{assert_eq!(h,1);assert_eq!(b.len(),256);self.reads+=1;
  if self.mode==2{return Err(5)}if self.mode==9{return Err(109)}
  if self.at==4{return match self.mode{7=>Err(109),8=>Err(5),_=>Ok(0)}}
  let data=[97,90,0,255];let n=if self.at==1{2}else{1};b[..n].copy_from_slice(&data[self.at..self.at+n]);self.at+=n;Ok(n)
 }
 fn write(&mut self,h:u32,b:&[u8])->Result<usize,u32>{assert_eq!(h,2);self.writes+=1;if self.mode==3{return Err(5)}if self.mode==4{return Ok(0)}assert!(!b.is_empty());self.output.push(b[0]);Ok(1)}
}
fn main(){
 for mode in [0,1,2,3,4,7,8,9]{let mut s=Script{mode,at:0,output:vec![],reads:0,writes:0};let code=translated::run(&mut s);
  if [0,7,8].contains(&mode){assert_eq!(s.output,[65,90,0,255]);}else{assert!(s.output.is_empty());}
  println!("{} {} {} {} {}",mode,code,s.reads,s.writes,s.output.len());
 }
}
