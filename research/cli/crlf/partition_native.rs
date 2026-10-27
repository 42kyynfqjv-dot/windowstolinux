// Whole-sequence pair replacement is the independent oracle. The generated
// application runs through every partition of each short binary input.
#[path="generated.rs"] mod translated;
struct Io { data:Vec<u8>, chunks:Vec<usize>, at:usize, read:usize, write:usize, pipe:bool, output:Vec<u8> }
impl translated::StreamIo for Io {
 fn standard(&mut self,s:u32)->u32 {if s==0xfffffff6 {1}else{2}}
 fn read(&mut self,_:u32,b:&mut[u8])->Result<usize,u32> {
  if self.at==self.data.len(){return if self.pipe {Err(109)}else{Ok(0)}}
  let n=self.chunks[self.read];self.read+=1;assert!(n<=b.len());
  b[..n].copy_from_slice(&self.data[self.at..self.at+n]);self.at+=n;Ok(n)
 }
 fn write(&mut self,_:u32,b:&[u8])->Result<usize,u32> {let n=self.write.min(b.len());self.output.extend_from_slice(&b[..n]);Ok(n)}
}
fn expected(data:&[u8])->Vec<u8> {
 // Remove exactly those CR positions followed immediately by LF.
 data.iter().enumerate().filter_map(|(i,&b)|if b==13 && data.get(i+1)==Some(&10){None}else{Some(b)}).collect()
}
fn main(){
 let mut count=0;
 for len in 0usize..=5 { for code in 0..4usize.pow(len as u32) {
  let data:Vec<_>=(0..len).map(|i|[13,10,0,65][(code>>(2*i))&3]).collect();let expected=expected(&data);
  for mask in 0..(1usize<<len.saturating_sub(1)) {
   let mut chunks=Vec::new();let mut prev=0;
   for i in 1..=len {if i==len || mask&(1<<(i-1))!=0 {chunks.push(i-prev);prev=i;}}
   for pipe in [false,true] {
    let mut io=Io{data:data.clone(),chunks:chunks.clone(),at:0,read:0,write:1+count%3,pipe,output:vec![]};
    assert_eq!(translated::run(&mut io),0);assert_eq!(io.output,expected,"input={data:?} chunks={chunks:?} pipe={pipe}");count+=1;
   }
  }
 }}
 assert_eq!(count,37450);println!("{count}");
}
