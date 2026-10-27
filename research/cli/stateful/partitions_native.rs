// Independent whole-sequence oracles; actual emitted code uses chosen backend partitions.
#[path="generated.rs"] mod translated;
const FAMILY:&str="FILTER";
struct Io {data:Vec<u8>,chunks:Vec<usize>,at:usize,read:usize,write:usize,pipe:bool,output:Vec<u8>}
impl translated::StreamIo for Io {
 fn standard(&mut self,s:u32)->u32 {if s==0xfffffff6 {1}else{2}}
 fn read(&mut self,_:u32,b:&mut[u8])->Result<usize,u32> {
  if self.at==self.data.len(){return if self.pipe {Err(109)}else{Ok(0)}}
  let n=self.chunks[self.read];self.read+=1;assert!(n<=b.len());b[..n].copy_from_slice(&self.data[self.at..self.at+n]);self.at+=n;Ok(n)
 }
 fn write(&mut self,_:u32,b:&[u8])->Result<usize,u32>{let n=self.write.min(b.len());self.output.extend_from_slice(&b[..n]);Ok(n)}
}
fn expected(data:&[u8])->Vec<u8>{
 if FAMILY=="fold" {return data.iter().enumerate().filter_map(|(i,&b)|if b==13 && data.get(i+1)==Some(&10) {None}else{Some(b.to_ascii_uppercase())}).collect()}
 if FAMILY=="tabs" {
  let mut out=Vec::new();let mut column=0usize;
  for &b in data {if b==9 {let target=(column/4+1)*4;out.resize(out.len()+target-column,32);column=target;}else{out.push(b);column=if b==10 || b==13 {0}else{column+1};}}
  return out;
 }
 let mut out=Vec::new();let mut i=0;while i<data.len(){if data[i]==92 && i+1<data.len(){i+=1;out.push(data[i]);}else if data[i]!=124 {out.push(data[i]);}i+=1;}out
}
fn main(){
 let alphabet=match FAMILY {"fold"=>[13,10,0,97],"tabs"=>[9,13,10,255],_=>[92,124,0,255]};let mut count=0;
 for len in 0usize..=5 {for code in 0..4usize.pow(len as u32){
  let data:Vec<_>=(0..len).map(|i|alphabet[(code>>(2*i))&3]).collect();let want=expected(&data);
  for mask in 0..1usize<<len.saturating_sub(1){let mut chunks=Vec::new();let mut prev=0;
   for i in 1..=len {if i==len || mask&(1<<(i-1))!=0 {chunks.push(i-prev);prev=i;}}
   for pipe in [false,true]{let mut io=Io{data:data.clone(),chunks:chunks.clone(),at:0,read:0,write:1+count%7,pipe,output:vec![]};assert_eq!(translated::run(&mut io),0);assert_eq!(io.output,want,"data={data:?} chunks={chunks:?}");count+=1;}
  }
 }}
 assert_eq!(count,37450);
 // Long maximum expansion and state/reset boundaries, independent chunk schedules.
 for data in [vec![9;4097],(0..4097).map(|i|[9,9,13,9,10,255,92,124,97][i%9]).collect(),(0..4097).map(|i|(i%256)as u8).collect()] {
  let want=expected(&data);
  for seed in 0..8usize {let mut chunks=Vec::new();let mut n=data.len();let mut k=seed;while n>0 {let take=(1+(k*17+seed)%64).min(n);chunks.push(take);n-=take;k+=1;}
   for pipe in [false,true]{let mut io=Io{data:data.clone(),chunks:chunks.clone(),at:0,read:0,write:1+seed*7,pipe,output:vec![]};assert_eq!(translated::run(&mut io),0);assert_eq!(io.output,want);count+=1;}
  }
 }
 assert_eq!(count,37498);println!("{count}");
}
