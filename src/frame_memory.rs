//! Byte access to the existing owned frame image. Generated private support;
//! layout authority comes from the original prolog proof, never guest input.
pub(crate) const EMITTED_TYPES: &str = r#"
#[derive(Clone,Copy)]
struct GuestModule { owner:u64, base:u32 }
struct FrameMemory<'a,P> {
 image:&'a mut FrameImage<P>, owner:u64,
 ordinary:std::collections::BTreeSet<i32>, lower:u32,
}
impl<'a,P> FrameMemory<'a,P> {
 fn new(image:&'a mut FrameImage<P>,owner:u64,ordinary:&[i32])->Result<Self,&'static str>{
  if owner==0 {return Err("frame memory owner");}
  let mut slots=std::collections::BTreeSet::new();
  for &offset in ordinary {
   let key=Self::key_for(image,offset)?;
   if !slots.insert(offset) || offset%4!=0 || (image.record..image.record.checked_add(16).ok_or("record extent")?).contains(&frame_address(image.ebp,offset)?) {
    return Err("frame memory ordinary layout");
   }
   match image.words.get(&key) {
    Some(FrameWord::Unknown|FrameWord::Scalar(_)|FrameWord::Bytes(_)|FrameWord::StackAddress(_)|FrameWord::ModuleBase{..}|FrameWord::Continuation(_))=>{},
    _=>return Err("frame memory protected layout"),
   }
  }
  let lower=frame_address(image.entry_sp,*image.words.keys().next().ok_or("empty frame")?)?;
  Ok(Self{image,owner,ordinary:slots,lower})
 }
 fn key_for(image:&FrameImage<P>,offset:i32)->Result<i32,&'static str>{
  let key=i64::from(image.ebp)-i64::from(image.entry_sp)+i64::from(offset);
  i32::try_from(key).map_err(|_|"frame relative offset overflow")
 }
 fn key(&self,offset:i32)->Result<i32,&'static str>{Self::key_for(self.image,offset)}
 fn ordinary_key(&self,offset:i32)->Result<i32,&'static str>{
  if offset%4!=0 || !self.ordinary.contains(&offset) {return Err("frame memory protected word");}
  self.key(offset)
 }
 fn frame_pointer(&self)->u32{self.image.ebp}
 fn stack_pointer(&self)->u32{self.image.esp}
 fn preflight_call_stack(&self,bytes:u32)->Result<(),&'static str>{
  // Temporary original call storage is below the allocated frame. Its writable
  // thread ownership is an explicit valid-stack entry premise; numeric wrap
  // and overlap with this frame are still rejected here.
  if bytes==0 || bytes>128 || bytes%4!=0 || self.image.esp.checked_sub(bytes).is_none_or(|p|p==0) {
   return Err("frame temporary call stack");
  } Ok(())
 }
 fn stack_address(&self,address:u32)->Result<(),&'static str>{
  if address%4!=0 || address<self.lower || address>self.image.ebp {return Err("frame stack address");} Ok(())
 }
 fn set_stack_pointer(&mut self,address:u32)->Result<(),&'static str>{
  self.stack_address(address)?;self.image.esp=address;Ok(())
 }
 fn read_u32(&self,offset:i32)->Result<u32,&'static str>{
  let key=self.ordinary_key(offset)?;
  match self.image.words.get(&key){
   Some(FrameWord::Scalar(n))=>Ok(*n),
   Some(FrameWord::Bytes(b))=>Ok(u32::from_le_bytes([b[0].ok_or("unknown frame byte")?,b[1].ok_or("unknown frame byte")?,b[2].ok_or("unknown frame byte")?,b[3].ok_or("unknown frame byte")?])),
   _=>Err("frame scalar initialization/type"),
  }
 }
 fn write_u32(&mut self,offset:i32,value:u32)->Result<(),&'static str>{
  let key=self.ordinary_key(offset)?;
  self.image.words.insert(key,FrameWord::Scalar(value));Ok(())
 }
 fn read_stack(&self,offset:i32)->Result<u32,&'static str>{
  if offset%4!=0{return Err("frame stack word alignment");}
  match self.image.words.get(&self.key(offset)?){
   Some(FrameWord::StackAddress(address))=>{self.stack_address(*address)?;Ok(*address)},
   _=>Err("frame stack pointer provenance"),
  }
 }
 fn write_stack(&mut self,offset:i32,address:u32)->Result<(),&'static str>{
  let key=self.ordinary_key(offset)?;self.stack_address(address)?;
  self.image.words.insert(key,FrameWord::StackAddress(address));Ok(())
 }
 fn write_module(&mut self,offset:i32,module:GuestModule)->Result<(),&'static str>{
  let key=self.ordinary_key(offset)?;
  if module.owner!=self.owner || module.base==0 || module.base%4096!=0 {return Err("frame module identity");}
  self.image.words.insert(key,FrameWord::ModuleBase{owner:module.owner,base:module.base});Ok(())
 }
 fn read_module(&self,offset:i32)->Result<u32,&'static str>{
  let key=self.ordinary_key(offset)?;
  match self.image.words.get(&key){Some(FrameWord::ModuleBase{owner,base}) if *owner==self.owner=>Ok(*base),_=>Err("frame module provenance")}
 }
 fn write_continuation(&mut self,offset:i32,target:u32)->Result<(),&'static str>{
  let key=self.ordinary_key(offset)?;
  if target==0 {return Err("frame continuation address");}
  // Only mechanically proved original target stores call this private method.
  self.image.words.insert(key,FrameWord::Continuation(target));Ok(())
 }
 fn read_continuation(&self,offset:i32)->Result<u32,&'static str>{
  let key=self.ordinary_key(offset)?;
  match self.image.words.get(&key){Some(FrameWord::Continuation(target))=>Ok(*target),_=>Err("frame continuation provenance")}
 }
 fn write_try_level(&mut self,value:i32)->Result<(),&'static str>{
  let address=self.image.record.checked_add(12).ok_or("frame record overflow")?;
  let key=i32::try_from(i64::from(address)-i64::from(self.image.entry_sp)).map_err(|_|"frame record relative offset")?;
  if !matches!(self.image.words.get(&key),Some(FrameWord::Scalar(_))){return Err("frame TryLevel type");}
  self.image.words.insert(key,FrameWord::Scalar(value as u32));self.image.try_level=value;Ok(())
 }
 fn read_guard(&self,offset:i32)->Result<(u32,u32,u32),&'static str>{
  match self.image.words.get(&self.key(offset)?){Some(FrameWord::Guard{frame,cookie,bits})=>Ok((*frame,*cookie,*bits)),_=>Err("frame guard provenance")}
 }
 fn fill(&mut self,offset:i32,length:u32,value:u8)->Result<(),&'static str>{
  if length>16384{return Err("frame fill budget");}
  let end=i64::from(offset)+i64::from(length);
  if end>i64::from(i32::MAX) {return Err("frame fill overflow");}
  // Preflight complete range and existing types before any observable write.
  let mut changes=std::collections::BTreeMap::new();
  for byte in i64::from(offset)..end {
   let at=i32::try_from(byte).map_err(|_|"frame byte offset")?;
   let word=at.div_euclid(4)*4;
   let key=self.ordinary_key(word)?;
   changes.entry(key).or_insert_with(||[None;4]);
  }
  for (&key,bytes) in changes.iter_mut(){
   *bytes=match self.image.words.get(&key){
    Some(FrameWord::Unknown)=>[None;4],
    Some(FrameWord::Scalar(n))=>n.to_le_bytes().map(Some),
    Some(FrameWord::Bytes(b))=>*b,
    _=>return Err("frame fill would erase pointer provenance"),
   };
  }
  for byte in i64::from(offset)..end {
   let at=byte as i32;let key=self.key(at.div_euclid(4)*4)?;
   changes.get_mut(&key).ok_or("frame fill preflight")?[at.rem_euclid(4) as usize]=Some(value);
  }
  for (key,b) in changes {
   let word=match b { [Some(a),Some(b),Some(c),Some(d)]=>FrameWord::Scalar(u32::from_le_bytes([a,b,c,d])),_=>FrameWord::Bytes(b)};
   self.image.words.insert(key,word);
  }
  Ok(())
 }
}
"#;

#[cfg(test)]
mod tests {
    #[test]
    fn emitted_byte_storage_preserves_unknowns_protected_tags_and_identity() {
        let source = format!(
            r#"#![allow(dead_code)]
{}
{}
fn main(){{
 use std::collections::BTreeMap;
 let mut words=BTreeMap::new();
 for offset in (-64..-28).step_by(4){{words.insert(offset,FrameWord::Unknown);}}
 words.insert(-28,FrameWord::Guard{{frame:0x10000,cookie:0x1234,bits:0x11234}});
 words.insert(-24,FrameWord::StackAddress(0xffc0));
 words.insert(-20,FrameWord::Unknown);
 words.insert(-16,FrameWord::Borrowed("original predecessor"));
 words.insert(-12,FrameWord::Scalar(0x401000));
 words.insert(-8,FrameWord::EncodedScope{{scope:0x402000,cookie:0x1234,bits:0x403234}});
 words.insert(-4,FrameWord::Scalar(u32::MAX-1));
 let mut image=FrameImage{{words,entry_sp:0x10000,ebp:0x10000,esp:0xffc0,record:0xfff0,scope_va:0x402000,handler_va:0x401000,try_level:-2}};
 let ordinary:Vec<_>=(-64..-28).step_by(4).chain([-20]).collect();
 let mut memory=FrameMemory::new(&mut image,7,&ordinary).unwrap();
 memory.fill(-64,1,0x11).unwrap();assert!(memory.read_u32(-64).is_err());
 memory.fill(-63,3,0x22).unwrap();assert_eq!(memory.read_u32(-64).unwrap(),0x22222211);
 memory.write_u32(-32,0x99887766).unwrap();
 assert!(memory.fill(-32,5,0).is_err());assert_eq!(memory.read_u32(-32).unwrap(),0x99887766);
 assert_eq!(memory.read_guard(-28).unwrap(),(0x10000,0x1234,0x11234));
 assert!(memory.write_u32(-24,0).is_err());assert_eq!(memory.read_stack(-24).unwrap(),0xffc0);
 memory.write_stack(-60,0x10000).unwrap();assert!(memory.read_u32(-60).is_err());
 assert!(memory.fill(-64,8,0).is_err());assert_eq!(memory.read_u32(-64).unwrap(),0x22222211);
 assert!(memory.write_module(-56,GuestModule{{owner:8,base:0x400000}}).is_err());
 assert!(memory.read_u32(-56).is_err());
 memory.write_module(-56,GuestModule{{owner:7,base:0x400000}}).unwrap();assert_eq!(memory.read_module(-56).unwrap(),0x400000);
 assert!(memory.read_u32(-56).is_err());
 memory.write_continuation(-52,0x401234).unwrap();assert_eq!(memory.read_continuation(-52).unwrap(),0x401234);
 assert!(memory.write_stack(-48,0xffbc).is_err());assert!(memory.set_stack_pointer(0x10004).is_err());
 memory.write_try_level(0).unwrap();assert_eq!(memory.image.try_level,0);
 assert!(matches!(memory.image.words.get(&-16),Some(FrameWord::Borrowed("original predecessor"))));
}}
"#,
            super::super::frame_proof::EMITTED_TYPES,
            super::EMITTED_TYPES
        );
        let directory =
            std::env::temp_dir().join(format!("w2l-frame-memory-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("main.rs");
        std::fs::write(&path, source).unwrap();
        let output = directory.join(if cfg!(windows) { "main.exe" } else { "main" });
        let result = std::process::Command::new("rustc")
            .args(["--edition=2021"])
            .arg(&path)
            .arg("-o")
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(std::process::Command::new(output)
            .status()
            .unwrap()
            .success());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
