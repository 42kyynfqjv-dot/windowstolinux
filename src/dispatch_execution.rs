//! Private effects for instruction-derived local unwind. The compiler binds
//! every callback and its closed, valid-memory effects before emission.
pub(crate) const EMITTED_TYPES: &str = r#"
#[derive(Clone,Debug,PartialEq,Eq)]
enum DispatchCapability {
 Frame { owner:u64, index:usize, binding:OwnedFrameBinding },
 Code { owner:u64, frame:usize, address:u32 },
 Exception { owner:u64, event:u32 },
}
type DispatchPacket=[BridgeValue<DispatchCapability>;8];
fn unknown_packet()->DispatchPacket{std::array::from_fn(|_|BridgeValue::Unknown)}
fn call_return(mut registers:DispatchPacket,bytes:u32)->Result<DispatchPacket,&'static str>{
 let BridgeValue::PrivateStack(sp)=registers[4] else{return Err("dispatch callee stack type");};
 registers[4]=BridgeValue::PrivateStack(sp.checked_add(i32::try_from(bytes).map_err(|_|"dispatch return extent")?).ok_or("dispatch return overflow")?);
 Ok(registers)
}
struct NotificationState {
 owner:u64,addresses:[u32;3],words:[BridgeValue<DispatchCapability>;3],
 writes:Vec<(u32,BridgeValue<DispatchCapability>)>,
}
impl NotificationState {
 fn new(owner:u64,addresses:[u32;3])->Result<Self,&'static str>{
  if owner==0||addresses.iter().any(|a|*a==0||a%4!=0||a.checked_add(4).is_none())
   ||addresses[0]==addresses[1]||addresses[0]==addresses[2]||addresses[1]==addresses[2]{return Err("notification word identity");}
  Ok(Self{owner,addresses,words:std::array::from_fn(|_|BridgeValue::Unknown),writes:Vec::new()})
 }
 fn store(&mut self,address:u32,value:&BridgeValue<DispatchCapability>)->Result<(),&'static str>{
  let slot=self.addresses.iter().position(|a|*a==address).ok_or("notification unbound module word")?;
  match(slot,value){
   (0,BridgeValue::Scalar(1|0x101))=>{},
   (1,BridgeValue::Capability(DispatchCapability::Code{owner,..}))if *owner==self.owner=>{},
   (2,BridgeValue::Capability(DispatchCapability::Frame{owner,binding,..}))if *owner==self.owner&&binding.owner()==self.owner=>{},
   _=>return Err("notification value provenance"),
  }
  if self.writes.len()>=4096{return Err("notification effect budget");}
  self.words[slot]=value.clone();self.writes.push((address,value.clone()));Ok(())
 }
 fn require(&self,owner:u64,frame:usize,binding:OwnedFrameBinding,target:u32,reason:u32)->Result<(),&'static str>{
  let expected=[BridgeValue::Scalar(reason),BridgeValue::Capability(DispatchCapability::Code{owner,frame,address:target}),BridgeValue::Capability(DispatchCapability::Frame{owner,index:frame,binding})];
  if self.owner!=owner||self.words!=expected{return Err("notification preceding original stores");}Ok(())
 }
}
struct OriginalLocal<'a,'r,F,N> {
 record:&'a mut LocalRecord<'r>,image:&'a mut FrameImage<RegistryHead>,
 owner:u64,frame:usize,binding:OwnedFrameBinding,ordinary:&'a[i32],
 scope_address:u32,rows:&'a[LocalScope],
 pending:Option<(i32,LocalScope)>,written:bool,notified:bool,
 finally:F,notification:N,
}
impl<F,N> LocalUnwindEffects for OriginalLocal<'_, '_,F,N>
where F:FnMut(u32,i32,&mut FrameImage<RegistryHead>)->Result<(),&'static str>,
 N:FnMut(u32,u32)->Result<(),&'static str> {
 fn install_temporary(&mut self,below_entry:u32,handler:u32)->Result<(),&'static str>{self.record.install_head(below_entry,handler)}
 fn restore_previous_head(&mut self)->Result<(),&'static str>{self.record.restore_previous_head()}
 fn decode_scope(&mut self)->Result<(),&'static str>{
  self.record.validate_binding(self.binding,self.image)?;
  if self.image.scope_va!=self.scope_address||self.binding.owner()!=self.owner||self.binding.frame_index()!=self.frame{return Err("local scope/frame authority");}
  let key=i32::try_from(i64::from(self.image.record)+8-i64::from(self.image.entry_sp)).map_err(|_|"local encoded scope range")?;
  match self.image.words.get(&key){Some(FrameWord::EncodedScope{scope,cookie,bits})if *scope==self.scope_address&&*bits==(*scope^*cookie)=>Ok(()),_=>Err("local encoded scope provenance")}
 }
 fn read_try_level(&mut self)->Result<i32,&'static str>{
  let key=i32::try_from(i64::from(self.image.record)+12-i64::from(self.image.entry_sp)).map_err(|_|"local TryLevel range")?;
  match self.image.words.get(&key){Some(FrameWord::Scalar(level))if *level as i32==self.image.try_level=>Ok(*level as i32),_=>Err("local TryLevel initialized identity")}
 }
 fn scope_row(&mut self,level:i32)->Result<LocalScope,&'static str>{
  if level!=self.read_try_level()?{return Err("local stale scope cursor");}
  let row=*self.rows.get(usize::try_from(level).map_err(|_|"local negative scope")?).ok_or("local full scope row range")?;
  self.pending=Some((level,row));self.written=false;self.notified=false;Ok(row)
 }
 fn write_try_level(&mut self,parent:i32)->Result<(),&'static str>{
  let Some((level,row))=self.pending else{return Err("local parent before scope read");};
  if row.parent!=parent||self.written||self.read_try_level()?!=level{return Err("local parent transition");}
  FrameMemory::new(self.image,self.owner,self.ordinary)?.write_try_level(parent)?;self.written=true;Ok(())
 }
 fn notify(&mut self,handler:u32,reason:u32)->Result<(),&'static str>{
  let Some((_,row))=self.pending else{return Err("local notify scope");};
  if !self.written||row.filter!=0||row.handler!=handler||reason!=0x101{return Err("local notification authority/order");}
  (self.notification)(handler,reason)?;self.notified=true;Ok(())
 }
 fn invoke_finally(&mut self,handler:u32,abnormal:u32)->Result<(),&'static str>{
  let Some((level,row))=self.pending else{return Err("local finally scope");};
  if !self.written||!self.notified||row.filter!=0||row.handler!=handler||abnormal!=1||self.read_try_level()?!=row.parent{return Err("local finally authority/order");}
  (self.finally)(handler,level,self.image)?;self.pending=None;self.written=false;self.notified=false;Ok(())
 }
 // The compiler emits this adapter only for the ordinary local body with
 // closed non-raising callbacks. Other original entries need their own proof.
 fn local_unwind(&mut self,_:i32)->Result<(),&'static str>{Err("local wrapper requires its bound body adapter")}
 fn check_temporary_cookie(&mut self)->Result<(),&'static str>{Err("nested entry requires containment proof")}
 fn reenter_local_unwind(&mut self)->Result<(),&'static str>{Err("nested entry requires containment proof")}
 fn write_collided_record(&mut self)->Result<(),&'static str>{Err("nested entry requires containment proof")}
}
"#;

#[cfg(test)]
#[path = "dispatch_execution_tests.rs"]
mod tests;
