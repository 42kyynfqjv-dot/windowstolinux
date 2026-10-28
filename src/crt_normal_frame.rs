//! Binding between the live normal-call registry and actual checked CRT stack.
//! This is a normal-path component boundary, not exception containment proof.
pub(crate) const EMITTED_TYPES: &str = r#"
#[derive(Clone,Debug,PartialEq,Eq)]
struct CrtNormalLayout {
 low:i32,bp:i32,record:i32,scope_slot:i32,level:i32,saved_sp:i32,guard:i32,
 saved:Vec<(i32,u8)>,scope:u32,handler:u32,cookie_address:u32,pop:u16,
}
struct CrtNormalBinding {
 anchor:guest_memory::Capability,identity:RegistryIdentity,epoch:u64,
 previous:RegistryHead,token:CrtThreadHead,caller:CrtPointer,entry:[CrtValue;8],return_id:u64,
 layout:CrtNormalLayout,cookie:u32,id:Option<NormalFrameId>,consumed:std::collections::BTreeSet<i32>,done:bool,
}
impl CrtNormalBinding {
 fn head_bits(head:RegistryHead)->[u64;3]{match head{
  RegistryHead::BorrowedRoot(_)=>[0,0,0],
  RegistryHead::BorrowedDispatcher{generation,..}=>[1,generation,0],
  RegistryHead::Owned(id)=>[2,id.generation,0],
  RegistryHead::Normal(id)=>[3,id.epoch,id.generation],
 }}
 fn bind(rt:&CrtStreamRuntime,cpu:&CrtCpu,epoch:&NormalCallEpoch<'_>,layout:CrtNormalLayout)->RegistryResult<Self>{
  epoch.state()?;let identity=epoch.registry.identity;let previous=epoch.head()?;
  let caller=CrtCpu::pointer(cpu.entry[4])?;
  if rt.owner!=identity.owner||rt.thread!=identity.instance||epoch.registry.cookie_address!=layout.cookie_address||rt.initialization.is_some()||rt.shutdown.is_some()||rt.closed
   ||cpu.returned||cpu.return_id==0||cpu.return_pop!=layout.pop||cpu.r[4]!=cpu.entry[4]
   ||caller.kind!=CrtRegionKind::Stack||caller.address()%4!=0
   ||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){
   return Err("CRT normal bind runtime/activation identity");
  }
  rt.valid(rt.offset(caller,i64::from(layout.low))?,u32::try_from(-i64::from(layout.low)+4+i64::from(layout.pop)).map_err(|_|"CRT normal frame extent")?)?;
  if rt.load(caller,32)?!=CrtValue::ProtectedReturn(cpu.return_id)
   ||rt.tags.values().filter(|v|**v==CrtValue::ProtectedReturn(cpu.return_id)).count()!=1{
   return Err("CRT normal unique caller return");
  }
  let cookie=rt.load(rt.resolve_absolute(layout.cookie_address,CrtRegionKind::Module)?,32)?.known_scalar()?;
  let token=rt.thread_head(identity.instance,epoch.generation,Self::head_bits(previous))?;
  Ok(Self{anchor:rt.anchor,identity,epoch:epoch.generation,previous,token,caller,entry:cpu.entry,
   return_id:cpu.return_id,layout,cookie,id:None,consumed:Default::default(),done:false})
 }
 fn authority(&self,rt:&CrtStreamRuntime,epoch:&NormalCallEpoch<'_>)->RegistryResult<()>{
  epoch.state()?;rt.validate_thread_head(self.token)?;
  if self.done||rt.anchor!=self.anchor||rt.owner!=self.identity.owner||rt.thread!=self.identity.instance
   ||epoch.registry.identity!=self.identity||epoch.generation!=self.epoch
   ||self.token.registry!=self.identity.instance||self.token.epoch!=self.epoch
   ||self.token.head!=Self::head_bits(self.previous)||rt.initialization.is_some()||rt.shutdown.is_some(){
   return Err("CRT normal stale epoch/arena/predecessor");
  }
  rt.valid(self.caller,4)?;
  if let Some(id)=self.id{epoch.top(id)?;}else if epoch.head()?!=self.previous{return Err("CRT normal predecessor no longer live");}
  Ok(())
 }
 fn at(&self,rt:&CrtStreamRuntime,offset:i32)->RegistryResult<CrtPointer>{rt.offset(self.caller,i64::from(offset))}
 fn saved(&self,register:u8)->CrtValue{match self.entry[register as usize]{CrtValue::Scalar{bits,known}=>CrtValue::Scalar{bits:bits&known,known},v=>v}}
 /// The projection is rebuilt from live words on every transition. Consumed
 /// saved words may be represented only by our exact POP receipt: storage must
 /// remain forgotten and the restored typed register must still match.
 fn image(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu,epoch:&NormalCallEpoch<'_>)->RegistryResult<FrameImage<RegistryHead>>{
  self.authority(rt,epoch)?;
  if cpu.entry!=self.entry||cpu.return_id!=self.return_id||cpu.returned||cpu.return_pop!=self.layout.pop{return Err("CRT normal changed CPU activation");}
  let l=&self.layout;let frame=self.at(rt,l.bp)?;let low=self.at(rt,l.low)?;let record=self.at(rt,l.record)?;
  if !self.consumed.contains(&l.bp)&&cpu.r[5]!=CrtValue::Pointer(frame){return Err("CRT normal actual frame pointer");}
  if rt.load(self.caller,32)?!=CrtValue::ProtectedReturn(self.return_id)
   ||rt.tags.values().filter(|v|**v==CrtValue::ProtectedReturn(self.return_id)).count()!=1
   ||rt.load(record,32)?!=CrtValue::ThreadHead(self.token)
   ||rt.load(self.at(rt,l.record+4)?,32)?.known_scalar()?!=l.handler
   ||rt.load(self.at(rt,l.scope_slot)?,32)?.known_scalar()?!=l.scope^self.cookie
   ||rt.load(self.at(rt,l.saved_sp)?,32)?!=CrtValue::Pointer(low)
   ||rt.load(rt.resolve_absolute(l.cookie_address,CrtRegionKind::Module)?,32)?.known_scalar()?!=self.cookie{
   return Err("CRT normal actual record/cookie/return changed");
  }
  let level=rt.load(self.at(rt,l.level)?,32)?.known_scalar()? as i32;
  // A body cannot hide another return/head in unused local storage and have
  // activation retirement silently consume it. Only the original owned words
  // (including exact saved opaque tags) may carry protected control values.
  for (&address,&value) in rt.tags.range(low.address()..=self.caller.address()){
   if matches!(value,CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)|CrtValue::OpaqueSaved(_)){
    let offset=(i64::from(address)-i64::from(self.caller.address())) as i32;
    let expected=if offset==0{Some(CrtValue::ProtectedReturn(self.return_id))}
     else if offset==l.record{Some(CrtValue::ThreadHead(self.token))}
     else{l.saved.iter().find(|&&(at,_)|at==offset).map(|&(_,r)|self.saved(r))};
    if expected!=Some(value)||self.consumed.contains(&offset){return Err("CRT normal extra protected alias in frame");}
   }
  }
  let mut words=std::collections::BTreeMap::from([
   (0,FrameWord::Return),(l.record,FrameWord::Borrowed(self.previous)),
   (l.record+4,FrameWord::Scalar(l.handler)),(l.scope_slot,FrameWord::EncodedScope{scope:l.scope,cookie:self.cookie,bits:l.scope^self.cookie}),
   (l.level,FrameWord::Scalar(level as u32)),(l.saved_sp,FrameWord::StackAddress(low.address())),
   (l.guard,FrameWord::Guard{frame:frame.address(),cookie:self.cookie,bits:frame.address()^self.cookie})]);
  for &(offset,register) in &l.saved{
   let value=self.saved(register);self.word(rt,cpu,offset,register,value)?;
   // Unknown or pointer bits cannot gain scalar knowledge in the registry.
   words.insert(offset,FrameWord::Saved(register,value.known_scalar().ok()));
  }
  self.word(rt,cpu,l.guard,1,CrtValue::scalar(frame.address()^self.cookie))?;
  Ok(FrameImage{entry_sp:self.caller.address(),ebp:frame.address(),esp:low.address(),record:record.address(),
   scope_va:l.scope,handler_va:l.handler,try_level:level,words})
 }
 fn word(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu,offset:i32,register:u8,value:CrtValue)->RegistryResult<()>{
  let actual=rt.load(self.at(rt,offset)?,32)?;
  if self.consumed.contains(&offset){
   if actual!=(CrtValue::Scalar{bits:0,known:0})||cpu.r[register as usize]!=value{return Err("CRT normal consumed word/register changed");}
  }else if actual!=value{return Err("CRT normal saved known-mask/type/guard changed");}Ok(())
 }
 fn install(&mut self,rt:&CrtStreamRuntime,cpu:&CrtCpu,epoch:&mut NormalCallEpoch<'_>,record:CrtPointer,token:CrtThreadHead)->RegistryResult<()>{
  if self.id.is_some()||record!=self.at(rt,self.layout.record)?||token!=self.token
   ||cpu.r[4]!=CrtValue::Pointer(self.at(rt,self.layout.low-4)?){return epoch.fail("CRT normal install record/token/replay");}
  let image=self.image(rt,cpu,epoch)?;
  let mut steps=vec![NormalFrameStep::RestorePredecessor,NormalFrameStep::DiscardGuard{offset:self.layout.guard,register:1}];
  let mut saved=self.layout.saved.clone();saved.sort_by_key(|&(offset,_)|offset);
  for(offset,register)in saved{steps.push(NormalFrameStep::PopSaved{offset,register});}
  let id=epoch.reserve_eh4(&image,NormalFramePlan{steps,callee_pop:u32::from(self.layout.pop)})?;
  self.id=Some(id);epoch.install_head(id,&image)
 }
 fn epilog_entry(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu,epoch:&NormalCallEpoch<'_>)->RegistryResult<()>{
  let image=self.image(rt,cpu,epoch)?;let id=self.id.ok_or("CRT normal epilog before installation")?;
  epoch.validate_image(id,&image)?;
  if epoch.head()?!=RegistryHead::Normal(id)||!self.consumed.is_empty()||image.try_level!= -2
   ||cpu.r[4]!=CrtValue::Pointer(self.at(rt,self.layout.low)?){return Err("CRT normal epilog scope/stack/head");}Ok(())
 }
 fn load_previous(&self,rt:&CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&NormalCallEpoch<'_>,register:u8)->RegistryResult<()>{
  self.epilog_entry(rt,cpu,epoch)?;cpu.set(register as usize,32,0,rt.load(self.at(rt,self.layout.record)?,32)?)
 }
 fn unlink(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu,epoch:&mut NormalCallEpoch<'_>,register:u8)->RegistryResult<()>{
  let image=self.image(rt,cpu,epoch)?;
  if cpu.r[register as usize]!=CrtValue::ThreadHead(self.token){return epoch.fail("CRT normal original FS source");}
  epoch.restore_previous_head(self.id.ok_or("CRT normal missing frame")?,&image)
 }
 fn pop(&mut self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>,offset:i32,register:u8)->RegistryResult<()>{
  let image=self.image(rt,cpu,epoch)?;let id=self.id.ok_or("CRT normal missing frame")?;
  if cpu.r[4]!=CrtValue::Pointer(self.at(rt,offset)?)||self.consumed.contains(&offset){return epoch.fail("CRT normal POP actual slot/order");}
  let value=rt.load(self.at(rt,offset)?,32)?;
  if offset==self.layout.guard{epoch.discard_guard(id,&image,offset,register)?;}else{epoch.restore_saved(id,&image,offset,register)?;}
  let popped=cpu.pop(rt)?;if popped!=value{return epoch.fail("CRT normal POP changed value");}
  cpu.set(register as usize,32,0,popped)?;self.consumed.insert(offset);Ok(())
 }
 fn leave(&mut self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>)->RegistryResult<()>{
  let image=self.image(rt,cpu,epoch)?;let id=self.id.ok_or("CRT normal missing frame")?;
  let bp=self.at(rt,self.layout.bp)?;
  if cpu.r[5]!=CrtValue::Pointer(bp)||cpu.r[4]!=CrtValue::Pointer(self.at(rt,self.layout.guard+16)?){return epoch.fail("CRT normal LEAVE stack/frame");}
  epoch.restore_saved(id,&image,self.layout.bp,5)?;cpu.leave(rt)?;self.consumed.insert(self.layout.bp);Ok(())
 }
 fn finish(&mut self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>)->RegistryResult<CrtValue>{
  let image=self.image(rt,cpu,epoch)?;let id=self.id.ok_or("CRT normal missing frame")?;
  if cpu.r[4]!=CrtValue::Pointer(self.caller)||self.consumed.len()!=self.layout.saved.len()+1{return epoch.fail("CRT normal incomplete native epilog");}
  // Validate registry order before allowing the original RET effects. There
  // are no external callbacks between this projection and the retirement.
  let f=epoch.top(id)?;
  if !f.unlinked||f.next!=f.plan.steps.len()||epoch.head()?!=self.previous{return epoch.fail("CRT normal incomplete registry epilog");}
  let low=self.at(rt,self.layout.low)?.address();let high=self.caller.address();
  let escapes=|v:CrtValue|matches!(v,CrtValue::Pointer(p)if p.cap==self.caller.cap&&p.address>=low&&p.address<high);
  if cpu.r.iter().copied().any(escapes)||rt.tags.iter().any(|(&at,&v)|(at<low||at>=high)&&escapes(v)){
   return epoch.fail("CRT normal escaping frame-local pointer");
  }
  let value=cpu.finish_pop(rt,self.layout.pop)?;
  let caller_sp=CrtCpu::pointer(cpu.r[4])?.address();epoch.return_to_caller(id,&image,caller_sp)?;
  // End this activation's storage lifetime after RET. This forgets facts;
  // it is not a synthesized guest store or erasure of external effects.
  for offset in (self.layout.low..0).step_by(4){let p=self.at(rt,offset)?;let old=rt.load(p,32)?;rt.consume_stack(p,old)?;}
  self.done=true;Ok(value)
 }
}
"#;
