//! Binding between the live normal-call registry and actual checked CRT stack.
//! This is a normal-path component boundary, not exception containment proof.
/// Exact instruction proof for a separately established RaiseException import.
/// Import identity must come from the enclosing image proof, never an address
/// guessed from disassembly. This certificate proves only the CALL encoding.
pub(crate) struct NormalRaiseCallProof {
    instruction: u32,
    continuation: u32,
    iat: u32,
}
impl NormalRaiseCallProof {
    pub(crate) fn prove(bytes: &[u8], instruction: u32, iat: u32) -> Result<Self, String> {
        let continuation = instruction
            .checked_add(6)
            .ok_or("normal raise instruction overflow")?;
        let iat_end = iat.checked_add(4).ok_or("normal raise IAT overflow")?;
        if instruction == 0
            || iat == 0
            || !iat.is_multiple_of(4)
            || bytes.len() != 6
            || bytes[..2] != [0xff, 0x15]
            || u32::from_le_bytes(bytes[2..6].try_into().unwrap()) != iat
            || (instruction < iat_end && iat < continuation)
        {
            return Err("normal raise exact indirect call/IAT boundary".into());
        }
        Ok(Self {
            instruction,
            continuation,
            iat,
        })
    }
    pub(crate) fn emit_site(&self) -> String {
        format!(
            "CrtNormalRaiseSite{{instruction:{},continuation:{},iat:{}}}",
            self.instruction, self.continuation, self.iat
        )
    }
}
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
  epoch.state()?;self.identity(rt,epoch)?;
  if let Some(id)=self.id{epoch.top(id)?;}else if epoch.head()?!=self.previous{return Err("CRT normal predecessor no longer live");}Ok(())
 }
 fn identity(&self,rt:&CrtStreamRuntime,epoch:&NormalCallEpoch<'_>)->RegistryResult<()>{
  rt.validate_thread_head(self.token)?;
  if self.done||rt.anchor!=self.anchor||rt.owner!=self.identity.owner||rt.thread!=self.identity.instance
   ||epoch.registry.identity!=self.identity||epoch.generation!=self.epoch
   ||self.token.registry!=self.identity.instance||self.token.epoch!=self.epoch
   ||self.token.head!=Self::head_bits(self.previous)||rt.initialization.is_some()||rt.shutdown.is_some(){
   return Err("CRT normal stale epoch/arena/predecessor");
  }
  rt.valid(self.caller,4)?;
  Ok(())
 }
 fn at(&self,rt:&CrtStreamRuntime,offset:i32)->RegistryResult<CrtPointer>{rt.offset(self.caller,i64::from(offset))}
 fn saved(&self,register:u8)->CrtValue{match self.entry[register as usize]{CrtValue::Scalar{bits,known}=>CrtValue::Scalar{bits:bits&known,known},v=>v}}
 /// The projection is rebuilt from live words on every transition. Consumed
 /// saved words may be represented only by our exact POP receipt: storage must
 /// remain forgotten and the restored typed register must still match.
 fn image(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu,epoch:&NormalCallEpoch<'_>)->RegistryResult<FrameImage<RegistryHead>>{
  self.authority(rt,epoch)?;
  self.storage_image(rt,cpu)
 }
 /// Read-only reconstruction. Callers must establish live normal or suspended
 /// authority before using it; it cannot mutate the registry or clear suspension.
 fn storage_image(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu)->RegistryResult<FrameImage<RegistryHead>>{
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

/// An issued software exception is not a successful API return. This private
/// token owns the interrupted guest CALL state. There is deliberately no API
/// turning it into a Windows captured CONTEXT or a normal-return receipt.
struct CrtNormalRaiseSite { instruction:u32,continuation:u32,iat:u32 }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum CrtNormalDelivery { Pending,Calling,Returned,ResultTaken,Failed }
struct CrtNormalHandlerReturn { identity:RegistryIdentity,epoch:u64,frame:NormalFrameId,generation:u64,value:CrtValue }
struct CrtNormalException {
 anchor:guest_memory::Capability,identity:RegistryIdentity,epoch:u64,frame:NormalFrameId,
 generation:u64,code:u32,noncontinuable:bool,continuation:u32,
 call_registers:[CrtValue;8],call_flags:CrtFlags,return_id:u64,delivery:CrtNormalDelivery,
}
impl CrtNormalException {
 /// Called only at a separately proved FF /2 RaiseException import boundary.
 /// Initial domain: no exception parameters. The opcode/IAT effect binding is
 /// still a compiler prerequisite, never inferred from numeric address equality.
 fn issue(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&CrtNormalBinding,site:CrtNormalRaiseSite)->RegistryResult<Self>{
  let CrtNormalRaiseSite{instruction,continuation,iat}=site;
  binding.image(rt,cpu,epoch)?;
  let frame=binding.id.ok_or("normal exception source not installed")?;
  let f=epoch.top(frame)?;
  if !f.installed||f.unlinked||epoch.head()!=Ok(RegistryHead::Normal(frame))
   ||instruction.checked_add(6)!=Some(continuation)||instruction==0
   ||!epoch.registry.module_contains_address(instruction)||!epoch.registry.module_contains_address(continuation)
   ||!epoch.registry.bound.iter().any(|&(a,b)|instruction>=a&&continuation<b)
   ||iat==0||iat%4!=0||iat.checked_add(4).is_none_or(|end|
    !epoch.registry.bound.iter().any(|&(a,b)|iat>=a&&end<=b)||instruction<end&&iat<continuation){
   return Err("normal exception source/call boundary");
  }
  let sp=CrtCpu::pointer(cpu.r[4])?;
  if sp.cap!=binding.caller.cap||sp.address()%4!=0
   ||sp.address().checked_add(16).is_none_or(|end|end>binding.at(rt,binding.layout.low).map(|p|p.address()).unwrap_or(0)){
   return Err("normal exception argument ownership/extent");
  }
  let mut args=[0;4];for(i,arg)in args.iter_mut().enumerate(){*arg=rt.load(rt.offset(sp,i as i64*4)?,32)?.known_scalar()?;}
  if args[0]&0x10000000!=0||args[1]>1||args[2]!=0||args[3]!=0{return Err("normal exception unsupported code/flags/parameters");}
  let slot=rt.offset(sp,-4)?;rt.valid(slot,4)?;
  epoch.registry.range(slot.address(),u64::from(sp.address())+16)?;
  if rt.overlapping_tags(slot.address(),4).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_))){return Err("normal exception protected CALL slot");}
  let generation=rt.generation.checked_add(1).filter(|n|*n<1u64<<63).ok_or("normal exception identity budget")?;
  let return_id=generation|(1u64<<63);
  if rt.tags.values().any(|v|*v==CrtValue::ProtectedReturn(return_id)){return Err("normal exception return collision");}
  let pending=Self{anchor:rt.anchor,identity:epoch.registry.identity,epoch:epoch.generation,frame,
   generation,code:args[0],noncontinuable:args[1]!=0,continuation,
   call_registers:cpu.r,call_flags:cpu.flags,return_id,delivery:CrtNormalDelivery::Pending};
  // Publish suspension only after the original CALL push succeeds. No argument
  // cleanup, clobber, captured-register synthesis, unlock or frame retirement.
  cpu.push(rt,CrtValue::ProtectedReturn(return_id))?;rt.generation=generation;
  epoch.registry.normal_epoch.as_mut().ok_or("normal exception missing epoch")?.pending_exception=Some(generation);
  Ok(pending)
 }
 /// Establish the actual interrupted EH4 source before any handler dispatch.
 /// This read-only projection does not grant normal-call or restoration authority.
 fn dispatch_source(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu,epoch:&NormalCallEpoch<'_>,binding:&CrtNormalBinding)->RegistryResult<FrameImage<RegistryHead>>{
  self.validate_pending(rt,epoch)?;binding.identity(rt,epoch)?;
  if binding.id!=Some(self.frame)||binding.epoch!=self.epoch||!binding.consumed.is_empty()
   ||cpu.r.iter().enumerate().any(|(i,v)|i!=4&&*v!=self.call_registers[i])
   ||cpu.r[4]!=CrtValue::Pointer(rt.offset(CrtCpu::pointer(self.call_registers[4])?,-4)?)
   ||(cpu.flags.cf,cpu.flags.zf,cpu.flags.sf,cpu.flags.of)!=(self.call_flags.cf,self.call_flags.zf,self.call_flags.sf,self.call_flags.of){
   return Err("normal exception changed interrupted activation");
  }
  let image=binding.storage_image(rt,cpu)?;
  let frame=epoch.registry.normal_epoch.as_ref().ok_or("normal exception expired epoch")?.frames.last().ok_or("normal exception missing frame")?;
  if frame.next!=0{return Err("normal exception partial epilog source");}
  NormalCallEpoch::check_image(frame,&image)?;Ok(image)
 }
 /// Component boundary: arguments and callback code require an enclosing
 /// dispatch proof. This does not synthesize an OS captured CONTEXT, select a
 /// disposition or authorize resuming the interrupted guest CALL.
 fn execute_handler<F>(&mut self,rt:&mut CrtStreamRuntime,interrupted:&CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&CrtNormalBinding,dispatcher:&mut CrtCpu,continuation:u32,body:F)->RegistryResult<CrtNormalHandlerReturn>
 where F:FnOnce(&mut CrtStreamRuntime,&mut CrtCpu)->RegistryResult<CrtValue>{
  if self.delivery!=CrtNormalDelivery::Pending{return Err("normal exception handler replay/phase");}
  let before=self.dispatch_source(rt,interrupted,epoch,binding)?;
  let sp=CrtCpu::pointer(dispatcher.r[4])?;let interrupted_sp=CrtCpu::pointer(interrupted.r[4])?;
  if sp.kind!=CrtRegionKind::Stack||sp.cap!=interrupted_sp.cap||sp.address()%4!=0
   ||sp.address().checked_add(16).is_none_or(|end|end>interrupted_sp.address()){
   return Err("normal exception handler scratch aliases interrupted storage");
  }
  let low=rt.offset(sp,-4)?;rt.valid(low,20)?;epoch.registry.range(low.address(),u64::from(sp.address())+16)?;
  for i in 0..4{let value=rt.load(rt.offset(sp,i*4)?,32)?;if matches!(value,CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)|CrtValue::OpaqueSaved(_)|CrtValue::Scalar{known:0,..}){return Err("normal exception unbound handler argument");}match value{CrtValue::Scalar{known,..}if known!=u32::MAX=>return Err("normal exception partial handler argument"),CrtValue::Pointer(p)=>rt.identity_range(p,0)?,_=>{}}}
  self.delivery=CrtNormalDelivery::Calling;
  let result=(||{
   let value=dispatcher.call_activation(rt,continuation,0,body)?;
   let after=self.dispatch_source(rt,interrupted,epoch,binding)?;
   if after.try_level!=before.try_level{return Err("normal exception unproved scope transition");}
   Ok(CrtNormalHandlerReturn{identity:self.identity,epoch:self.epoch,frame:self.frame,generation:self.generation,value})
  })();
  match result{Ok(receipt)=>{self.delivery=CrtNormalDelivery::Returned;Ok(receipt)},Err(error)=>{self.delivery=CrtNormalDelivery::Failed;epoch.fail(error)}}
 }
 /// Consume only an actually completed callback result for this live event.
 /// The returned scalar is not an EXCEPTION_DISPOSITION authorization: the
 /// enclosing original dispatcher must still prove its meaning and effects.
 fn take_handler_result(&mut self,receipt:CrtNormalHandlerReturn,rt:&CrtStreamRuntime,interrupted:&CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&CrtNormalBinding)->RegistryResult<u32>{
  let result=(||{
   if self.delivery!=CrtNormalDelivery::Returned||receipt.identity!=self.identity||receipt.epoch!=self.epoch
    ||receipt.frame!=self.frame||receipt.generation!=self.generation{return Err("normal exception foreign/stale handler receipt");}
   self.dispatch_source(rt,interrupted,epoch,binding)?;receipt.value.known_scalar()
  })();
  match result{Ok(value)=>{self.delivery=CrtNormalDelivery::ResultTaken;Ok(value)},Err(error)=>{self.delivery=CrtNormalDelivery::Failed;epoch.fail(error)}}
 }
 fn validate_pending(&self,rt:&CrtStreamRuntime,epoch:&NormalCallEpoch<'_>)->RegistryResult<()>{
  epoch.registry.available()?;
  let state=epoch.registry.normal_epoch.as_ref().ok_or("normal exception expired epoch")?;
  if rt.anchor!=self.anchor||rt.owner!=self.identity.owner||rt.thread!=self.identity.instance||rt.closed
   ||rt.initialization.is_some()||rt.shutdown.is_some()
   ||epoch.registry.identity!=self.identity||epoch.generation!=self.epoch||state.generation!=self.epoch
   ||state.pending_exception!=Some(self.generation)||epoch.registry.head!=RegistryHead::Normal(self.frame)
   ||state.frames.last().is_none_or(|f|f.id!=self.frame||!f.installed||f.unlinked){return Err("normal exception stale/foreign ownership");}
  let sp=CrtCpu::pointer(self.call_registers[4])?;
  if rt.load(rt.offset(sp,-4)?,32)?!=CrtValue::ProtectedReturn(self.return_id)||rt.tags.values().filter(|v|**v==CrtValue::ProtectedReturn(self.return_id)).count()!=1{return Err("normal exception lost/aliased CALL continuation");}Ok(())
 }
}
"#;
