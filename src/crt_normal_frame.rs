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
/// Lower one original MOV [establisher+12], register into the live frame.
/// Scope-table/control-flow proof remains the caller's obligation. This proof
/// establishes the memory/register operation, not which scope may be selected.
pub(crate) struct NormalScopeStoreProof {
    base: usize,
    source: usize,
}
impl NormalScopeStoreProof {
    pub(crate) fn prove(bytes: &[u8], origin: u32) -> Result<Self, String> {
        use iced_x86::{Code, Decoder, DecoderOptions, OpKind, Register};
        let mut decoder = Decoder::with_ip(32, bytes, u64::from(origin), DecoderOptions::NONE);
        let i = decoder.decode();
        let reg = |r| match r {
            Register::EAX => Some(0),
            Register::ECX => Some(1),
            Register::EDX => Some(2),
            Register::EBX => Some(3),
            Register::EBP => Some(5),
            Register::ESI => Some(6),
            Register::EDI => Some(7),
            _ => None,
        };
        if origin == 0
            || origin.checked_add(bytes.len() as u32).is_none()
            || i.code() != Code::Mov_rm32_r32
            || i.op0_kind() != OpKind::Memory
            || i.op1_kind() != OpKind::Register
            || decoder.position() != bytes.len()
            || bytes.len() != 3
            || bytes[0] != 0x89
            || i.memory_index() != Register::None
            || i.memory_displacement32() != 12
        {
            return Err("normal scope store exact word instruction".into());
        }
        Ok(Self {
            base: reg(i.memory_base()).ok_or("normal scope store base")?,
            source: reg(i.op1_register()).ok_or("normal scope store source")?,
        })
    }
    pub(crate) fn emit(&self, name: &str) -> String {
        format!("fn {name}(frame:&mut CrtLiveFrame<'_,'_>,cpu:&CrtCpu)->RegistryResult<()>{{frame.store_level_operand(cpu.r[{}],cpu.r[{}])}}",self.base,self.source)
    }
    pub(crate) fn emit_owned_local(&self, name: &str, before: i32, after: i32) -> String {
        format!("fn {name}(rt:&mut CrtStreamRuntime,local:&mut LocalRecord<'_>,machine:&Machine,storage:&mut CrtOwnedStorage,cpu:&CrtCpu)->RegistryResult<()>{{storage.store_local_level(rt,local,machine,cpu.r[{}],cpu.r[{}],{before},{after})}}",self.base,self.source)
    }
    pub(crate) fn emit_owned(&self, name: &str, before: i32, after: i32) -> String {
        format!("fn {name}(frame:&mut CrtOwnedFrameView<'_>,cpu:&CrtCpu)->RegistryResult<()>{{frame.store_level_operand(cpu.r[{}],cpu.r[{}],{before},{after})}}",self.base,self.source)
    }
}
/// Exact admitted x86 frame prolog for the original EH4 handler. This does
/// not prove the following helper calls or exception delivery.
pub(crate) fn emit_handler_prolog(bytes: &[u8], origin: u32) -> Result<String, String> {
    emit_handler_prolog_for(
        bytes,
        origin,
        "original_handler_prolog",
        "CrtLiveFrame<'_,'_>",
    )
}
pub(crate) fn emit_handler_prolog_for(
    bytes: &[u8],
    origin: u32,
    name: &str,
    frame_type: &str,
) -> Result<String, String> {
    if bytes != [0x55, 0x8b, 0xec, 0x83, 0xec, 0x1c]
        || origin == 0
        || origin.checked_add(6).is_none()
    {
        return Err("handler prolog instruction contract".into());
    }
    let body = r#"
 frame.validate()?;let entry=CrtCpu::pointer(cpu.r[4])?;
 if cpu.returned||cpu.return_id!=frame.active_call()||cpu.r[4]!=cpu.entry[4]
  ||frame.rt.load(entry,32)?!=CrtValue::ProtectedReturn(cpu.return_id){return Err("handler prolog activation");}
 let low=frame.rt.offset(entry,-32)?;frame.rt.valid(low,32)?;
 if !frame.rt.overlapping_tags(low.address(),32).is_empty(){return Err("handler prolog typed stack overlap");}
 frame.stack_range(low.address(),u64::from(entry.address()))?;
 cpu.push(frame.rt,cpu.r[5])?;cpu.r[5]=cpu.r[4];cpu.r[4]=CrtValue::Pointer(low);cpu.flags=CrtFlags::unknown();Ok(())
"#;
    Ok(format!(
        "fn {name}(frame:&mut {frame_type},cpu:&mut CrtCpu)->RegistryResult<()>{{{body}}}"
    ))
}
impl super::PrologProof {
    pub(crate) fn guard_proof(
        &self,
        code: &[u8],
        origin: u32,
        security: &[u8],
        security_origin: u32,
        header: [i32; 4],
    ) -> Result<crate::handler_guard::GuardProof, String> {
        let offset = self
            .layout
            .guard
            .checked_sub(self.layout.frame_pointer)
            .ok_or("guard prolog offset")?;
        crate::handler_guard::prove_guard_offsets(
            code,
            origin,
            security,
            security_origin,
            self.cookie_address,
            header,
            &[offset],
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
 layout:CrtNormalLayout,cookie:u32,initialization:Option<CrtInitialization>,id:Option<NormalFrameId>,consumed:std::collections::BTreeSet<i32>,done:bool,
}
impl CrtNormalBinding {
 fn head_bits(head:RegistryHead)->[u64;3]{match head{
  RegistryHead::BorrowedRoot(_)=>[0,0,0],
  RegistryHead::BorrowedDispatcher{generation,..}=>[1,generation,0],
  RegistryHead::Owned(id)=>[2,id.generation,0],
  RegistryHead::Normal(id)=>[3,id.epoch,id.generation],
  RegistryHead::Cxx(id)=>[4,id.generation,0],
 }}
 fn validate_cxx_head(rt:&CrtStreamRuntime,epoch:&NormalCallEpoch<'_>)->RegistryResult<()>{
  Self::validate_cxx_from(rt,epoch,epoch.head()?)
 }
 fn validate_cxx_from(rt:&CrtStreamRuntime,epoch:&NormalCallEpoch<'_>,mut head:RegistryHead)->RegistryResult<()>{
  epoch.state()?;
  for _ in 0..=32{let RegistryHead::Cxx(id)=head else{return Ok(());};
   let f=epoch.registry.cxx.iter().find(|f|f.id==id&&f.linked).ok_or("C++ inherited stale head")?;
   if f.epoch!=epoch.generation||rt.owner!=epoch.registry.identity.owner||rt.thread!=epoch.registry.identity.instance{return Err("C++ inherited foreign epoch/runtime");}
   let entry=rt.resolve_absolute(u32::try_from(f.high-4).map_err(|_|"C++ inherited return range")?,CrtRegionKind::Stack)?;
   let record=rt.resolve_absolute(f.record,CrtRegionKind::Stack)?;rt.valid(record,12)?;
   let token=rt.thread_head(epoch.registry.identity.instance,f.epoch,Self::head_bits(f.previous))?;
   if rt.load(entry,32)?!=CrtValue::ProtectedReturn(f.owner)||rt.tags.values().filter(|v|**v==CrtValue::ProtectedReturn(f.owner)).count()!=1
    ||rt.load(record,32)?!=CrtValue::ThreadHead(token)||rt.load(rt.offset(record,4)?,32)?!=CrtValue::scalar(f.handler){return Err("C++ inherited owner/record lifetime");}
   rt.load(rt.offset(record,8)?,32)?.known_scalar()?;head=f.previous;
  }Err("C++ inherited chain budget/cycle")
 }
 fn bind(rt:&CrtStreamRuntime,cpu:&CrtCpu,epoch:&NormalCallEpoch<'_>,layout:CrtNormalLayout)->RegistryResult<Self>{
  Self::bind_phase(rt,cpu,epoch,layout,None)
 }
 fn bind_initializing(rt:&CrtStreamRuntime,cpu:&CrtCpu,epoch:&NormalCallEpoch<'_>,layout:CrtNormalLayout,initialization:CrtInitialization)->RegistryResult<Self>{
  rt.initialization(initialization)?;Self::bind_phase(rt,cpu,epoch,layout,Some(initialization))
 }
 fn bind_phase(rt:&CrtStreamRuntime,cpu:&CrtCpu,epoch:&NormalCallEpoch<'_>,layout:CrtNormalLayout,initialization:Option<CrtInitialization>)->RegistryResult<Self>{
  match initialization{Some(token)=>rt.initialization(token)?,None=>if rt.initialization.is_some(){return Err("CRT normal initialization token required");}}

  epoch.state()?;Self::validate_cxx_head(rt,epoch)?;let identity=epoch.registry.identity;let previous=epoch.head()?;
  let caller=CrtCpu::pointer(cpu.entry[4])?;
  if rt.owner!=identity.owner||rt.thread!=identity.instance||epoch.registry.cookie_address!=layout.cookie_address||rt.shutdown.is_some()||rt.closed
   ||cpu.returned||cpu.return_id==0||cpu.return_pop!=layout.pop||cpu.r[4]!=cpu.entry[4]
   ||caller.kind!=CrtRegionKind::Stack||caller.address()%4!=0
   ||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){
   return Err("CRT normal bind runtime/activation identity");
  }
  epoch.delivery_range(rt.offset(caller,i64::from(layout.low))?.address(),u64::from(caller.address())+4+u64::from(layout.pop))?;
  rt.valid(rt.offset(caller,i64::from(layout.low))?,u32::try_from(-i64::from(layout.low)+4+i64::from(layout.pop)).map_err(|_|"CRT normal frame extent")?)?;
  if rt.load(caller,32)?!=CrtValue::ProtectedReturn(cpu.return_id)
   ||rt.tags.values().filter(|v|**v==CrtValue::ProtectedReturn(cpu.return_id)).count()!=1{
   return Err("CRT normal unique caller return");
  }
  let cookie=rt.load(rt.resolve_absolute(layout.cookie_address,CrtRegionKind::Module)?,32)?.known_scalar()?;
  let token=rt.thread_head(identity.instance,epoch.generation,Self::head_bits(previous))?;
  Ok(Self{anchor:rt.anchor,identity,epoch:epoch.generation,previous,token,caller,entry:cpu.entry,
   return_id:cpu.return_id,layout,cookie,initialization,id:None,consumed:Default::default(),done:false})
 }
 fn authority(&self,rt:&CrtStreamRuntime,epoch:&NormalCallEpoch<'_>)->RegistryResult<()>{
  epoch.state()?;self.identity(rt,epoch)?;
  if let Some(id)=self.id{epoch.top(id)?;}else if epoch.head()?!=self.previous{return Err("CRT normal predecessor no longer live");}Ok(())
 }
 fn identity(&self,rt:&CrtStreamRuntime,epoch:&NormalCallEpoch<'_>)->RegistryResult<()>{
  rt.validate_thread_head(self.token)?;
  match self.initialization{Some(token)=>rt.initialization(token)?,None=>if rt.initialization.is_some(){return Err("CRT normal initialization phase changed");}}
  if self.done||rt.anchor!=self.anchor||rt.owner!=self.identity.owner||rt.thread!=self.identity.instance
   ||epoch.registry.identity!=self.identity||epoch.generation!=self.epoch
   ||self.token.registry!=self.identity.instance||self.token.epoch!=self.epoch
   ||self.token.head!=Self::head_bits(self.previous)||rt.shutdown.is_some(){
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
  if let Err(e)=Self::validate_cxx_from(rt,epoch,self.previous){return epoch.fail(e);}
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
  if let Err(e)=Self::validate_cxx_from(rt,epoch,self.previous){return epoch.fail(e);}
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
struct CrtNormalHandlerReturn { identity:RegistryIdentity,epoch:u64,frame:NormalFrameId,generation:u64,level:i32,value:CrtValue }
/// Explicit captured-state input cut. Construction validates supplied objects
/// and retains the exact value/knowledge mask. Predicate use never manufactures
/// an exact ESP or creates captured registers from guest CALL state.
struct CrtNormalObjects {
 anchor:guest_memory::Capability,identity:RegistryIdentity,epoch:u64,generation:u64,
 record:CrtPointer,context:CrtPointer,captured_esp:CrtValue,unobserved:Option<CrtUnobservedContext>,
}
impl CrtNormalObjects {
 fn bind(event:&CrtNormalException,rt:&CrtStreamRuntime,epoch:&NormalCallEpoch<'_>,record:CrtPointer,context:CrtPointer)->RegistryResult<Self>{
  event.validate_pending(rt,epoch)?;
  if record.kind!=CrtRegionKind::Context||context.kind!=CrtRegionKind::Context
   ||record.address()%4!=0||context.address()%4!=0
   ||(u64::from(record.address())<u64::from(context.address())+716&&u64::from(context.address())<u64::from(record.address())+80){return Err("normal exception object roles/alias");}
  rt.valid(record,80)?;rt.valid(context,716)?;
  let captured_esp=rt.load(rt.offset(context,0xc4)?,32)?;
  let objects=Self{anchor:rt.anchor,identity:event.identity,epoch:event.epoch,generation:event.generation,record,context,captured_esp,unobserved:None};
  objects.validate(event,rt,epoch)?;Ok(objects)
 }
 fn validate_record(&self,event:&CrtNormalException,rt:&CrtStreamRuntime,epoch:&NormalCallEpoch<'_>)->RegistryResult<()>{
  event.validate_pending(rt,epoch)?;
  if rt.anchor!=self.anchor||event.identity!=self.identity||event.epoch!=self.epoch||event.generation!=self.generation{return Err("normal exception captured object identity/bounds");}
  if event.produced_record.is_some_and(|p|p!=self.record){return Err("normal record producer object mismatch");}
  rt.valid(self.record,80)?;rt.valid(self.context,716)?;
  for (offset,value) in [(0,event.code),(4,u32::from(event.noncontinuable)),(8,0),(16,0)]{
   if rt.load(rt.offset(self.record,offset)?,32)?.known_scalar()?!=value{return Err("normal exception record input mismatch");}
  }
  Ok(())
 }
 fn validate(&self,event:&CrtNormalException,rt:&CrtStreamRuntime,epoch:&NormalCallEpoch<'_>)->RegistryResult<()>{
  self.validate_record(event,rt,epoch)?;
  if let Some(lease)=&self.unobserved{
   if lease.context!=self.context||lease.source!=[event.identity.instance,event.epoch,event.frame.generation,event.generation]
    ||event.unobserved.as_ref().is_none_or(|issued|!std::rc::Rc::ptr_eq(&issued.live,&lease.live))
    ||self.captured_esp!=(CrtValue::Scalar{bits:0,known:0}){return Err("unobserved context wrong event/object");}
   return lease.validate(rt);
  }
  if event.unobserved.is_some(){return Err("unobserved context cannot become supplied capture");}
  if rt.load(rt.offset(self.context,0xc4)?,32)?!=self.captured_esp{return Err("normal exception captured ESP input changed");}
  let view=self.capture_view(epoch)?;
  if view.captured_below_limit(self.identity.owner)?||!view.captured_at_most_base(self.identity.owner)?{return Err("normal exception captured object identity/bounds");}Ok(())
 }
 fn capture_view(&self,epoch:&NormalCallEpoch<'_>)->RegistryResult<CapturedStackView>{
  if self.unobserved.is_some(){return Err("unobserved context has no captured predicates");}
  let CrtValue::Scalar{bits,known}=self.captured_esp else{return Err("normal captured ESP requires scalar knowledge");};
  CapturedStackView::from_bits(self.identity.owner,epoch.registry.limit,epoch.registry.base,bits,known)
 }
 fn check_arguments(&self,event:&CrtNormalException,rt:&CrtStreamRuntime,epoch:&NormalCallEpoch<'_>,binding:&CrtNormalBinding,dispatcher:&CrtCpu)->RegistryResult<()>{
  self.validate(event,rt,epoch)?;let sp=CrtCpu::pointer(dispatcher.r[4])?;
  for(i,pointer)in [self.record,binding.at(rt,binding.layout.record)?,self.context].into_iter().enumerate(){
   if rt.load(rt.offset(sp,i as i64*4)?,32)?!=CrtValue::Pointer(pointer){return Err("normal exception handler argument provenance");}
  }Ok(())
 }
}
struct CrtNormalException {
 anchor:guest_memory::Capability,identity:RegistryIdentity,epoch:u64,frame:NormalFrameId,
 generation:u64,code:u32,noncontinuable:bool,continuation:u32,
 call_registers:[CrtValue;8],call_flags:CrtFlags,return_id:u64,delivery:CrtNormalDelivery,produced_record:Option<CrtPointer>,unobserved:Option<CrtUnobservedContext>,
}
impl Drop for CrtNormalException {fn drop(&mut self){if let Some(lease)=&self.unobserved{lease.revoke();}}}
impl CrtNormalException {
 fn fail_capture(&mut self){if let Some(lease)=&self.unobserved{lease.revoke();}self.delivery=CrtNormalDelivery::Failed;}
 /// Called only at a separately proved FF /2 RaiseException import boundary.
 /// Initial domain: no exception parameters. The opcode/IAT effect binding is
 /// still a compiler prerequisite, never inferred from numeric address equality.
 fn issue(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&CrtNormalBinding,site:CrtNormalRaiseSite)->RegistryResult<Self>{
  if epoch.registry.normal_epoch.as_ref().is_some_and(|s|s.pending_exception.is_some()||s.delivery.is_some()){
   return Err("normal exception nested delivery contract unbound");
  }
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
   call_registers:cpu.r,call_flags:cpu.flags,return_id,delivery:CrtNormalDelivery::Pending,produced_record:None,unobserved:None};
  // Publish suspension only after the original CALL push succeeds. No argument
  // cleanup, clobber, captured-register synthesis, unlock or frame retirement.
  cpu.push(rt,CrtValue::ProtectedReturn(return_id))?;rt.generation=generation;
  epoch.registry.normal_epoch.as_mut().ok_or("normal exception missing epoch")?.pending_exception=Some(generation);
  Ok(pending)
 }
 /// Materialize code/count and documented noncontinuable-bit knowledge only.
 /// CONTEXT, ExceptionAddress, nested link and unused parameter bytes stay
 /// outside this producer's knowledge; no CALL register becomes saved state.
 fn produce_record_fields(&mut self,rt:&mut CrtStreamRuntime,interrupted:&CrtCpu,epoch:&NormalCallEpoch<'_>,binding:&CrtNormalBinding,record:CrtPointer)->RegistryResult<()>{
  self.dispatch_source(rt,interrupted,epoch,binding)?;
  if self.delivery!=CrtNormalDelivery::Pending||self.produced_record.is_some()||record.kind!=CrtRegionKind::Context||record.address()%4!=0{return Err("normal record producer phase/role/replay");}
  rt.valid(record,80)?;
  for i in 0..80{if !matches!(rt.load(rt.offset(record,i)?,8)?,CrtValue::Scalar{known,..} if known&255==0){return Err("normal record producer requires fresh storage");}}
  for(offset,value)in [(0,self.code),(16,0)]{rt.store(rt.offset(record,offset)?,32,CrtValue::scalar(value))?;}
  // Only the documented noncontinuable bit follows from dwExceptionFlags.
  // Reserved/system delivery bits need a separate effect contract.
  rt.store(rt.offset(record,4)?,32,CrtValue::Scalar{bits:u32::from(self.noncontinuable),known:1})?;
  self.produced_record=Some(record);Ok(())
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
 fn check_handler_stack(&self,rt:&CrtStreamRuntime,interrupted:&CrtCpu,epoch:&NormalCallEpoch<'_>,dispatcher:&CrtCpu)->RegistryResult<()>{
  let sp=CrtCpu::pointer(dispatcher.r[4])?;let interrupted_sp=CrtCpu::pointer(interrupted.r[4])?;
  if sp.kind!=CrtRegionKind::Stack||sp.cap!=interrupted_sp.cap||sp.address()%4!=0
   ||sp.address().checked_add(16).is_none_or(|end|end>interrupted_sp.address()){
   return Err("normal exception handler scratch aliases interrupted storage");
  }
  let low=rt.offset(sp,-4)?;rt.valid(low,20)?;epoch.registry.range(low.address(),u64::from(sp.address())+16)?;
  for i in 0..4{let value=rt.load(rt.offset(sp,i*4)?,32)?;if matches!(value,CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)|CrtValue::OpaqueSaved(_)|CrtValue::Scalar{known:0,..}){return Err("normal exception unbound handler argument");}match value{CrtValue::Scalar{known,..}if known!=u32::MAX=>return Err("normal exception partial handler argument"),CrtValue::Pointer(p)=>rt.identity_range(p,0)?,_=>{}}}
  Ok(())
 }
 /// Component boundary: arguments and callback code require an enclosing
 /// dispatch proof. This does not synthesize an OS captured CONTEXT, select a
 /// disposition or authorize resuming the interrupted guest CALL.
 fn execute_handler<F>(&mut self,rt:&mut CrtStreamRuntime,interrupted:&CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&CrtNormalBinding,dispatcher:&mut CrtCpu,continuation:u32,body:F)->RegistryResult<CrtNormalHandlerReturn>
 where F:FnOnce(&mut CrtStreamRuntime,&mut CrtCpu)->RegistryResult<CrtValue>{
  if self.delivery!=CrtNormalDelivery::Pending{return Err("normal exception handler replay/phase");}
  let before=self.dispatch_source(rt,interrupted,epoch,binding)?;
  self.check_handler_stack(rt,interrupted,epoch,dispatcher)?;
  self.delivery=CrtNormalDelivery::Calling;
  let result=(||{
   let value=dispatcher.call_activation(rt,continuation,0,body)?;
   let after=self.dispatch_source(rt,interrupted,epoch,binding)?;
   if after.try_level!=before.try_level{return Err("normal exception unproved scope transition");}
   Ok(CrtNormalHandlerReturn{identity:self.identity,epoch:self.epoch,frame:self.frame,generation:self.generation,level:after.try_level,value})
  })();
  match result{Ok(receipt)=>{self.delivery=CrtNormalDelivery::Returned;Ok(receipt)},Err(error)=>{self.fail_capture();epoch.fail(error)}}
 }
 /// Lend only child-frame authority during the protected handler CALL. The
 /// interrupted frame remains suspended; no finished-event permit is minted.
 /// Nested native helper frames are allowed. A nested exception requires its
 /// own delivery/containment contract and is rejected by issue().
 fn execute_child_handler<F>(&mut self,rt:&mut CrtStreamRuntime,interrupted:&CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&CrtNormalBinding,dispatcher:&mut CrtCpu,continuation:u32,body:F)->RegistryResult<CrtNormalHandlerReturn>
 where F:FnOnce(&mut CrtStreamRuntime,&mut CrtCpu,&mut NormalCallEpoch<'_>)->RegistryResult<CrtValue>{
  if self.delivery!=CrtNormalDelivery::Pending||epoch.delivery.is_some(){return Err("delivery child replay/nested phase");}
  let before=self.dispatch_source(rt,interrupted,epoch,binding)?;
  self.check_handler_stack(rt,interrupted,epoch,dispatcher)?;
  let state=epoch.registry.normal_epoch.as_ref().ok_or("delivery child missing epoch")?;
  if state.delivery.is_some(){return Err("delivery child already borrowed");}
  let floor=state.frames.len();let context=state.context;let cxx_before=epoch.registry.cxx.clone();
  let lease=epoch.registry.next_id()?.generation;
  self.delivery=CrtNormalDelivery::Calling;
  let result=(||{
   let value=dispatcher.call_activation(rt,continuation,0,|rt,child|{
    let grant=DeliveryChildAuthority{event:self.generation,lease,parent:self.frame,floor,
     ceiling:u64::from(CrtCpu::pointer(child.entry[4])?.address())+4,arguments_high:u64::from(CrtCpu::pointer(child.entry[4])?.address())+20};
    epoch.registry.normal_epoch.as_mut().ok_or("delivery child expired epoch")?.delivery=Some(grant);
    let value={let mut borrowed=NormalCallEpoch{registry:&mut *epoch.registry,generation:epoch.generation,delivery:Some(grant)};
     let value=body(rt,child,&mut borrowed)?;
     let state=borrowed.state()?;
     if borrowed.registry.cxx!=cxx_before||state.frames.len()!=floor||state.context!=context||borrowed.head()?!=RegistryHead::Normal(self.frame){return Err("delivery child incomplete return or changed context");}
     value
    };
    epoch.registry.normal_epoch.as_mut().ok_or("delivery child expired epoch")?.delivery=None;
    Ok(value)
   })?;
   let after=self.dispatch_source(rt,interrupted,epoch,binding)?;
   if after.try_level!=before.try_level{return Err("delivery child unproved scope transition");}
   Ok(CrtNormalHandlerReturn{identity:self.identity,epoch:self.epoch,frame:self.frame,generation:self.generation,level:after.try_level,value})
  })();
  match result{Ok(receipt)=>{self.delivery=CrtNormalDelivery::Returned;Ok(receipt)},Err(error)=>{self.fail_capture();epoch.fail(error)}}
 }
 /// Original handler binding must use the owned object boundary. The fourth
 /// dispatcher argument remains separately proved; no host pointer is inferred.
 fn execute_bound_handler<F>(&mut self,objects:&CrtNormalObjects,rt:&mut CrtStreamRuntime,interrupted:&CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&CrtNormalBinding,dispatcher:&mut CrtCpu,continuation:u32,body:F)->RegistryResult<CrtNormalHandlerReturn>
 where F:FnOnce(&mut CrtStreamRuntime,&mut CrtCpu)->RegistryResult<CrtValue>{
  objects.check_arguments(self,rt,epoch,binding,dispatcher)?;
  let receipt=self.execute_handler(rt,interrupted,epoch,binding,dispatcher,continuation,body)?;
  if let Err(error)=objects.validate(self,rt,epoch){self.fail_capture();return epoch.fail(error);}Ok(receipt)
 }
 /// Consume only an actually completed callback result for this live event.
 /// The returned scalar is not an EXCEPTION_DISPOSITION authorization: the
 /// enclosing original dispatcher must still prove its meaning and effects.
 fn take_handler_result(&mut self,receipt:CrtNormalHandlerReturn,rt:&CrtStreamRuntime,interrupted:&CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&CrtNormalBinding)->RegistryResult<u32>{
  let result=(||{
   if self.delivery!=CrtNormalDelivery::Returned||receipt.identity!=self.identity||receipt.epoch!=self.epoch
    ||receipt.frame!=self.frame||receipt.generation!=self.generation{return Err("normal exception foreign/stale handler receipt");}
   if self.dispatch_source(rt,interrupted,epoch,binding)?.try_level!=receipt.level{return Err("normal exception changed returned scope");}receipt.value.known_scalar()
  })();
  match result{Ok(value)=>{self.delivery=CrtNormalDelivery::ResultTaken;Ok(value)},Err(error)=>{self.fail_capture();epoch.fail(error)}}
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
/// A delivery-local view of checked storage. It borrows the pending event and
/// never changes the finished outer Machine or forges an OwnedFrameBinding.
/// Scope cursor knowledge is shared across nested native calls; frame words are
/// always loaded from CRT storage, never copied back from a FrameImage.
struct CrtLiveDispatchState { level:i32,depth:u32,calls:u32,activation:u64,failed:bool }
struct CrtLiveFrame<'a,'e> {
 rt:&'a mut CrtStreamRuntime,event:&'a CrtNormalException,
 interrupted:&'a CrtCpu,epoch:&'a NormalCallEpoch<'e>,binding:&'a CrtNormalBinding,
 state:&'a mut CrtLiveDispatchState,
}
impl CrtLiveFrame<'_,'_> {
 fn scope_address(&self)->u32{self.binding.layout.scope}
 fn cookie_address(&self)->u32{self.binding.layout.cookie_address}
 fn active_call(&self)->u64{self.state.activation}
 fn stack_range(&self,low:u32,high:u64)->RegistryResult<()>{self.epoch.registry.range(low,high)}
 fn preflight_bridge(&self,cpu:&CrtCpu,bytes:u32)->RegistryResult<()>{
  self.validate()?;let sp=CrtCpu::pointer(cpu.r[4])?;let source=CrtCpu::pointer(self.interrupted.r[4])?;
  if bytes==0||bytes>256||cpu.returned||cpu.return_id!=self.state.activation||cpu.r[4]!=cpu.entry[4]||sp.cap!=source.cap||sp.address()>=source.address()||self.rt.load(sp,32)?!=CrtValue::ProtectedReturn(cpu.return_id){return Err("normal bridge entry/scratch alias");}
  let low=self.rt.offset(sp,-i64::from(bytes))?;self.rt.valid(low,bytes)?;self.epoch.registry.range(low.address(),u64::from(sp.address()))?;
  if self.rt.overlapping_tags(low.address(),bytes).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_))){return Err("normal bridge protected scratch");}Ok(())
 }
 fn owner_frame(&self)->RegistryResult<CrtPointer>{self.validate()?;self.binding.at(self.rt,self.binding.layout.bp)}
 fn validate(&self)->RegistryResult<()>{
  if self.state.failed||self.event.delivery!=CrtNormalDelivery::Calling||self.state.depth==0||self.state.depth>32 {
   return Err("live dispatch failed/expired phase");
  }
  let image=self.event.dispatch_source(self.rt,self.interrupted,self.epoch,self.binding)?;
  if image.try_level!=self.state.level{return Err("live dispatch unproved scope alias write");}Ok(())
 }
 /// Offsets are relative to the proved original EBP. Full words must fit in
 /// this activation, and no ordinary alias grants access to record/save tags.
 fn ordinary(&self,offset:i32)->RegistryResult<CrtPointer>{
  self.validate()?;
  let l=&self.binding.layout;let at=l.bp.checked_add(offset).ok_or("live frame offset overflow")?;
  if at%4!=0||at<l.low||at.checked_add(4).is_none_or(|end|end>0)
   ||(l.record..l.record+16).contains(&at)||at==l.guard||at==l.saved_sp
   ||l.saved.iter().any(|&(p,_)|p==at){return Err("live frame protected/outside word");}
  let p=self.binding.at(self.rt,at)?;self.rt.valid(p,4)?;Ok(p)
 }
 /// End a completed handler's local borrow without inventing guest writes.
 fn retire_handler_scratch(&mut self,cpu:&mut CrtCpu,low:CrtPointer,bytes:u32)->RegistryResult<()>{
  self.validate()?;let entry=CrtCpu::pointer(cpu.entry[4])?;
  if !cpu.returned||cpu.return_id!=self.state.activation||bytes==0||bytes>256||bytes%4!=0
   ||low!=self.rt.offset(entry,-i64::from(bytes))?{return Err("live search scratch retirement authority");}
  self.rt.valid(low,bytes)?;
  if self.rt.overlapping_tags(low.address(),bytes).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)|CrtValue::OpaqueSaved(_))){return Err("live search scratch retains protected state");}
  let inside=|p:CrtPointer|p.cap==low.cap&&p.address()>=low.address()&&p.address()<entry.address();
  // Preserve numeric bytes of escaped aliases, but remove the expired borrow.
  self.rt.tags.retain(|&at,v|!(at>=low.address()&&at<entry.address())&&!matches!(v,CrtValue::Pointer(p)if inside(*p)));
  self.rt.partial.retain(|&at,_|at<low.address()||at>=entry.address());
  self.rt.memory.forget(low.address(),bytes).map_err(|_|"live search scratch extent")?;
  for v in &mut cpu.r{if let CrtValue::Pointer(p)=*v{if inside(p){*v=CrtValue::scalar(p.address());}}}
  Ok(())
 }
 fn read(&self,offset:i32)->RegistryResult<CrtValue>{self.rt.load(self.ordinary(offset)?,32)}
 fn write(&mut self,offset:i32,value:CrtValue)->RegistryResult<()>{
  let p=self.ordinary(offset)?;
  if !matches!(value,CrtValue::Scalar{..}|CrtValue::Pointer(_)){return Err("live frame protected value transport");}
  self.rt.store(p,32,value)
 }
 fn read_u32(&self,offset:i32)->RegistryResult<u32>{self.read(offset)?.known_scalar()}
 fn write_u32(&mut self,offset:i32,value:u32)->RegistryResult<()>{self.write(offset,CrtValue::scalar(value))}
 fn write_stack(&mut self,offset:i32,address:i32)->RegistryResult<()>{
  let p=self.ordinary(address)?;self.write(offset,CrtValue::Pointer(p))
 }
 /// Lowering of a proved original TryLevel store. The before value is a proof
 /// obligation, not a saved projection that can overwrite intervening effects.
 fn store_try_level(&mut self,before:i32,after:i32)->RegistryResult<()>{
  self.validate()?;
  if self.state.level!=before{return Err("live dispatch stale scope store");}
  let p=self.binding.at(self.rt,self.binding.layout.level)?;
  self.rt.store(p,32,CrtValue::scalar(after as u32))?;self.state.level=after;Ok(())
 }
 fn store_level_operand(&mut self,base:CrtValue,value:CrtValue)->RegistryResult<()>{
  self.validate()?;
  if base!=CrtValue::Pointer(self.binding.at(self.rt,self.binding.layout.record)?){return Err("live scope store establisher identity");}
  let after=value.known_scalar()? as i32;self.store_try_level(self.state.level,after)
 }
 /// Nested helper execution retains the same event and normal-frame owner.
 /// A second software exception still needs a separate delivery proof and is
 /// rejected; a native helper CALL is not such a proof.
 fn call<F>(&mut self,cpu:&mut CrtCpu,continuation:u32,body:F)->RegistryResult<CrtValue>
 where F:FnOnce(&mut CrtLiveFrame<'_,'_>,&mut CrtCpu)->RegistryResult<CrtValue>{
  let result=self.call_checked(cpu,continuation,body);
  if result.is_err(){self.state.failed=true;}result
 }
 fn call_checked<F>(&mut self,cpu:&mut CrtCpu,continuation:u32,body:F)->RegistryResult<CrtValue>
 where F:FnOnce(&mut CrtLiveFrame<'_,'_>,&mut CrtCpu)->RegistryResult<CrtValue>{
  self.validate()?;
  let sp=CrtCpu::pointer(cpu.r[4])?;let interrupted_sp=CrtCpu::pointer(self.interrupted.r[4])?;
  if self.state.depth>=32||self.state.calls>=4096||sp.kind!=CrtRegionKind::Stack
   ||sp.cap!=interrupted_sp.cap||sp.address()%4!=0||sp.address()>=interrupted_sp.address()
   ||cpu.return_id!=self.state.activation||sp.address()>CrtCpu::pointer(cpu.entry[4])?.address()
   ||!self.epoch.registry.module_contains_address(continuation){return Err("live dispatch call bounds/budget");}
  self.epoch.registry.range(self.rt.offset(sp,-4)?.address(),u64::from(sp.address()))?;
  let parent=self.state.activation;self.state.depth+=1;self.state.calls+=1;
  let result=cpu.call_activation(self.rt,continuation,0,|rt,child|{
   self.state.activation=child.return_id;
   let mut view=CrtLiveFrame{rt,event:self.event,interrupted:self.interrupted,epoch:self.epoch,binding:self.binding,state:self.state};
   let value=body(&mut view,child)?;view.validate()?;Ok(value)
  });
  self.state.depth-=1;self.state.activation=parent;
  result
 }
}
impl CrtNormalException {
 /// This is a checked storage/call composition for an enclosing original
 /// dispatcher proof, not a containment or resumption certificate. Objects
 /// remain an explicit captured-state input. No projection is committed.
 fn execute_live_handler<F>(&mut self,objects:&CrtNormalObjects,rt:&mut CrtStreamRuntime,interrupted:&CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&CrtNormalBinding,dispatcher:&mut CrtCpu,continuation:u32,body:F)->RegistryResult<CrtNormalHandlerReturn>
 where F:FnOnce(&mut CrtLiveFrame<'_,'_>,&mut CrtCpu)->RegistryResult<CrtValue>{
  if self.delivery!=CrtNormalDelivery::Pending{return Err("normal exception handler replay/phase");}
  objects.check_arguments(self,rt,epoch,binding,dispatcher)?;
  let image=self.dispatch_source(rt,interrupted,epoch,binding)?;
  self.check_handler_stack(rt,interrupted,epoch,dispatcher)?;
  if !epoch.registry.module_contains_address(continuation){return Err("live dispatch unbound continuation");}
  self.delivery=CrtNormalDelivery::Calling;
  let mut state=CrtLiveDispatchState{level:image.try_level,depth:1,calls:1,activation:0,failed:false};
  let result=dispatcher.call_activation(rt,continuation,0,|rt,handler|{
   state.activation=handler.return_id;
   let mut view=CrtLiveFrame{rt,event:self,interrupted,epoch,binding,state:&mut state};
   let value=body(&mut view,handler)?;view.validate()?;objects.validate(view.event,view.rt,view.epoch)?;Ok(value)
  });
  match result {
   Ok(value)=>{self.delivery=CrtNormalDelivery::Returned;Ok(CrtNormalHandlerReturn{identity:self.identity,epoch:self.epoch,frame:self.frame,generation:self.generation,level:state.level,value})},
   Err(error)=>{self.fail_capture();epoch.fail(error)},
  }
 }
}

/// First-node search ownership. Advancement records order only; it does not
/// execute the predecessor, grant a child lease, or authorize restoration.
struct CrtOrderedSearch {
 identity:RegistryIdentity,epoch:u64,event:u64,source:NormalFrameId,serial:u64,
 current:RegistryHead,previous:RegistryHead,root:RegistryHead,handler:u32,owner:u64,
 record:CrtPointer,context:CrtPointer,captured_esp:CrtValue,cxx:Vec<RegistryCxxFrame>,normal_count:usize,phase:u8,
}
struct CrtOrderedReturn { serial:u64,source:NormalFrameId,previous:RegistryHead,handler:u32,receipt:CrtNormalHandlerReturn }
impl CrtOrderedSearch {
 fn begin(event:&CrtNormalException,objects:&CrtNormalObjects,rt:&CrtStreamRuntime,interrupted:&CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&CrtNormalBinding)->RegistryResult<Self>{
  if event.delivery!=CrtNormalDelivery::Pending{return Err("ordered search requires pending first handler");}
  event.dispatch_source(rt,interrupted,epoch,binding)?;objects.validate(event,rt,epoch)?;
  let serial=epoch.registry.next_id()?.generation;
  let s=Self{identity:event.identity,epoch:event.epoch,event:event.generation,source:event.frame,serial,
   current:RegistryHead::Normal(event.frame),previous:binding.previous,root:epoch.registry.normal_epoch.as_ref().ok_or("ordered search missing root")?.previous,handler:binding.layout.handler,owner:binding.return_id,
   record:objects.record,context:objects.context,captured_esp:objects.captured_esp,cxx:epoch.registry.cxx.clone(),normal_count:epoch.registry.normal_epoch.as_ref().ok_or("ordered search missing epoch")?.frames.len(),phase:0};
  s.validate(event,objects,rt,interrupted,epoch,binding)?;Ok(s)
 }
 fn validate(&self,event:&CrtNormalException,objects:&CrtNormalObjects,rt:&CrtStreamRuntime,interrupted:&CrtCpu,epoch:&NormalCallEpoch<'_>,binding:&CrtNormalBinding)->RegistryResult<()>{
  self.validate_stage(event,objects,rt,interrupted,epoch,binding,false)
 }
 fn validate_stage(&self,event:&CrtNormalException,objects:&CrtNormalObjects,rt:&CrtStreamRuntime,interrupted:&CrtCpu,epoch:&NormalCallEpoch<'_>,binding:&CrtNormalBinding,advanced:bool)->RegistryResult<()>{
  event.dispatch_source(rt,interrupted,epoch,binding)?;objects.validate(event,rt,epoch)?;
  if (if advanced{!matches!((self.phase,event.delivery),(2,CrtNormalDelivery::ResultTaken)|(4,CrtNormalDelivery::Returned))||self.current!=self.previous}else{self.phase>1||self.current!=RegistryHead::Normal(event.frame)})||self.identity!=event.identity||self.epoch!=event.epoch||self.event!=event.generation
   ||self.source!=event.frame||self.previous!=binding.previous
   ||self.handler!=binding.layout.handler||self.owner!=binding.return_id||self.record!=objects.record||self.context!=objects.context||self.captured_esp!=objects.captured_esp
   ||epoch.registry.cxx!=self.cxx||epoch.registry.normal_epoch.as_ref().is_none_or(|s|s.frames.len()!=self.normal_count||s.delivery.is_some()){
   return Err("ordered search stale source/order/children");
  }
  let state=epoch.registry.normal_epoch.as_ref().ok_or("ordered search expired root epoch")?;
  if state.previous!=self.root||self.root!=RegistryHead::Owned(state.selected){return Err("ordered search incoming root authority changed");}
  // Unlike normal-call acquisition, this read-only check deliberately permits
  // the source's pending exception. It grants no predecessor execution rights.
  let mut head=self.previous;
  for _ in 0..32{
   let RegistryHead::Cxx(id)=head else{
    return match head{
     RegistryHead::Owned(id)=>{if head!=self.root{return Err("ordered search does not reach established root");}let f=&epoch.registry.frames[epoch.registry.frame_index(id)?];if !f.linked{return Err("ordered search incoming owned predecessor unlinked");}Ok(())},
     RegistryHead::BorrowedRoot(_)|RegistryHead::BorrowedDispatcher{..}=>Err("ordered search incoming borrowed containment unproved"),
     _=>Err("ordered search incoming source shape unbound"),
    };
   };
   let f=epoch.registry.cxx.iter().find(|f|f.id==id&&f.linked).ok_or("ordered search missing predecessor")?;
   if f.epoch!=self.epoch{return Err("ordered search foreign predecessor epoch");}
   let entry=rt.resolve_absolute(u32::try_from(f.high-4).map_err(|_|"ordered predecessor extent")?,CrtRegionKind::Stack)?;
   let record=rt.resolve_absolute(f.record,CrtRegionKind::Stack)?;
   let token=rt.thread_head(self.identity.instance,f.epoch,CrtNormalBinding::head_bits(f.previous))?;
   if rt.load(entry,32)?!=CrtValue::ProtectedReturn(f.owner)||rt.tags.values().filter(|v|**v==CrtValue::ProtectedReturn(f.owner)).count()!=1
    ||rt.load(record,32)?!=CrtValue::ThreadHead(token)||rt.load(rt.offset(record,4)?,32)?!=CrtValue::scalar(f.handler){return Err("ordered search expired predecessor storage");}
   rt.load(rt.offset(record,8)?,32)?.known_scalar()?;head=f.previous;
  }Err("ordered search predecessor budget/cycle")
 }
 fn consume(&mut self,returned:CrtOrderedReturn,event:&mut CrtNormalException,objects:&CrtNormalObjects,rt:&CrtStreamRuntime,interrupted:&CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&CrtNormalBinding)->RegistryResult<RegistryHead>{
  let result=(||{
   self.validate(event,objects,rt,interrupted,epoch,binding)?;
   if self.phase!=1||returned.serial!=self.serial||returned.source!=self.source||returned.previous!=self.previous||returned.handler!=self.handler{return Err("ordered search foreign/replayed executed receipt");}
   if returned.receipt.value!=CrtValue::scalar(1){return Err("ordered search requires ContinueSearch disposition");}
   if event.take_handler_result(returned.receipt,rt,interrupted,epoch,binding)?!=1{return Err("ordered search disposition changed");}
   self.phase=2;self.current=self.previous;Ok(self.current)
  })();if result.is_err(){self.phase=3;if let Some(lease)=&event.unobserved{lease.revoke();}}result
 }
}

/// Event-owned handler locals. Construction requires the original handler
/// prolog's actual EBP/ESP and protected CALL, not a numeric scratch address.
struct CrtHandlerPair { activation:u64,epoch:u64,event:u64,frame:NormalFrameId,low:CrtPointer,bp:CrtPointer,record:CrtPointer,context:CrtPointer,installed:bool }
impl CrtHandlerPair {
 fn bind(frame:&CrtLiveFrame<'_,'_>,cpu:&CrtCpu,objects:&CrtNormalObjects)->RegistryResult<Self>{
  frame.validate()?;objects.validate(frame.event,frame.rt,frame.epoch)?;
  let entry=CrtCpu::pointer(cpu.entry[4])?;let bp=CrtCpu::pointer(cpu.r[5])?;
  if cpu.returned||cpu.return_id!=frame.state.activation||bp!=frame.rt.offset(entry,-4)?
   ||(cpu.r[4]!=CrtValue::Pointer(frame.rt.offset(bp,-28)?)
      &&(cpu.r[4]!=CrtValue::Pointer(frame.rt.offset(bp,-40)?)
       ||[(32,3),(36,6),(40,7)].iter().any(|&(off,r)|frame.rt.offset(bp,-off).and_then(|p|frame.rt.load(p,32))!=Ok(cpu.entry[r]))))
   ||frame.rt.load(entry,32)?!=CrtValue::ProtectedReturn(cpu.return_id)
   ||frame.rt.load(bp,32)?!=cpu.entry[5]{return Err("handler locals original prolog ownership");}
  let low=frame.rt.offset(bp,-28)?;frame.rt.valid(low,28)?;
  if frame.rt.overlapping_tags(low.address(),28).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)|CrtValue::OpaqueSaved(_))){return Err("handler locals protected overlap");}
  Ok(Self{activation:cpu.return_id,epoch:frame.event.epoch,event:frame.event.generation,frame:frame.event.frame,low,bp,record:objects.record,context:objects.context,installed:false})
 }
 fn from_installed(frame:&CrtLiveFrame<'_,'_>,cpu:&CrtCpu,objects:&CrtNormalObjects)->RegistryResult<Self>{
  let mut pair=Self::bind(frame,cpu,objects)?;pair.installed=true;pair.read(frame,cpu)?;Ok(pair)
 }
 fn validate(&self,frame:&CrtLiveFrame<'_,'_>,cpu:&CrtCpu)->RegistryResult<()>{
  frame.validate()?;
  frame.rt.valid(CrtCpu::pointer(cpu.r[4])?,0)?;
  if cpu.returned||cpu.return_id!=self.activation||frame.state.activation!=self.activation
   ||frame.event.epoch!=self.epoch||frame.event.generation!=self.event||frame.event.frame!=self.frame
   ||cpu.r[5]!=CrtValue::Pointer(self.bp)||CrtCpu::pointer(cpu.r[4])?.cap!=self.low.cap
   ||CrtCpu::pointer(cpu.r[4])?.address()>self.low.address()
   ||frame.rt.load(self.bp,32)?!=cpu.entry[5]
   ||frame.rt.load(CrtCpu::pointer(cpu.entry[4])?,32)?!=CrtValue::ProtectedReturn(self.activation){return Err("handler pair expired/foreign activation");}
  frame.rt.valid(self.low,8)?;frame.rt.valid(self.record,80)?;frame.rt.valid(self.context,716)?;Ok(())
 }
 fn store(&self,frame:&mut CrtLiveFrame<'_,'_>,cpu:&CrtCpu,offset:i32,value:CrtValue)->RegistryResult<()>{
  self.validate(frame,cpu)?;
  let expected=match offset{-28=>self.record,-24=>self.context,_=>return Err("handler pair word bound")};
  if self.installed||value!=CrtValue::Pointer(expected){return Err("handler pair input provenance/replay");}
  frame.rt.store(frame.rt.offset(self.bp,i64::from(offset))?,32,value)
 }
 fn context_argument(&self,frame:&CrtLiveFrame<'_,'_>,cpu:&CrtCpu)->RegistryResult<CrtValue>{
  self.validate(frame,cpu)?;let value=frame.rt.load(frame.rt.offset(self.bp,16)?,32)?;
  if value!=CrtValue::Pointer(self.context){return Err("handler original context argument");}Ok(value)
 }
 fn install(&mut self,frame:&mut CrtLiveFrame<'_,'_>,cpu:&CrtCpu,value:CrtValue)->RegistryResult<()>{
  self.validate(frame,cpu)?;
  if self.installed||value!=CrtValue::Pointer(self.low)||cpu.r[3]!=CrtValue::Pointer(frame.binding.at(frame.rt,frame.binding.layout.record)?){return Err("handler pair owner address");}
  if frame.rt.load(self.low,32)?!=CrtValue::Pointer(self.record)||frame.rt.load(frame.rt.offset(self.low,4)?,32)?!=CrtValue::Pointer(self.context){return Err("handler pair incomplete words");}
  frame.write(-20,value)?;self.installed=true;Ok(())
 }
 fn read(&self,frame:&CrtLiveFrame<'_,'_>,cpu:&CrtCpu)->RegistryResult<(CrtPointer,CrtPointer)>{
  self.validate(frame,cpu)?;self.read_graph(frame)
 }
 /// Lend the installed original pair only for a real protected nested call.
 /// The body still needs a decoded filter/effect proof; return is not a
 /// disposition or restoration certificate. Mutations remain observable.
 fn call_filter<F>(&self,frame:&mut CrtLiveFrame<'_,'_>,cpu:&mut CrtCpu,continuation:u32,body:F)->RegistryResult<CrtValue>
 where F:FnOnce(&mut CrtLiveFrame<'_,'_>,&mut CrtCpu,CrtPointer,CrtPointer)->RegistryResult<CrtValue>{
  self.read(frame,cpu)?;let level=frame.state.level;
  let result=frame.call(cpu,continuation,|child,callee|{
   let(record,context)=self.read_graph(child)?;
   let result=body(child,callee,record,context)?;self.read_graph(child)?;
   if child.state.level!=level{return Err("handler filter changed scope");}Ok(result)
  });
  match result{Ok(value)=>{if let Err(error)=self.read(frame,cpu){frame.state.failed=true;return Err(error);}Ok(value)},Err(error)=>Err(error)}
 }
 fn read_graph(&self,frame:&CrtLiveFrame<'_,'_>)->RegistryResult<(CrtPointer,CrtPointer)>{
  frame.validate()?;frame.rt.valid(self.low,8)?;
  if frame.event.epoch!=self.epoch||frame.event.generation!=self.event||frame.event.frame!=self.frame{return Err("handler borrowed pair event");}
  let entry=frame.rt.offset(self.bp,4)?;
  if frame.rt.load(entry,32)?!=CrtValue::ProtectedReturn(self.activation){return Err("handler borrowed pair owner retired");}
  if !self.installed||frame.read(-20)?!=CrtValue::Pointer(self.low)
   ||frame.rt.load(self.low,32)?!=CrtValue::Pointer(self.record)
   ||frame.rt.load(frame.rt.offset(self.low,4)?,32)?!=CrtValue::Pointer(self.context){return Err("handler pair changed live graph");}
  Ok((self.record,self.context))
 }
}

impl CrtNormalObjects{fn validate_prefix_source(&self,frame:&CrtLiveFrame<'_,'_>)->RegistryResult<()>{self.validate(frame.event,frame.rt,frame.epoch)}}
struct CrtGuardView<'a,'b,'e>{owner:u64,frame:&'a CrtLiveFrame<'b,'e>,bp:u32}
impl CrtGuardView<'_,'_,'_>{
 fn frame_pointer(&self)->u32{self.bp}
 fn read_guard(&self,offset:i32)->RegistryResult<(u32,u32,u32)>{
  self.frame.validate()?;let b=self.frame.binding;
  if b.layout.bp.checked_add(offset)!=Some(b.layout.guard){return Err("live guard offset provenance");}
  let bits=self.frame.rt.load(b.at(self.frame.rt,b.layout.guard)?,32)?.known_scalar()?;
  Ok((b.at(self.frame.rt,b.layout.bp)?.address(),b.cookie,bits))
 }
}
"#;
