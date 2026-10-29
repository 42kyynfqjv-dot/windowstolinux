//! Checked live storage for an existing owned-frame proof. Supplied entry CPU
//! and exception-pointer objects remain explicit component inputs.
use super::frame_proof::ProvenFrame;
pub(crate) fn emit_initializer(proof: &ProvenFrame, name: &str) -> String {
    let ordinary = proof.ordinary_words().iter().copied().collect::<Vec<_>>();
    format!(
        r#"fn {name}(rt:&mut CrtStreamRuntime,registry:&mut ThreadRegistry,machine:&Machine,binding:OwnedFrameBinding,cpu:&CrtCpu)->RegistryResult<CrtOwnedStorage>{{
 let entry_sp=CrtCpu::pointer(cpu.entry[4])?.address();let cookie=rt.load(rt.resolve_absolute(registry.cookie_address,CrtRegionKind::Module)?,32)?.known_scalar()?;
 let saved=cpu.entry.map(|v|v.known_scalar().ok());let predecessor=registry.head()?;
 let image=(||->RegistryResult<FrameImage<RegistryHead>>{{{body}}})()?;
 CrtOwnedStorage::initialize(rt,registry,machine,binding,cpu,image,&{ordinary:?})
}}"#,
        body = proof.initializer_body()
    )
}
pub(crate) fn emit_activation(
    proof: &ProvenFrame,
    bytes: &[u8],
    origin: u32,
    name: &str,
) -> Result<String, String> {
    let fragment = proof.prove_initializer_fragment(bytes, origin)?;
    let level = fragment
        .try_level()
        .ok_or("activation missing scope store")?;
    if fragment.writes().len() != 1
        || fragment.writes().get(&proof.try_level_offset()) != Some(&(level as u32))
    {
        return Err("activation has additional effects".into());
    }
    Ok(format!("fn {name}(rt:&mut CrtStreamRuntime,r:&ThreadRegistry,m:&Machine,storage:&mut CrtOwnedStorage)->RegistryResult<()>{{if storage.image.scope_va!={}||storage.image.handler_va!={}||i64::from(storage.image.esp)-i64::from(storage.image.ebp)!={}{{return Err(\"activation original frame binding\");}}if !r.module_contains_address({origin}){{return Err(\"activation instruction module\");}}storage.scope_store(rt,r,m,{},{level})}}",proof.scope_va(),proof.handler_va(),proof.esp_offset(),proof.try_level()))
}
/// Bind the instruction-proved ordinary notification to live CRT module words.
/// Entry and callback containment remain separate caller proofs.
pub(crate) fn emit_notification(
    code: &[u8],
    origin: u32,
    binding: super::unwind_bridges::NotificationBinding,
    continuation: u32,
) -> Result<String, String> {
    let proof = super::unwind_bridges::prove_notification(code, origin, binding)?;
    let record_base = binding
        .target_word
        .checked_sub(4)
        .ok_or("notification record underflow")?;
    if binding.action_word
        != record_base
            .checked_add(8)
            .ok_or("notification record overflow")?
        || binding.frame_word
            != record_base
                .checked_add(12)
                .ok_or("notification record overflow")?
        || record_base.checked_add(16).is_none()
        || continuation == 0
    {
        return Err("notification contiguous live record/continuation".into());
    }
    Ok(format!(
        r#"fn map_original_notification(rt:&mut CrtStreamRuntime)->RegistryResult<()>{{rt.map_region({record_base},16,CrtRegionKind::Module,None)?;rt.map_region({origin},{length},CrtRegionKind::Module,Some(&{code:?}))?;Ok(())}}
fn original_notify_invoke(rt:&mut CrtStreamRuntime,storage:&mut CrtOwnedStorage,record:&mut LocalRecord<'_>,cpu:&mut CrtCpu,target:u32,reason:u32)->RegistryResult<()>{{
record.validate_binding(storage.binding,&storage.image)?;let target=rt.resolve_absolute(target,CrtRegionKind::Module)?;let frame=rt.resolve_absolute(storage.image.ebp,CrtRegionKind::Stack)?;
let p=rt.resolve_absolute({origin},CrtRegionKind::Module)?;for(i,byte)in {code:?}.into_iter().enumerate(){{if rt.load(rt.offset(p,i as i64)?,8)?.known_scalar()?!=byte as u32{{return Err("original notification bytes changed");}}}}
let sp=CrtCpu::pointer(cpu.r[4])?;let entry=CrtCpu::pointer(cpu.entry[4])?;
if cpu.returned||cpu.return_id==0||sp.cap!=storage.entry.cap||entry.cap!=sp.cap||sp.address()>entry.address()||sp.address()>=storage.image.esp||cpu.r[0]!=CrtValue::Pointer(target)||cpu.r[5]!=CrtValue::Pointer(frame)||!record.registry.module_contains_address({continuation})||rt.load(entry,32)?!=CrtValue::ProtectedReturn(cpu.return_id)||rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(cpu.return_id)).count()!=1{{return Err("notification live caller authority");}}
let low=rt.offset(sp,-{scratch})?;rt.valid(low,{scratch})?;record.registry.range(low.address(),u64::from(sp.address()))?;
if rt.overlapping_tags(low.address(),{scratch}).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_)))||record.registry.temporary.iter().any(|t|u64::from(low.address())<t.high&&u64::from(t.low)<u64::from(sp.address())){{return Err("notification private stack alias");}}cpu.push(rt,CrtValue::scalar(reason))?;
cpu.call_activation(rt,{continuation},4,|rt,cpu|{{let registers=cpu.r.map(BridgeValue::Capability);let argument=BridgeValue::Scalar(reason);let mut store=|at:u32,value:&BridgeValue<CrtValue>|->RegistryResult<()>{{
let expected=match at{{{target_word}=>BridgeValue::Capability(CrtValue::Pointer(target)),{action_word}=>BridgeValue::Scalar(reason),{frame_word}=>BridgeValue::Capability(CrtValue::Pointer(frame)),_=>return Err("notification word role")}};
if *value!=expected||reason!=0x101{{return Err("notification original value authority");}}let value=match value{{BridgeValue::Scalar(v)=>CrtValue::scalar(*v),BridgeValue::Capability(v)=>*v,_=>return Err("notification unbound value")}};rt.store(rt.resolve_absolute(at,CrtRegionKind::Module)?,32,value)}};
let result=(||->RegistryResult<BridgeExit<CrtValue>>{{type T=CrtValue;{body}}})();let BridgeExit::Return{{registers,cleanup}}=result? else{{return Err("notification nonlocal exit");}};
if cleanup!=4||registers[4]!=BridgeValue::PrivateStack(0){{return Err("notification original ABI");}}for(i,v)in registers.into_iter().enumerate(){{if i!=4{{cpu.r[i]=match v{{BridgeValue::Capability(v)=>v,BridgeValue::Scalar(v)=>CrtValue::scalar(v),_=>return Err("notification register knowledge")}};}}}}cpu.finish_pop(rt,4)
}})?;require_original_notification(rt,storage,target.address(),reason)
}}
fn require_original_notification(rt:&CrtStreamRuntime,storage:&CrtOwnedStorage,target:u32,reason:u32)->RegistryResult<()>{{let frame=rt.resolve_absolute(storage.image.ebp,CrtRegionKind::Stack)?;let target=rt.resolve_absolute(target,CrtRegionKind::Module)?;for(at,v)in [({target_word},CrtValue::Pointer(target)),({action_word},CrtValue::scalar(reason)),({frame_word},CrtValue::Pointer(frame))]{{if rt.load(rt.resolve_absolute(at,CrtRegionKind::Module)?,32)?!=v{{return Err("notification live result changed");}}}}Ok(())}}
"#,
        length = code.len(),
        code = code,
        body = proof.body(),
        target_word = binding.target_word,
        action_word = binding.action_word,
        frame_word = binding.frame_word,
        record_base = record_base,
        scratch = proof
            .temporary_bytes
            .checked_add(8)
            .ok_or("notification call depth overflow")?
    ))
}
pub(crate) const EMITTED_TYPES: &str = r#"
struct CrtOwnedStorage {
 anchor:guest_memory::Capability,identity:RegistryIdentity,binding:OwnedFrameBinding,id:RegistrationId,event:u64,
 entry:CrtPointer,return_id:u64,image:FrameImage<RegistryHead>,ordinary:std::collections::BTreeSet<i32>,
 protected:std::collections::BTreeMap<i32,CrtValue>,input:Option<(Option<CrtPointer>,CrtPointer,CrtPointer,u32)>,pair_return:Option<(CrtPointer,u64)>,unwind_epoch:Option<u64>,
}
impl RegistryFrameStorage for CrtOwnedStorage{fn registry_image(&self)->&FrameImage<RegistryHead>{&self.image}}
impl CrtOwnedStorage {
 fn initialize(rt:&mut CrtStreamRuntime,r:&mut ThreadRegistry,m:&Machine,binding:OwnedFrameBinding,cpu:&CrtCpu,image:FrameImage<RegistryHead>,ordinary:&[i32])->RegistryResult<Self>{
  m.check_raise_binding(binding).map_err(|_|"owned initializer event phase")?;
  if rt.closed||rt.initialization.is_some()||rt.shutdown.is_some()||r.identity.owner!=m.owner||rt.owner!=m.owner||rt.thread!=r.identity.instance||r.normal_epoch.is_some()||r.selected.is_some()||!r.handlers.is_empty()||!r.temporary.is_empty()||r.borrowed_depth!=0||r.frames.len()>=64
   ||r.frames.iter().any(|f|f.binding.frame==binding.frame||f.binding.index==binding.index)
   ||cpu.returned||cpu.r!=cpu.entry||cpu.return_id==0{return Err("owned initializer identity/entry");}
  let entry=CrtCpu::pointer(cpu.entry[4])?;
  if entry.kind!=CrtRegionKind::Stack||entry.address()!=image.entry_sp||rt.load(entry,32)?!=CrtValue::ProtectedReturn(cpu.return_id){return Err("owned original caller return");}
  let low=rt.offset(entry,i64::from(image.esp)-i64::from(image.entry_sp))?;let extent=image.entry_sp.checked_sub(image.esp).ok_or("owned frame extent")?;
  rt.valid(low,extent+4)?;r.range(low.address(),u64::from(image.entry_sp)+4)?;
  if !rt.overlapping_tags(low.address(),extent).is_empty()||r.frames.iter().any(|f|f.live&&u64::from(low.address())<f.high&&u64::from(f.low)<u64::from(image.entry_sp)+4){return Err("owned initializer storage overlap");}
  let token=rt.thread_head(r.identity.instance,binding.frame.generation,CrtNormalBinding::head_bits(r.head()?))?;
  let keys=ordinary.iter().map(|&o|i32::try_from(i64::from(image.ebp)-i64::from(image.entry_sp)+i64::from(o)).map_err(|_|"owned ordinary offset")).collect::<Result<std::collections::BTreeSet<_>,_>>()?;
  let mut writes=Vec::new();let mut protected=std::collections::BTreeMap::new();
  for(&key,word)in &image.words{
   let p=rt.offset(entry,i64::from(key))?;rt.valid(p,4)?;
   let value=match word{
    FrameWord::Unknown=>continue,
    FrameWord::Return=>{if key!=0{return Err("owned return placement");}CrtValue::ProtectedReturn(cpu.return_id)},
    FrameWord::Saved(reg,known)=>{let v=*cpu.entry.get(*reg as usize).ok_or("owned saved register")?;if known.is_some_and(|n|v.known_scalar()!=Ok(n)){return Err("owned saved knowledge");}v},
    FrameWord::Borrowed(previous)=>{if *previous!=r.head()?{return Err("owned predecessor");}CrtValue::ThreadHead(token)},
    FrameWord::Scalar(n)|FrameWord::Cookie(n)=>CrtValue::scalar(*n),
    FrameWord::EncodedScope{bits,..}|FrameWord::Guard{bits,..}=>CrtValue::scalar(*bits),
    FrameWord::StackAddress(at)=>CrtValue::Pointer(rt.resolve_absolute(*at,CrtRegionKind::Stack)?),
    _=>return Err("owned initializer unsupported word role"),
   };
   if !keys.contains(&key){protected.insert(key,value);}
   if key!=0{writes.push((p,value));}
  }
  // All ranges and roles are checked before the original private prolog stores.
  // No external callback occurs before final registry installation.
  for(p,value)in writes{rt.store(p,32,value)?;}
  let id=r.install_frame(binding,&image)?;
  Ok(Self{anchor:rt.anchor,identity:r.identity,binding,id,event:m.event,entry,return_id:cpu.return_id,image,ordinary:ordinary.iter().copied().collect(),protected,input:None,pair_return:None,unwind_epoch:None})
 }
 fn validate(&self,rt:&CrtStreamRuntime,r:&ThreadRegistry,m:&Machine)->RegistryResult<()>{
  self.validate_storage(rt,r,m)?;
  if !m.event_issued||m.phase!=Phase::Cleanup||!m.explicit_dispatch{return Err("owned callback event phase");}
  r.expected_callback(self.id)
 }
 fn validate_storage(&self,rt:&CrtStreamRuntime,r:&ThreadRegistry,m:&Machine)->RegistryResult<()>{
  if rt.closed||rt.initialization.is_some()||rt.shutdown.is_some()||rt.anchor!=self.anchor||r.identity!=self.identity||rt.owner!=m.owner||rt.thread!=self.identity.instance
   ||m.owner!=self.binding.owner||m.event!=self.event
   ||m.owned_binding(self.binding.index).map_err(|_|"owned binding expired")?!=self.binding
   ||!m.frames[self.binding.index].live||r.registration(self.binding)?!=self.id{return Err("owned live source identity/phase");}
  r.validate_frame(self.id,&self.image)?;
  rt.valid(rt.offset(self.entry,i64::from(self.image.esp)-i64::from(self.image.entry_sp))?,self.image.entry_sp-self.image.esp+4)?;
  for(&offset,&value)in &self.protected{if rt.load(rt.offset(self.entry,i64::from(offset))?,32)?!=value{return Err("owned live protected word changed");}}
  for(&at,&value)in rt.tags.range(self.image.esp..=self.image.entry_sp){
   if matches!(value,CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)|CrtValue::OpaqueSaved(_)){
    let key=i32::try_from(i64::from(at)-i64::from(self.image.entry_sp)).map_err(|_|"owned control offset")?;
    if self.protected.get(&key)!=Some(&value){return Err("owned unexpected protected alias");}
   }
  }
  if rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(self.return_id)).count()!=1{return Err("owned return alias");}
  if rt.load(rt.resolve_absolute(r.cookie_address,CrtRegionKind::Module)?,32)?.known_scalar()?!=r.frames[r.frame_index(self.id)?].cookie{return Err("owned cookie module changed");}
  if let Some((pair,record,context,code))=self.input{
   rt.valid(record,80)?;rt.valid(context,716)?;
   if rt.load(record,32)?.known_scalar()?!=code{return Err("owned captured code changed");}
   if let Some(pair)=pair{
    let owner_slot=rt.offset(self.entry,i64::from(self.image.ebp)-i64::from(self.image.entry_sp)-20)?;
    if rt.load(owner_slot,32)?!=CrtValue::Pointer(pair)||rt.load(pair,32)?!=CrtValue::Pointer(record)||rt.load(rt.offset(pair,4)?,32)?!=CrtValue::Pointer(context){return Err("owned captured input graph changed");}
   }
   if let Some((entry,id))=self.pair_return{
    if rt.load(entry,32)?!=CrtValue::ProtectedReturn(id)||rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(id)).count()!=1{return Err("owned installed pair lifetime");}
   }
  }Ok(())
 }
 fn store_level(&mut self,rt:&mut CrtStreamRuntime,r:&ThreadRegistry,m:&Machine,base:CrtValue,value:CrtValue,before:i32,after:i32)->RegistryResult<()>{
  self.validate(rt,r,m)?;let owner=rt.offset(self.entry,i64::from(self.image.ebp)-i64::from(self.image.entry_sp))?;
  if base!=CrtValue::Pointer(rt.offset(owner,-16)?)||self.image.try_level!=before
   ||value.known_scalar()?!=after as u32||after< -2||after== -1{return Err("owned original scope store operands/state");}
  let key=i32::try_from(i64::from(self.image.record)+12-i64::from(self.image.entry_sp)).map_err(|_|"owned scope word offset")?;
  if self.protected.get(&key)!=Some(&CrtValue::scalar(before as u32)){return Err("owned original scope store role");}
  rt.store(rt.offset(self.entry,i64::from(key))?,32,value)?;
  self.protected.insert(key,value);self.image.words.insert(key,FrameWord::Scalar(after as u32));self.image.try_level=after;self.validate(rt,r,m)

 }
 fn store_local_level(&mut self,rt:&mut CrtStreamRuntime,local:&mut LocalRecord<'_>,m:&Machine,base:CrtValue,value:CrtValue,before:i32,after:i32)->RegistryResult<()>{
  local.validate_binding(self.binding,&self.image)?;
  if local.frame()?!=self.id||local.registry.handlers.last()!=Some(&self.id){return Err("owned local cleanup lifetime");}
  self.store_level(rt,local.registry,m,base,value,before,after)
 }
 fn scope_store(&mut self,rt:&mut CrtStreamRuntime,r:&ThreadRegistry,m:&Machine,before:i32,after:i32)->RegistryResult<()>{
  m.check_raise_binding(self.binding).map_err(|_|"owned activation after event/phase")?;
  self.validate_storage(rt,r,m)?;
  if r.head()?!=RegistryHead::Owned(self.id)||r.normal_epoch.is_some()||r.selected.is_some()||!r.handlers.is_empty()||!r.temporary.is_empty()||r.borrowed_depth!=0||self.input.is_some()||self.image.try_level!=before{return Err("owned activation source/replay");}
  let key=i32::try_from(i64::from(self.image.record)+12-i64::from(self.image.entry_sp)).map_err(|_|"owned level offset")?;
  if self.protected.get(&key)!=Some(&CrtValue::scalar(before as u32)){return Err("owned activation level role");}
  rt.store(rt.offset(self.entry,i64::from(key))?,32,CrtValue::scalar(after as u32))?;
  self.protected.insert(key,CrtValue::scalar(after as u32));self.image.words.insert(key,FrameWord::Scalar(after as u32));self.image.try_level=after;Ok(())
 }
 fn bind_input(&mut self,rt:&CrtStreamRuntime,r:&ThreadRegistry,m:&Machine,pair:CrtPointer,record:CrtPointer,context:CrtPointer,code:u32)->RegistryResult<()>{
  self.validate(rt,r,m)?;
  if self.input.is_some()||[pair,record,context].iter().any(|p|p.kind!=CrtRegionKind::Context){return Err("owned input roles/replay");}
  self.input=Some((Some(pair),record,context,code));self.validate(rt,r,m)
 }
 fn bind_captured(&mut self,rt:&CrtStreamRuntime,r:&ThreadRegistry,m:&Machine,record:CrtPointer,context:CrtPointer,code:u32)->RegistryResult<()>{
  self.validate(rt,r,m)?;
  if self.input.is_some()||record.kind!=CrtRegionKind::Context||context.kind!=CrtRegionKind::Context{return Err("owned captured roles/replay");}
  rt.valid(record,80)?;rt.valid(context,716)?;if rt.load(record,32)?.known_scalar()?!=code{return Err("owned captured code");}
  self.input=Some((None,record,context,code));self.validate(rt,r,m)
 }
}
struct CrtOwnedFrameView<'a>{rt:&'a mut CrtStreamRuntime,registry:&'a ThreadRegistry,machine:&'a Machine,storage:&'a mut CrtOwnedStorage,active:u64,depth:u32,calls:u32,failed:bool}
impl CrtOwnedFrameView<'_>{
 fn scope_address(&self)->u32{self.storage.image.scope_va}
 fn cookie_address(&self)->u32{self.registry.cookie_address}
 fn validate(&self)->RegistryResult<()>{if self.failed||self.depth>32||self.calls>4096{return Err("owned filter call failed/budget");}self.storage.validate(self.rt,self.registry,self.machine)}
 fn active_call(&self)->u64{self.active}
 fn stack_range(&self,low:u32,high:u64)->RegistryResult<()>{self.registry.range(low,high)}
 fn preflight_bridge(&self,cpu:&CrtCpu,bytes:u32)->RegistryResult<()>{
  self.validate()?;let sp=CrtCpu::pointer(cpu.r[4])?;
  if bytes==0||bytes>256||cpu.returned||cpu.return_id!=self.active||cpu.r[4]!=cpu.entry[4]
   ||sp.cap!=self.storage.entry.cap||sp.address()>=self.storage.image.esp
   ||self.rt.load(sp,32)?!=CrtValue::ProtectedReturn(cpu.return_id)||self.rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(cpu.return_id)).count()!=1{return Err("owned bridge entry/scratch alias");}
  let low=self.rt.offset(sp,-i64::from(bytes))?;self.rt.valid(low,bytes)?;self.registry.range(low.address(),u64::from(sp.address()))?;
  if self.rt.overlapping_tags(low.address(),bytes).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_))){return Err("owned bridge protected scratch");}Ok(())
 }
 fn call<F>(&mut self,cpu:&mut CrtCpu,continuation:u32,body:F)->RegistryResult<CrtValue>
 where F:FnOnce(&mut CrtOwnedFrameView<'_>,&mut CrtCpu)->RegistryResult<CrtValue>{
  let result=(||{
   self.validate()?;let sp=CrtCpu::pointer(cpu.r[4])?;
   if self.depth>=32||self.calls>=4096||cpu.returned||cpu.return_id!=self.active
    ||sp.cap!=self.storage.entry.cap||sp.address()>CrtCpu::pointer(cpu.entry[4])?.address()
    ||sp.address()>=self.storage.image.esp||!self.registry.module_contains_address(continuation)
    ||self.rt.load(CrtCpu::pointer(cpu.entry[4])?,32)?!=CrtValue::ProtectedReturn(cpu.return_id)||self.rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(cpu.return_id)).count()!=1{return Err("owned filter call activation/scratch");}
   self.registry.range(self.rt.offset(sp,-4)?.address(),u64::from(sp.address()))?;
   let parent=self.active;self.depth+=1;self.calls+=1;
   let value=cpu.call_activation(self.rt,continuation,0,|rt,child|{
    let mut view=CrtOwnedFrameView{rt,registry:self.registry,machine:self.machine,storage:self.storage,active:child.return_id,depth:self.depth,calls:self.calls,failed:false};
    let result=body(&mut view,child);self.calls=view.calls;
    match result{Ok(v)=>{view.validate()?;Ok(v)},Err(e)=>Err(e)}
   });self.depth-=1;self.active=parent;value
  })();if result.is_err(){self.failed=true;}result
 }
 fn owner_frame(&self)->RegistryResult<CrtPointer>{self.validate()?;self.rt.offset(self.storage.entry,i64::from(self.storage.image.ebp)-i64::from(self.storage.image.entry_sp))}
 fn at(&self,offset:i32)->RegistryResult<CrtPointer>{self.validate()?;if offset%4!=0||!self.storage.ordinary.contains(&offset){return Err("owned ordinary word bounds/role");}self.rt.offset(self.owner_frame()?,i64::from(offset))}
 fn read(&self,offset:i32)->RegistryResult<CrtValue>{if offset== -20&&self.storage.input.is_none_or(|(pair,_,_,_)|pair.is_none()){return Err("owned unbound exception pair");}self.rt.load(self.at(offset)?,32)}
 fn write_u32(&mut self,offset:i32,value:u32)->RegistryResult<()>{let p=self.at(offset)?;self.rt.store(p,32,CrtValue::scalar(value))}
 /// Original MOV to protected TryLevel only. Selection/unwind completion is
 /// a separate caller proof; this store cannot move Machine into Restore.
 fn store_level_operand(&mut self,base:CrtValue,value:CrtValue,before:i32,after:i32)->RegistryResult<()>{
  self.validate()?;self.storage.store_level(self.rt,self.registry,self.machine,base,value,before,after)
 }
}
/// Captured objects and callback entry remain explicit inputs, tied to the
/// owned event. This token neither synthesizes CONTEXT nor authorizes resumption.
struct CrtOwnedPrefixInput {
 identity:RegistryIdentity,event:u64,binding:OwnedFrameBinding,id:RegistrationId,
 anchor:guest_memory::Capability,entry:[CrtValue;8],callback:u64,
 record:CrtPointer,context:CrtPointer,code:u32,captured_esp:u32,
}
impl CrtOwnedPrefixInput {
 fn bind(frame:&CrtOwnedFrameView<'_>,cpu:&CrtCpu,record:CrtPointer,context:CrtPointer,handler:u32,temporary:u32)->RegistryResult<Self>{
  frame.validate()?;
  let Some((_,bound_record,bound_context,_))=frame.storage.input else{return Err("owned prefix missing captured input");};
  if record!=bound_record||context!=bound_context{return Err("owned prefix captured object identity");}
  if frame.storage.image.handler_va!=handler||frame.storage.image.try_level!=0||!frame.registry.module_contains_address(handler)
   ||temporary==0||temporary>256||cpu.r[4]!=cpu.entry[4]||record.kind!=CrtRegionKind::Context||context.kind!=CrtRegionKind::Context
   ||(u64::from(record.address())<u64::from(context.address())+716&&u64::from(context.address())<u64::from(record.address())+80){return Err("owned prefix entry/layout/objects");}
  let sp=CrtCpu::pointer(cpu.r[4])?;
  if sp.cap!=frame.storage.entry.cap||sp.address()%4!=0||sp.address().checked_add(20).is_none_or(|end|end>frame.storage.image.esp){return Err("owned prefix entry stack alias");}
  let low=frame.rt.offset(sp,-i64::from(temporary))?;frame.rt.valid(low,temporary+20)?;frame.registry.range(low.address(),u64::from(sp.address())+20)?;
  if !frame.rt.overlapping_tags(low.address(),temporary).is_empty(){return Err("owned prefix typed scratch overlap");}
  frame.rt.valid(record,80)?;frame.rt.valid(context,716)?;
  let captured_esp=frame.rt.load(frame.rt.offset(context,0xc4)?,32)?.known_scalar()?;
  let code=frame.rt.load(record,32)?.known_scalar()?;
  let result=Self{identity:frame.registry.identity,event:frame.machine.event,binding:frame.storage.binding,id:frame.storage.id,anchor:frame.rt.anchor,entry:cpu.entry,callback:cpu.return_id,record,context,code,captured_esp};
  result.validate(frame,cpu)?;Ok(result)
 }
 fn validate(&self,frame:&CrtOwnedFrameView<'_>,cpu:&CrtCpu)->RegistryResult<()>{
  self.validate_prefix_source(frame)?;
  if cpu.returned||cpu.entry!=self.entry||cpu.return_id!=self.callback||frame.active!=self.callback{return Err("owned prefix callback activation changed");}Ok(())
 }
 fn validate_prefix_source(&self,frame:&CrtOwnedFrameView<'_>)->RegistryResult<()>{
  if frame.storage.unwind_epoch.is_some(){return Err("owned search input suspended by unwind");}
  self.validate_source_fields(frame,0)
 }
 fn validate_source_fields(&self,frame:&CrtOwnedFrameView<'_>,record_flags:u32)->RegistryResult<()>{
  frame.validate()?;let sp=CrtCpu::pointer(self.entry[4])?;
  if frame.storage.input.is_none_or(|(_,record,context,_)|record!=self.record||context!=self.context){return Err("owned prefix captured object binding changed");}
  if self.identity!=frame.registry.identity||self.event!=frame.machine.event||self.binding!=frame.storage.binding||self.id!=frame.storage.id||self.anchor!=frame.rt.anchor
   ||frame.rt.load(sp,32)?!=CrtValue::ProtectedReturn(self.callback)
   ||frame.rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(self.callback)).count()!=1
   ||self.captured_esp<frame.registry.limit||self.captured_esp>frame.registry.base{return Err("owned prefix stale callback/event/context");}
  frame.rt.valid(self.record,80)?;frame.rt.valid(self.context,716)?;
  for(offset,value)in [(0,self.code),(4,record_flags),(8,0),(16,0)]{if frame.rt.load(frame.rt.offset(self.record,offset)?,32)?.known_scalar()?!=value{return Err("owned prefix record fields");}}
  if frame.rt.load(frame.rt.offset(self.context,0xc4)?,32)?.known_scalar()?!=self.captured_esp{return Err("owned prefix captured ESP changed");}
  let establisher=frame.rt.offset(frame.storage.entry,i64::from(frame.storage.image.record)-i64::from(frame.storage.image.entry_sp))?;
  for(i,value)in [CrtValue::Pointer(self.record),CrtValue::Pointer(establisher),CrtValue::Pointer(self.context),CrtValue::scalar(0)].into_iter().enumerate(){
   if frame.rt.load(frame.rt.offset(sp,4+i as i64*4)?,32)?!=value{return Err("owned prefix callback argument provenance");}
  }Ok(())
 }
 /// Consume the original prefix's actual final installer stores, not a projected pair.
 fn installed(&self,frame:&mut CrtOwnedFrameView<'_>,cpu:&CrtCpu)->RegistryResult<()>{
  self.validate(frame,cpu)?;
  if frame.storage.input.is_none_or(|(pair,_,_,_)|pair.is_some())||frame.storage.pair_return.is_some(){return Err("owned prefix pair installation replay");}
  let entry=CrtCpu::pointer(self.entry[4])?;let bp=frame.rt.offset(entry,-4)?;let pair=frame.rt.offset(bp,-28)?;
  if cpu.r[5]!=CrtValue::Pointer(bp)||cpu.r[4]!=CrtValue::Pointer(frame.rt.offset(bp,-40)?)||cpu.r[0]!=CrtValue::Pointer(pair){return Err("owned prefix final stack/pair");}
  let owner=frame.owner_frame()?;let record=frame.rt.offset(owner,-16)?;
  if cpu.r[3]!=CrtValue::Pointer(record)||frame.rt.load(bp,32)?!=self.entry[5]{return Err("owned prefix owner/saved EBP");}
  for(offset,reg)in [(-32,3),(-36,6),(-40,7)]{if frame.rt.load(frame.rt.offset(bp,offset)?,32)?!=self.entry[reg]{return Err("owned prefix saved registers");}}
  if frame.rt.load(frame.rt.offset(owner,-20)?,32)?!=CrtValue::Pointer(pair)||frame.rt.load(pair,32)?!=CrtValue::Pointer(self.record)||frame.rt.load(frame.rt.offset(pair,4)?,32)?!=CrtValue::Pointer(self.context){return Err("owned prefix actual installer graph");}
  frame.storage.input=Some((Some(pair),self.record,self.context,self.code));frame.storage.pair_return=Some((entry,self.callback));frame.validate()
 }
}
/// An API-boundary lifetime, not an RtlUnwind implementation or completion
/// receipt. Delivery objects remain explicit provider inputs. The search
/// context is retained for identity checks and is never used as call registers.
struct CrtOwnedUnwind<'a>{
 source:&'a CrtOwnedPrefixInput,epoch:u64,wrapper_entry:CrtPointer,wrapper_id:u64,api_sp:CrtPointer,
 captured:Vec<CrtValue>,active:Vec<(u64,CrtPointer,CrtPointer,u64)>,used:Vec<CrtPointer>,serial:u64,failed:bool,
}
struct CrtUnwindDelivery{
 epoch:u64,serial:u64,context:CrtPointer,entry:CrtPointer,callback:u64,captured_esp:u32,snapshot:Vec<CrtValue>,
}
impl CrtOwnedUnwind<'_>{
 fn context_words(rt:&CrtStreamRuntime,p:CrtPointer)->RegistryResult<Vec<CrtValue>>{
  if p.kind!=CrtRegionKind::Context||p.address()%4!=0{return Err("unwind context role/alignment");}
  rt.valid(p,716)?;(0..179).map(|i|rt.load(rt.offset(p,i*4)?,32)).collect()
 }
 fn overlap(a:CrtPointer,an:u32,b:CrtPointer,bn:u32)->bool{u64::from(a.address())<u64::from(b.address())+u64::from(bn)&&u64::from(b.address())<u64::from(a.address())+u64::from(an)}
 fn begin<'a>(frame:&mut CrtOwnedFrameView<'_>,cpu:&CrtCpu,source:&'a CrtOwnedPrefixInput,private_bytes:u32)->RegistryResult<CrtOwnedUnwind<'a>>{
  source.validate_prefix_source(frame)?;
  let entry=CrtCpu::pointer(cpu.entry[4])?;let api_sp=CrtCpu::pointer(cpu.r[4])?;
  if private_bytes<16||private_bytes>256||private_bytes%4!=0||cpu.returned||cpu.return_id!=frame.active||cpu.return_id==source.callback
   ||frame.storage.unwind_epoch.is_some()||entry.cap!=frame.storage.entry.cap
   ||api_sp.cap!=entry.cap||api_sp.address().checked_add(private_bytes)!=Some(entry.address())
   ||entry.address()>=CrtCpu::pointer(source.entry[4])?.address()
   ||frame.rt.load(entry,32)?!=CrtValue::ProtectedReturn(cpu.return_id)
   ||frame.rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(cpu.return_id)).count()!=1{return Err("unwind wrapper activation/stack");}
  // The caller's instruction/IAT proof binds TargetIp and the four arguments.
  // This boundary records ownership only and cannot approve an arbitrary API.
  let captured=Self::context_words(frame.rt,source.context)?;
  let epoch=frame.rt.generation.checked_add(1).ok_or("unwind generation exhausted")?;
  frame.rt.generation=epoch;frame.storage.unwind_epoch=Some(epoch);
  Ok(CrtOwnedUnwind{source,epoch,wrapper_entry:entry,wrapper_id:cpu.return_id,api_sp,captured,active:vec![],used:vec![],serial:0,failed:false})
 }
 fn validate(&self,frame:&CrtOwnedFrameView<'_>)->RegistryResult<()>{
  if self.failed||frame.storage.unwind_epoch!=Some(self.epoch){return Err("unwind stale/failed lifetime");}
  self.source.validate_source_fields(frame,2)?;
  if frame.rt.load(self.wrapper_entry,32)?!=CrtValue::ProtectedReturn(self.wrapper_id)
   ||frame.rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(self.wrapper_id)).count()!=1
   ||Self::context_words(frame.rt,self.source.context)?!=self.captured{return Err("unwind captured context/wrapper changed");}
  Ok(())
 }
 /// Scoped explicit delivery cut. The provider must independently establish
 /// record flags and CONTEXT bytes. No sampled CONTEXT is synthesized here.
 /// Failure retains effects and poisons the enclosing call; no receipt is made.
 fn with_delivery<T,F>(&mut self,frame:&mut CrtOwnedFrameView<'_>,cpu:&mut CrtCpu,context:CrtPointer,body:F)->RegistryResult<T>
 where F:FnOnce(&mut Self,&mut CrtOwnedFrameView<'_>,&mut CrtCpu,&CrtUnwindDelivery)->RegistryResult<T>{
  let parent=frame.active;
  let result=(||{
   self.validate(frame)?;
   if frame.active!=self.active.last().map(|(_,_,_,id)|*id).unwrap_or(self.wrapper_id){return Err("unwind parent activation changed");}
   if self.active.len()>=16||self.used.len()>=64||cpu.returned||cpu.r!=cpu.entry||cpu.return_id==0
    ||cpu.return_id==self.source.callback||cpu.return_id==self.wrapper_id
    ||self.active.iter().any(|(_,_,_,id)|*id==cpu.return_id)
    ||Self::overlap(context,716,self.source.record,80)||Self::overlap(context,716,self.source.context,716)
    ||self.active.iter().any(|(_,p,_,_)|Self::overlap(context,716,*p,716)){return Err("unwind delivery identity/alias/budget");}
   let entry=CrtCpu::pointer(cpu.entry[4])?;
   let ceiling=self.active.last().map(|(_,_,p,_)|p.address().saturating_sub(32)).unwrap_or(self.api_sp.address());
   if entry.kind!=CrtRegionKind::Stack||entry.cap!=self.api_sp.cap||entry.address()%4!=0
    ||entry.address().checked_add(20).is_none_or(|n|n>ceiling)
    ||frame.rt.load(entry,32)?!=CrtValue::ProtectedReturn(cpu.return_id)
    ||frame.rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(cpu.return_id)).count()!=1{return Err("unwind delivery callback stack");}
   let low=frame.rt.offset(entry,-32)?;frame.rt.valid(low,52)?;frame.registry.range(low.address(),u64::from(entry.address())+20)?;
   if !frame.rt.overlapping_tags(low.address(),32).is_empty(){return Err("unwind delivery protected scratch");}
   let snapshot=Self::context_words(frame.rt,context)?;
   let captured_esp=snapshot[0xc4/4].known_scalar()?;
   if captured_esp<frame.registry.limit||captured_esp>frame.registry.base{return Err("unwind delivery captured stack bounds");}
   let owner=frame.rt.offset(frame.storage.entry,i64::from(frame.storage.image.record)-i64::from(frame.storage.image.entry_sp))?;
   for(i,v)in [CrtValue::Pointer(self.source.record),CrtValue::Pointer(owner),CrtValue::Pointer(context),CrtValue::scalar(0)].into_iter().enumerate(){
    if frame.rt.load(frame.rt.offset(entry,4+i as i64*4)?,32)?!=v{return Err("unwind delivery argument provenance");}
   }
   let serial=self.serial.checked_add(1).ok_or("unwind delivery serial exhausted")?;self.serial=serial;
   let token=CrtUnwindDelivery{epoch:self.epoch,serial,context,entry,callback:cpu.return_id,captured_esp,snapshot};
   self.active.push((serial,context,entry,cpu.return_id));self.used.push(context);frame.active=cpu.return_id;
   let value=body(self,frame,cpu,&token)?;
   self.validate_delivery(frame,cpu,&token)?;self.active.pop();Ok(value)
  })();frame.active=parent;
  if result.is_err(){self.failed=true;frame.failed=true;}result
 }
 /// Completed delivery scopes alone cannot satisfy this boundary. Registry
 /// retirement must account for every younger owned registration. This is a
 /// prerequisite check, never an API completion or Machine restoration token.
 fn check_cleanup_boundary(&self,frame:&CrtOwnedFrameView<'_>,cpu:&CrtCpu,target_ip:u32)->RegistryResult<()>{
  self.validate(frame)?;
  if !self.active.is_empty()||frame.active!=self.wrapper_id||cpu.returned||cpu.return_id!=self.wrapper_id
   ||CrtCpu::pointer(cpu.entry[4])?!=self.wrapper_entry||cpu.r[4]!=CrtValue::Pointer(self.api_sp)
   ||frame.registry.target_ready()?!=frame.storage.id||target_ip==0||!frame.registry.module_contains_address(target_ip){return Err("unwind cleanup/continuation boundary");}
  let owner=frame.rt.offset(frame.storage.entry,i64::from(frame.storage.image.record)-i64::from(frame.storage.image.entry_sp))?;
  for(i,v)in [CrtValue::Pointer(owner),CrtValue::scalar(target_ip),CrtValue::Pointer(self.source.record),CrtValue::scalar(0)].into_iter().enumerate(){
   if frame.rt.load(frame.rt.offset(self.api_sp,i as i64*4)?,32)?!=v{return Err("unwind continuation arguments changed");}
  }Ok(())
 }
 fn validate_delivery(&self,frame:&CrtOwnedFrameView<'_>,cpu:&CrtCpu,token:&CrtUnwindDelivery)->RegistryResult<()>{
  self.validate(frame)?;
  if token.epoch!=self.epoch||self.active.last()!=Some(&(token.serial,token.context,token.entry,token.callback))
   ||frame.active!=token.callback||cpu.returned||cpu.return_id!=token.callback||CrtCpu::pointer(cpu.entry[4])?!=token.entry
   ||frame.rt.load(token.entry,32)?!=CrtValue::ProtectedReturn(token.callback)
   ||frame.rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(token.callback)).count()!=1
   ||Self::context_words(frame.rt,token.context)?!=token.snapshot{return Err("unwind delivery lifetime/context changed");}
  let owner=frame.rt.offset(frame.storage.entry,i64::from(frame.storage.image.record)-i64::from(frame.storage.image.entry_sp))?;
  for(i,v)in [CrtValue::Pointer(self.source.record),CrtValue::Pointer(owner),CrtValue::Pointer(token.context),CrtValue::scalar(0)].into_iter().enumerate(){
   if frame.rt.load(frame.rt.offset(token.entry,4+i as i64*4)?,32)?!=v{return Err("unwind delivery arguments changed");}
  }
  // A comparison snapshot has no restoration/writeback authority.
  Ok(())
 }
}

/// Adapter for the instruction-proved ordinary local body. Callback providers
/// remain separate compiler obligations; this type grants no API admission.
struct CrtOwnedTemporary{base:CrtPointer,id:RegistrationId,shape:[RegistryWord;7],words:[CrtValue;7]}
impl CrtOwnedTemporary{
 fn bind(rt:&mut CrtStreamRuntime,record:&mut LocalRecord<'_>,storage:&CrtOwnedStorage)->RegistryResult<Self>{
  let index=record.active_index()?;let t=&record.registry.temporary[index];
  if t.installed||t.restored||t.frame!=storage.id{return Err("owned temporary installation lifetime");}
  let base=rt.resolve_absolute(t.low,CrtRegionKind::Stack)?;rt.valid(base,28)?;
  if rt.overlapping_tags(base.address(),28).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_))){return Err("owned temporary protected alias");}
  let mut words=[CrtValue::scalar(0);7];
  for(i,word)in t.words.iter().enumerate(){words[i]=match *word{
   RegistryWord::Previous(head)=>CrtValue::ThreadHead(rt.thread_head(record.registry.identity.instance,t.id.generation,CrtNormalBinding::head_bits(head))?),
   RegistryWord::Handler(at)|RegistryWord::CookieAddress(at)=>CrtValue::Pointer(rt.resolve_absolute(at,CrtRegionKind::Module)?),
   RegistryWord::Guard{bits,..}|RegistryWord::Scalar(bits)=>CrtValue::scalar(bits),
   RegistryWord::Establisher(id,at)|RegistryWord::FramePointer(id,at)=>{if id!=storage.id{return Err("owned temporary frame provenance");}CrtValue::Pointer(rt.resolve_absolute(at,CrtRegionKind::Stack)?)},
  };}
  // Full preflight precedes the private stores; no callback runs between these
  // original private initialization effects and the bound MOV FS instruction.
  for(i,v)in words.iter().enumerate(){rt.store(rt.offset(base,i as i64*4)?,32,*v)?;}
  Ok(Self{base,id:t.id,shape:t.words,words})
 }
 fn validate(&self,rt:&CrtStreamRuntime,record:&LocalRecord<'_>)->RegistryResult<()>{
  let t=&record.registry.temporary[record.active_index()?];if t.id!=self.id||!t.installed||t.low!=self.base.address()||t.words!=self.shape{return Err("owned temporary stale source");}
  for(i,v)in self.words.iter().enumerate(){if rt.load(rt.offset(self.base,i as i64*4)?,32)?!=*v{return Err("owned temporary live word changed");}}Ok(())
 }
 fn discard(self,rt:&mut CrtStreamRuntime)->RegistryResult<()>{for(i,v)in self.words.into_iter().enumerate(){rt.consume_stack(rt.offset(self.base,i as i64*4)?,v)?;}Ok(())}
}

struct CrtOwnedLocalEffects<'a,'r,F,N>{
 rt:&'a mut CrtStreamRuntime,record:&'a mut LocalRecord<'r>,machine:&'a Machine,storage:&'a mut CrtOwnedStorage,
 rows:&'a[LocalScope],temporary:Option<CrtOwnedTemporary>,pending:Option<(i32,LocalScope)>,written:bool,notified:bool,finally:F,notification:N,
}
impl<F,N> CrtOwnedLocalEffects<'_,'_,F,N>
where F:FnMut(u32,i32,&mut CrtStreamRuntime,&mut CrtOwnedStorage,&mut LocalRecord<'_>)->RegistryResult<()>,N:FnMut(u32,u32,&mut CrtStreamRuntime,&mut CrtOwnedStorage,&mut LocalRecord<'_>)->RegistryResult<()>{
 fn validate_source(&mut self)->RegistryResult<()>{
  self.temporary.as_ref().ok_or("owned temporary bytes absent")?.validate(self.rt,self.record)?;
  self.record.validate_binding(self.storage.binding,&self.storage.image)?;self.storage.validate(self.rt,self.record.registry,self.machine)?;
  if self.record.frame()?!=self.storage.id||self.rows.is_empty()||self.rows.len()>64{return Err("owned local source/row budget");}
  let table=self.rt.resolve_absolute(self.storage.image.scope_va,CrtRegionKind::Module)?;self.rt.valid(table,16+self.rows.len()as u32*12)?;
  for(i,row)in self.rows.iter().enumerate(){for(j,value)in [row.parent as u32,row.filter,row.handler].into_iter().enumerate(){
   if self.rt.load(self.rt.offset(table,16+(i*12+j*4)as i64)?,32)?.known_scalar()?!=value{return Err("owned local readonly scope rows changed");}
  }}Ok(())
 }
}
impl<F,N> LocalUnwindEffects for CrtOwnedLocalEffects<'_,'_,F,N>
where F:FnMut(u32,i32,&mut CrtStreamRuntime,&mut CrtOwnedStorage,&mut LocalRecord<'_>)->RegistryResult<()>,N:FnMut(u32,u32,&mut CrtStreamRuntime,&mut CrtOwnedStorage,&mut LocalRecord<'_>)->RegistryResult<()>{
 fn install_temporary(&mut self,n:u32,h:u32)->RegistryResult<()>{
  if n!=40||self.temporary.is_some(){return Err("owned temporary layout/replay");}
  self.storage.validate(self.rt,self.record.registry,self.machine)?;
  self.temporary=Some(CrtOwnedTemporary::bind(self.rt,self.record,self.storage)?);self.record.install_head(n,h)
 }
 fn restore_previous_head(&mut self)->RegistryResult<()>{
  self.validate_source()?;
  if self.pending.is_some_and(|(_,row)|row.filter==0){return Err("owned local incomplete callback");}self.record.restore_previous_head()?;self.temporary.take().ok_or("owned temporary missing bytes")?.discard(self.rt)
 }
 fn decode_scope(&mut self)->RegistryResult<()>{self.validate_source()}
 fn read_try_level(&mut self)->RegistryResult<i32>{
  self.validate_source()?;let at=self.rt.resolve_absolute(self.storage.image.record+12,CrtRegionKind::Stack)?;
  let level=self.rt.load(at,32)?.known_scalar()? as i32;if level!=self.storage.image.try_level{return Err("owned local level cache mismatch");}Ok(level)
 }
 fn scope_row(&mut self,level:i32)->RegistryResult<LocalScope>{
  if self.pending.is_some_and(|(_,row)|row.filter==0)||self.read_try_level()?!=level{return Err("owned local pending/stale row");}
  let row=*self.rows.get(usize::try_from(level).map_err(|_|"owned local negative row")?).ok_or("owned local complete row bounds")?;
  if row.filter==0&&!self.record.registry.module_contains_address(row.handler){return Err("owned local unbound callback code");}
  if row.parent!= -2&&(row.parent<0||row.parent>=level){return Err("owned local nondecreasing parent");}
  self.pending=Some((level,row));self.written=false;self.notified=false;Ok(row)
 }
 fn write_try_level(&mut self,parent:i32)->RegistryResult<()>{
  let(level,row)=self.pending.ok_or("owned local parent without row")?;
  if self.written||row.parent!=parent||self.read_try_level()?!=level{return Err("owned local parent transition");}
  let base=self.rt.resolve_absolute(self.storage.image.record,CrtRegionKind::Stack)?;
  self.storage.store_local_level(self.rt,self.record,self.machine,CrtValue::Pointer(base),CrtValue::scalar(parent as u32),level,parent)?;self.written=true;Ok(())
 }
 fn notify(&mut self,handler:u32,reason:u32)->RegistryResult<()>{
  let(_,row)=self.pending.ok_or("owned local notification without row")?;
  if !self.written||self.notified||row.filter!=0||row.handler!=handler||reason!=0x101||self.read_try_level()?!=row.parent{return Err("owned local notification order");}
  (self.notification)(handler,reason,self.rt,self.storage,self.record)?;self.validate_source()?;self.notified=true;Ok(())
 }
 fn invoke_finally(&mut self,handler:u32,abnormal:u32)->RegistryResult<()>{
  let(level,row)=self.pending.ok_or("owned local callback without row")?;
  if !self.written||!self.notified||row.filter!=0||row.handler!=handler||abnormal!=1||self.read_try_level()?!=row.parent{return Err("owned local callback order");}
  (self.finally)(handler,level,self.rt,self.storage,self.record)?;
  if self.read_try_level()?!=row.parent{return Err("owned local callback changed protected cursor");}
  self.pending=None;self.written=false;self.notified=false;Ok(())
 }
 fn local_unwind(&mut self,_:i32)->RegistryResult<()>{Err("owned local wrapper requires separate proof")}
 fn check_temporary_cookie(&mut self)->RegistryResult<()>{Err("owned nested handler requires containment proof")}
 fn reenter_local_unwind(&mut self)->RegistryResult<()>{Err("owned nested handler requires containment proof")}
 fn write_collided_record(&mut self)->RegistryResult<()>{Err("owned collided handler requires containment proof")}
}

struct CrtOwnedGuardView<'a,'b>{owner:u64,frame:&'a CrtOwnedFrameView<'b>,bp:u32}
impl CrtOwnedGuardView<'_,'_>{
 fn frame_pointer(&self)->u32{self.bp}
 fn read_guard(&self,offset:i32)->RegistryResult<(u32,u32,u32)>{
  self.frame.validate()?;let storage=&self.frame.storage;
  let key=i32::try_from(i64::from(storage.image.ebp)-i64::from(storage.image.entry_sp)+i64::from(offset)).map_err(|_|"owned guard offset")?;
  let Some(FrameWord::Guard{frame,cookie,bits})=storage.image.words.get(&key)else{return Err("owned guard role provenance");};
  if *frame!=self.bp{return Err("owned guard frame provenance");}
  let actual=self.frame.rt.load(self.frame.rt.offset(storage.entry,i64::from(key))?,32)?.known_scalar()?;
  if actual!=*bits{return Err("owned guard live bits");}Ok((*frame,*cookie,actual))
 }
}

"#;
