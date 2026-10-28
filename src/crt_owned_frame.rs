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
pub(crate) const EMITTED_TYPES: &str = r#"
struct CrtOwnedStorage {
 anchor:guest_memory::Capability,identity:RegistryIdentity,binding:OwnedFrameBinding,id:RegistrationId,event:u64,
 entry:CrtPointer,return_id:u64,image:FrameImage<RegistryHead>,ordinary:std::collections::BTreeSet<i32>,
 protected:std::collections::BTreeMap<i32,CrtValue>,input:Option<(CrtPointer,CrtPointer,CrtPointer,u32)>,
}
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
  Ok(Self{anchor:rt.anchor,identity:r.identity,binding,id,event:m.event,entry,return_id:cpu.return_id,image,ordinary:ordinary.iter().copied().collect(),protected,input:None})
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
   let owner_slot=rt.offset(self.entry,i64::from(self.image.ebp)-i64::from(self.image.entry_sp)-20)?;
   if rt.load(owner_slot,32)?!=CrtValue::Pointer(pair)||rt.load(pair,32)?!=CrtValue::Pointer(record)||rt.load(rt.offset(pair,4)?,32)?!=CrtValue::Pointer(context)||rt.load(record,32)?.known_scalar()?!=code{return Err("owned captured input graph changed");}
  }Ok(())
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
  self.input=Some((pair,record,context,code));self.validate(rt,r,m)
 }
}
struct CrtOwnedFrameView<'a>{rt:&'a mut CrtStreamRuntime,registry:&'a ThreadRegistry,machine:&'a Machine,storage:&'a CrtOwnedStorage,active:u64,depth:u32,calls:u32,failed:bool}
impl CrtOwnedFrameView<'_>{
 fn validate(&self)->RegistryResult<()>{if self.failed||self.depth>32||self.calls>4096{return Err("owned filter call failed/budget");}self.storage.validate(self.rt,self.registry,self.machine)}
 fn active_call(&self)->u64{self.active}
 fn stack_range(&self,low:u32,high:u64)->RegistryResult<()>{self.registry.range(low,high)}
 fn preflight_bridge(&self,cpu:&CrtCpu,bytes:u32)->RegistryResult<()>{
  self.validate()?;let sp=CrtCpu::pointer(cpu.r[4])?;
  if bytes==0||bytes>256||cpu.returned||cpu.return_id!=self.active||cpu.r[4]!=cpu.entry[4]
   ||sp.cap!=self.storage.entry.cap||sp.address()>=self.storage.image.esp
   ||self.rt.load(sp,32)?!=CrtValue::ProtectedReturn(cpu.return_id){return Err("owned bridge entry/scratch alias");}
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
    ||self.rt.load(CrtCpu::pointer(cpu.entry[4])?,32)?!=CrtValue::ProtectedReturn(cpu.return_id){return Err("owned filter call activation/scratch");}
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
 fn read(&self,offset:i32)->RegistryResult<CrtValue>{if offset== -20&&self.storage.input.is_none(){return Err("owned unbound exception pair");}self.rt.load(self.at(offset)?,32)}
 fn write_u32(&mut self,offset:i32,value:u32)->RegistryResult<()>{let p=self.at(offset)?;self.rt.store(p,32,CrtValue::scalar(value))}
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
  frame.validate()?;let sp=CrtCpu::pointer(self.entry[4])?;
  if frame.storage.input.is_none_or(|(_,record,context,_)|record!=self.record||context!=self.context){return Err("owned prefix captured object binding changed");}
  if self.identity!=frame.registry.identity||self.event!=frame.machine.event||self.binding!=frame.storage.binding||self.id!=frame.storage.id||self.anchor!=frame.rt.anchor
   ||cpu.returned||cpu.entry!=self.entry||cpu.return_id!=self.callback||frame.active!=self.callback
   ||frame.rt.load(sp,32)?!=CrtValue::ProtectedReturn(self.callback)
   ||frame.rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(self.callback)).count()!=1
   ||self.captured_esp<frame.registry.limit||self.captured_esp>frame.registry.base{return Err("owned prefix stale callback/event/context");}
  frame.rt.valid(self.record,80)?;frame.rt.valid(self.context,716)?;
  for(offset,value)in [(0,self.code),(4,0),(8,0),(16,0)]{if frame.rt.load(frame.rt.offset(self.record,offset)?,32)?.known_scalar()?!=value{return Err("owned prefix record fields");}}
  if frame.rt.load(frame.rt.offset(self.context,0xc4)?,32)?.known_scalar()?!=self.captured_esp{return Err("owned prefix captured ESP changed");}
  let establisher=frame.rt.offset(frame.storage.entry,i64::from(frame.storage.image.record)-i64::from(frame.storage.image.entry_sp))?;
  for(i,value)in [CrtValue::Pointer(self.record),CrtValue::Pointer(establisher),CrtValue::Pointer(self.context),CrtValue::scalar(0)].into_iter().enumerate(){
   if frame.rt.load(frame.rt.offset(sp,4+i as i64*4)?,32)?!=value{return Err("owned prefix callback argument provenance");}
  }Ok(())
 }
}

"#;
