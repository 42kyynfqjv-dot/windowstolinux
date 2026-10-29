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
 protected:std::collections::BTreeMap<i32,CrtValue>,input:Option<(Option<CrtPointer>,CrtPointer,CrtPointer,u32)>,pair_return:Option<(CrtPointer,u64)>,unwind_epoch:Option<u64>,
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
 fn read(&self,offset:i32)->RegistryResult<CrtValue>{if offset== -20&&self.storage.input.is_none_or(|(pair,_,_,_)|pair.is_none()){return Err("owned unbound exception pair");}self.rt.load(self.at(offset)?,32)}
 fn write_u32(&mut self,offset:i32,value:u32)->RegistryResult<()>{let p=self.at(offset)?;self.rt.store(p,32,CrtValue::scalar(value))}
 /// Original MOV to protected TryLevel only. Selection/unwind completion is
 /// a separate caller proof; this store cannot move Machine into Restore.
 fn store_level_operand(&mut self,base:CrtValue,value:CrtValue,before:i32,after:i32)->RegistryResult<()>{
  self.validate()?;let owner=self.owner_frame()?;
  if base!=CrtValue::Pointer(self.rt.offset(owner,-16)?)||self.storage.image.try_level!=before
   ||value.known_scalar()?!=after as u32||after< -2||after== -1{return Err("owned original scope store operands/state");}
  let key=i32::try_from(i64::from(self.storage.image.record)+12-i64::from(self.storage.image.entry_sp)).map_err(|_|"owned scope word offset")?;
  if self.storage.protected.get(&key)!=Some(&CrtValue::scalar(before as u32)){return Err("owned original scope store role");}
  self.rt.store(self.rt.offset(self.storage.entry,i64::from(key))?,32,value)?;
  self.storage.protected.insert(key,value);self.storage.image.words.insert(key,FrameWord::Scalar(after as u32));self.storage.image.try_level=after;self.validate()
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
