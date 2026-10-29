//! Private storage for instruction-proved registrations. This is not an
//! implementation or admission certificate for Windows exception delivery or
//! RtlUnwind. Unlink timing and borrowed dispatcher entry remain external gates.
pub(crate) const EMITTED_TYPES: &str = r#"
static NEXT_THREAD_REGISTRY:std::sync::atomic::AtomicU64=std::sync::atomic::AtomicU64::new(1);
type RegistryResult<T>=Result<T,&'static str>;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct RegistryIdentity {owner:u64,instance:u64}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct RegistrationId {identity:RegistryIdentity,generation:u64}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum RegistryHead {
 BorrowedRoot(RegistryIdentity),
 BorrowedDispatcher{identity:RegistryIdentity,generation:u64},
 Owned(RegistrationId),
 Normal(NormalFrameId),
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum RegistryWord {
 Previous(RegistryHead), Handler(u32), Guard{record:u32,cookie:u32,bits:u32},
 Scalar(u32), Establisher(RegistrationId,u32), CookieAddress(u32), FramePointer(RegistrationId,u32),
}
struct RegistryFrame {
 id:RegistrationId,binding:OwnedFrameBinding,previous:RegistryHead,
 low:u32,high:u64,record:u32,ebp:u32,handler:u32,scope:u32,cookie:u32,
 linked:bool,live:bool,completion:Option<u64>,
}
struct RegistryTemporary {
 id:RegistrationId,frame:RegistrationId,previous:RegistryHead,
 low:u32,high:u64,words:[RegistryWord;7],installed:bool,restored:bool,
}
#[derive(Clone,Copy,Debug)]
struct LocalEntry {entry_sp:u32,handler:u32,cookie_address:u32,cookie:u32,target_level:i32}
#[derive(Debug)]
struct HandlerCompletion {identity:RegistryIdentity,frame:RegistrationId,generation:u64}
#[derive(Clone,Debug)]
struct Containment {identity:RegistryIdentity,target:RegistrationId,younger:Vec<RegistrationId>}
impl Containment {fn younger(&self)->&[RegistrationId]{&self.younger}fn target(&self)->RegistrationId{self.target}}
trait RegistryFrameStorage {fn registry_image(&self)->&FrameImage<RegistryHead>;}
impl RegistryFrameStorage for FrameImage<RegistryHead>{fn registry_image(&self)->&FrameImage<RegistryHead>{self}}
struct ThreadRegistry {
 identity:RegistryIdentity,limit:u32,base:u32,bound:Vec<(u32,u32)>,cookie_address:u32,
 head:RegistryHead,frames:Vec<RegistryFrame>,temporary:Vec<RegistryTemporary>,
 generation:u64,selected:Option<Containment>,next_unwind:usize,
 handlers:Vec<RegistrationId>,borrowed_depth:usize,failure:Option<&'static str>,
 normal_authority:std::cell::Cell<Option<u64>>,normal_epoch:Option<NormalEpochState>,
}
struct LocalRecord<'a>{registry:&'a mut ThreadRegistry,id:RegistrationId}
// Minted only by the enclosing owned-event finish path. The registry verifies
// the same state again at use; no externally supplied success Boolean grants
// normal-call authority. Unknown saved register bits remain unknown.
struct FinishedEventPermit {
 identity:RegistryIdentity,event:u64,binding:OwnedFrameBinding,selected:RegistrationId,
 context:[Option<u32>;10],stamp:u64,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct NormalFrameId {identity:RegistryIdentity,epoch:u64,generation:u64}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum NormalRegistrationKind {Eh4,Cxx{metadata:u32}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum NormalFrameStep {
 RestorePredecessor,PopSaved{offset:i32,register:u8},
 DiscardGuard{offset:i32,register:u8},CheckGuard{offset:i32,target:u32},
}
struct NormalFramePlan {steps:Vec<NormalFrameStep>,callee_pop:u32}
struct RegistryNormalFrame {
 id:NormalFrameId,kind:NormalRegistrationKind,previous:RegistryHead,
 low:u32,high:u64,entry_sp:u32,ebp:u32,record:u32,handler:u32,scope:u32,cookie:u32,
 protected:std::collections::BTreeMap<i32,FrameWord<RegistryHead>>,
 plan:NormalFramePlan,next:usize,saved:[Option<u32>;8],installed:bool,unlinked:bool,
}
struct NormalEpochState {
 generation:u64,event:u64,selected:RegistrationId,previous:RegistryHead,next_unwind:usize,
 context:[Option<u32>;10],frames:Vec<RegistryNormalFrame>,issued:usize,pending_exception:Option<u64>,
}
struct NormalCallEpoch<'a>{registry:&'a mut ThreadRegistry,generation:u64}
#[derive(Debug)]
struct NormalFrameReceipt {frame:NormalFrameId,caller_sp:u32,saved:[Option<u32>;8]}
impl ThreadRegistry {
 fn new(owner:u64,limit:u32,base:u32,bound:&[(u32,u32)],cookie_address:u32)->RegistryResult<Self>{
  if owner==0||limit==0||limit>=base||bound.len()>256||bound.iter().any(|&(a,b)|a==0||a>=b)
    ||cookie_address%4!=0||!bound.iter().any(|&(a,b)|cookie_address>=a&&u64::from(cookie_address)+4<=u64::from(b)) {
   return Err("registry initial owner/thread/module bounds");
  }
  let instance=NEXT_THREAD_REGISTRY.fetch_update(std::sync::atomic::Ordering::Relaxed,std::sync::atomic::Ordering::Relaxed,|n|n.checked_add(1)).map_err(|_|"registry identity exhaustion")?;
  let identity=RegistryIdentity{owner,instance};
  Ok(Self{identity,limit,base,bound:bound.to_vec(),cookie_address,head:RegistryHead::BorrowedRoot(identity),frames:Vec::new(),temporary:Vec::new(),generation:0,selected:None,next_unwind:0,handlers:Vec::new(),borrowed_depth:0,failure:None,normal_authority:std::cell::Cell::new(None),normal_epoch:None})
 }
 fn available(&self)->RegistryResult<()>{if let Some(e)=self.failure{Err(e)}else{Ok(())}}
 fn fail<T>(&mut self,error:&'static str)->RegistryResult<T>{let error=*self.failure.get_or_insert(error);Err(error)}
 fn block(&mut self,error:&'static str){self.failure.get_or_insert(error);}
 fn next_id(&mut self)->RegistryResult<RegistrationId>{
  self.generation=self.generation.checked_add(1).ok_or("registry generation exhaustion")?;
  Ok(RegistrationId{identity:self.identity,generation:self.generation})
 }
 fn head(&self)->RegistryResult<RegistryHead>{self.available()?;Ok(self.head)}
 fn frame_index(&self,id:RegistrationId)->RegistryResult<usize>{
  self.available()?;
  if id.identity!=self.identity{return Err("registry foreign identity");}
  self.frames.iter().position(|f|f.id==id&&f.live).ok_or("registry stale frame")
 }
 fn registration(&self,binding:OwnedFrameBinding)->RegistryResult<RegistrationId>{
  self.available()?;
  if binding.owner!=self.identity.owner||binding.frame.owner!=self.identity.owner||binding.frame.generation==0{return Err("registry foreign frame binding");}
  self.frames.iter().find(|f|f.live&&f.binding==binding).map(|f|f.id).ok_or("registry stale or mismatched frame binding")
 }
 fn image_key(image:&FrameImage<RegistryHead>,address:u32)->RegistryResult<i32>{
  i32::try_from(i64::from(address)-i64::from(image.entry_sp)).map_err(|_|"registry frame relative offset")
 }
 fn image_record(image:&FrameImage<RegistryHead>)->RegistryResult<(RegistryHead,u32,u32,u32,i32)>{
  if image.record%4!=0||image.record.checked_add(16)!=Some(image.ebp){return Err("registry record frame relation");}
  let key=Self::image_key(image,image.record)?;
  let Some(FrameWord::Borrowed(previous))=image.words.get(&key)else{return Err("registry missing typed previous word");};
  let Some(FrameWord::Scalar(handler))=image.words.get(&(key+4))else{return Err("registry missing initialized handler word");};
  let Some(FrameWord::EncodedScope{scope,cookie,bits})=image.words.get(&(key+8))else{return Err("registry missing encoded table word");};
  let Some(FrameWord::Scalar(level))=image.words.get(&(key+12))else{return Err("registry missing initialized TryLevel word");};
  if *handler!=image.handler_va||*scope!=image.scope_va||*bits!=(*scope^*cookie)||*level as i32!=image.try_level {
   return Err("registry record bytes/provenance disagreement");
  }
  Ok((*previous,*handler,*scope,*cookie,*level as i32))
 }
 fn range(&self,low:u32,high:u64)->RegistryResult<()>{
  if low<self.limit||u64::from(low)>=high||high>u64::from(self.base)
   ||self.bound.iter().any(|&(a,b)|u64::from(low)<u64::from(b)&&u64::from(a)<high){return Err("registry thread/module range");}Ok(())
 }
 // Numeric module containment only. Original executable-target and metadata
 // provenance are separate compiler obligations, not permissions granted here.
 fn module_contains_address(&self,address:u32)->bool{address!=0&&self.bound.iter().any(|&(a,b)|address>=a&&address<b)}
 fn install_frame(&mut self,binding:OwnedFrameBinding,image:&FrameImage<RegistryHead>)->RegistryResult<RegistrationId>{
  self.available()?;
  let result=(||{
   if self.selected.is_some()||!self.handlers.is_empty()||!self.temporary.is_empty()||self.borrowed_depth!=0||self.frames.len()>=64 {
    return Err("registry installation phase/budget");
   }
   if binding.owner!=self.identity.owner||binding.frame.owner!=self.identity.owner||binding.frame.generation==0
    ||self.frames.iter().any(|f|f.binding.frame==binding.frame||f.binding.index==binding.index){return Err("registry frame binding identity");}
   let low=image.esp;let high=u64::from(image.entry_sp)+4;self.range(low,high)?;
   if low%4!=0||image.entry_sp%4!=0||image.ebp<low||u64::from(image.ebp)+4>high||image.record<low
    ||self.frames.iter().any(|f|f.live&&u64::from(low)<f.high&&u64::from(f.low)<high){return Err("registry frame overlap/alignment");}
   let(previous,handler,scope,cookie,_)=Self::image_record(image)?;
   if previous!=self.head||!self.module_contains_address(handler)||!self.module_contains_address(scope){return Err("registry previous/metadata identity");}
   let id=self.next_id()?;
   self.frames.push(RegistryFrame{id,binding,previous,low,high,record:image.record,ebp:image.ebp,handler,scope,cookie,linked:true,live:true,completion:None});
   self.head=RegistryHead::Owned(id);Ok(id)
  })();match result{Ok(id)=>Ok(id),Err(e)=>self.fail(e)}
 }
 fn validate_frame(&self,id:RegistrationId,image:&FrameImage<RegistryHead>)->RegistryResult<()>{
  let frame=&self.frames[self.frame_index(id)?];
  let(previous,handler,scope,cookie,_)=Self::image_record(image)?;
  if frame.record!=image.record||frame.ebp!=image.ebp||frame.high!=u64::from(image.entry_sp)+4
   ||image.esp<frame.low||image.esp>frame.ebp||frame.previous!=previous||frame.handler!=handler||frame.scope!=scope||frame.cookie!=cookie {
   return Err("registry changed or foreign frame storage");
  }Ok(())
 }
 fn contain(&mut self,target:RegistrationId)->RegistryResult<Containment>{
  self.available()?;
  let result=(||{
   self.frame_index(target)?;
   if self.selected.is_some()||!self.temporary.is_empty()||!self.handlers.is_empty()||self.borrowed_depth!=0{return Err("registry containment phase");}
   let mut head=self.head;let mut younger=Vec::new();
   loop {
    let RegistryHead::Owned(id)=head else{return Err("registry target crosses borrowed boundary");};
    let f=&self.frames[self.frame_index(id)?];if !f.linked{return Err("registry unlinked chain node");}
    if id==target{break;}
    if younger.contains(&id)||younger.len()>=64{return Err("registry chain cycle/budget");}
    younger.push(id);head=f.previous;
   }
   let plan=Containment{identity:self.identity,target,younger};self.selected=Some(plan.clone());Ok(plan)
  })();match result{Ok(plan)=>Ok(plan),Err(e)=>self.fail(e)}
 }
 fn expected_callback(&self,id:RegistrationId)->RegistryResult<()>{
  if self.normal_epoch.is_some(){return Err("registry exception callback during normal call epoch");}
  self.frame_index(id)?;
  let plan=self.selected.as_ref().ok_or("registry missing containment")?;
  if plan.identity!=self.identity{return Err("registry containment identity");}
  let expected=plan.younger.get(self.next_unwind).copied().unwrap_or(plan.target);
  if expected!=id{return Err("registry callback order");}Ok(())
 }
 /// A decoded or independently closed external effect must justify this exact
 /// unlink. Storage remains live for callbacks. No Windows timing is assumed.
 fn unlink_head(&mut self,id:RegistrationId)->RegistryResult<()>{
  self.available()?;
  let result=(||{
   self.expected_callback(id)?;
   if self.selected.as_ref().is_some_and(|p|p.target==id)||self.head!=RegistryHead::Owned(id)||!self.temporary.is_empty()||self.borrowed_depth!=0 {
    return Err("registry unlink target/head/temporary boundary");
   }
   let index=self.frame_index(id)?;let frame=&mut self.frames[index];
   if !frame.linked{return Err("registry repeated unlink");}
   frame.linked=false;self.head=frame.previous;Ok(())
  })();match result{Ok(())=>Ok(()),Err(e)=>self.fail(e)}
 }
 /// Executes the compiler-proved original callback, including post-cleanup
 /// guard/epilog effects. A Boolean cannot manufacture the completion token.
 fn execute_handler<T,S:RegistryFrameStorage>(&mut self,id:RegistrationId,image:&mut S,body:impl FnOnce(&mut Self,&mut S)->RegistryResult<T>)->RegistryResult<(T,HandlerCompletion)>{
  self.available()?;
  let start=(||{self.expected_callback(id)?;self.validate_frame(id,image.registry_image())?;if self.handlers.contains(&id)||self.handlers.len()>=16{return Err("registry recursive handler outside contract");}Ok((self.head,self.temporary.len(),self.borrowed_depth))})();
  let(head,depth,borrowed)=match start{Ok(v)=>v,Err(e)=>return self.fail(e)};
  self.handlers.push(id);
  let result=body(self,image);
  match result{Err(e)=>return self.fail(e),Ok(value)=>{
   if let Err(e)=self.available(){return Err(e);}
   if self.head!=head||self.temporary.len()!=depth||self.borrowed_depth!=borrowed||self.handlers.last()!=Some(&id){return self.fail("registry callback head/lifetime mismatch");}
   if let Err(e)=self.validate_frame(id,image.registry_image()){return self.fail(e);}
   self.handlers.pop();let generation=match self.next_id(){Ok(t)=>t.generation,Err(e)=>return self.fail(e)};
   let index=self.frame_index(id)?;self.frames[index].completion=Some(generation);
   Ok((value,HandlerCompletion{identity:self.identity,frame:id,generation}))
  }}
 }
 fn retire_frame(&mut self,completion:HandlerCompletion,image:&FrameImage<RegistryHead>)->RegistryResult<()>{
  self.available()?;
  let result=(||{
   if completion.identity!=self.identity{return Err("registry foreign completion");}
   let id=completion.frame;self.expected_callback(id)?;self.validate_frame(id,image)?;
   let index=self.frame_index(id)?;
   if self.selected.as_ref().is_some_and(|p|p.target==id)||!self.handlers.is_empty()||!self.temporary.is_empty()||self.borrowed_depth!=0
    ||self.frames[index].linked||image.try_level!=-2||self.frames[index].completion!=Some(completion.generation){return Err("registry retirement phase/state/receipt");}
   self.frames[index].live=false;self.frames[index].completion=None;self.next_unwind+=1;Ok(())
  })();match result{Ok(())=>Ok(()),Err(e)=>self.fail(e)}
 }
 fn target_ready(&self)->RegistryResult<RegistrationId>{
  self.available()?;let plan=self.selected.as_ref().ok_or("registry missing containment")?;
  if self.normal_epoch.is_some()||self.next_unwind!=plan.younger.len()||!self.handlers.is_empty()||!self.temporary.is_empty()||self.borrowed_depth!=0
   ||self.head!=RegistryHead::Owned(plan.target){return Err("registry target not ready");}
  self.frame_index(plan.target)?;Ok(plan.target)
 }
 /// Explicit borrowed dispatcher-entry cut. This capability has no guest
 /// numeric address or dereference operation. Its provider must establish
 /// lifetime and restoration; this method alone supplies no OS effect proof.
 fn with_borrowed_dispatcher<T>(&mut self,body:impl FnOnce(&mut Self)->RegistryResult<T>)->RegistryResult<T>{
  self.available()?;
  if self.normal_epoch.is_some()||self.selected.is_none()||self.borrowed_depth>=16{return self.fail("registry borrowed dispatcher phase/budget");}
  let previous=self.head;let depth=self.temporary.len();let id=match self.next_id(){Ok(id)=>id,Err(e)=>return self.fail(e)};
  let borrowed=RegistryHead::BorrowedDispatcher{identity:self.identity,generation:id.generation};
  self.head=borrowed;self.borrowed_depth+=1;
  match body(self){Err(e)=>self.fail(e),Ok(value)=>{
   self.available()?;if self.head!=borrowed||self.temporary.len()!=depth{return self.fail("registry borrowed dispatcher not restored");}
   self.head=previous;self.borrowed_depth-=1;Ok(value)
  }}
 }
 fn execute_local<T,S:RegistryFrameStorage>(&mut self,id:RegistrationId,image:&mut S,entry:LocalEntry,body:impl FnOnce(&mut LocalRecord<'_>,&mut S)->RegistryResult<T>)->RegistryResult<T>{
  self.available()?;
  let start=(||{
   self.expected_callback(id)?;self.validate_frame(id,image.registry_image())?;
   if self.handlers.last()!=Some(&id)||self.temporary.len()>=16{return Err("registry local callback lifetime/budget");}
   let index=self.frame_index(id)?;let frame=&self.frames[index];
   if entry.cookie_address!=self.cookie_address||entry.cookie!=frame.cookie||!self.module_contains_address(entry.handler)
    ||entry.entry_sp%4!=0||entry.target_level< -2||entry.target_level== -1{return Err("registry local argument provenance");}
   let low=entry.entry_sp.checked_sub(40).ok_or("registry temporary underflow")?;let high=u64::from(entry.entry_sp)+4;self.range(low,high)?;
   if self.frames.iter().any(|f|f.live&&u64::from(low)<f.high&&u64::from(f.low)<high)
    ||self.temporary.iter().any(|t|u64::from(low)<t.high&&u64::from(t.low)<high){return Err("registry temporary storage alias");}
   Ok((low,high,frame.record,frame.ebp,self.head))
  })();
  let(low,high,record,ebp,previous)=match start{Ok(v)=>v,Err(e)=>return self.fail(e)};
  let token=match self.next_id(){Ok(id)=>id,Err(e)=>return self.fail(e)};
  let words=[RegistryWord::Previous(previous),RegistryWord::Handler(entry.handler),RegistryWord::Guard{record:low,cookie:entry.cookie,bits:low^entry.cookie},RegistryWord::Scalar(entry.target_level as u32),RegistryWord::Establisher(id,record),RegistryWord::CookieAddress(entry.cookie_address),RegistryWord::FramePointer(id,ebp)];
  // Reserve private temporary storage first. Only the original MOV FS:[0]
  // command may install it; the wrapper must not make that write early.
  self.temporary.push(RegistryTemporary{id:token,frame:id,previous,low,high,words,installed:false,restored:false});
  let result=body(&mut LocalRecord{registry:self,id:token},image);
  match result{Err(e)=>self.fail(e),Ok(value)=>{
   self.available()?;
   let Some(last)=self.temporary.last()else{return self.fail("registry missing temporary completion");};
   if last.id!=token||!last.installed||!last.restored||self.head!=previous{return self.fail("registry original MOV/POP FS not completed");}
   if let Err(e)=self.validate_frame(id,image.registry_image()){return self.fail(e);}
   self.temporary.pop();Ok(value)
  }}
 }
}
impl ThreadRegistry {
 /// Validate the already consumed original Main return. The receipt issuer,
 /// CRT runtime anchor and shutdown effects are separate obligations.
 fn validate_returned_event(&self,machine:&Machine,owner:u64,event:u64,selected:FrameId)->RegistryResult<()>{
  self.available()?;
  if owner==0||owner!=self.identity.owner||owner!=machine.owner()||event!=machine.event
   ||!machine.event_issued||machine.phase!=Phase::Returned||!machine.owned_storage||!machine.explicit_dispatch
   ||self.normal_epoch.is_some()||!self.handlers.is_empty()||!self.temporary.is_empty()||self.borrowed_depth!=0 {
   return Err("returned event unfinished or foreign lifecycle");
  }
  let plan=self.selected.as_ref().ok_or("returned event missing containment")?;
  let target=self.frames.iter().find(|f|f.id==plan.target).ok_or("returned event selected registration")?;
  let frame=machine.frames.get(machine.selected).ok_or("returned event selected activation")?;
  if plan.identity!=self.identity||self.next_unwind!=plan.younger.len()||target.binding.frame!=selected
   ||target.binding.index!=machine.selected||target.binding.owner!=owner||frame.id!=selected||frame.live
   ||target.live||target.linked||self.head!=target.previous||self.normal_authority.get().is_none()
   ||plan.younger.iter().any(|id|self.frames.iter().find(|f|f.id==*id).is_none_or(|f|f.live||f.linked)) {
   return Err("returned event incomplete retirement or changed containment");
  }Ok(())
 }
 fn mint_finished_event(&self,machine:&Machine,binding:OwnedFrameBinding)->RegistryResult<FinishedEventPermit>{
  self.available()?;
  if self.normal_authority.get().is_some()||machine.phase!=Phase::Done||!machine.event_issued
   ||!machine.owned_storage||!machine.explicit_dispatch||machine.owner()!=self.identity.owner
   ||machine.owned_binding(machine.selected).map_err(|_|"normal event selected binding")?!=binding {
   return Err("normal event unfinished, foreign or repeated permit");
  }
  let selected=self.registration(binding)?;
  if self.target_ready()?!=selected{return Err("normal event selected registration");}
  let context=machine.owned_context.ok_or("normal event missing owned context")?;
  if [0,4,5,8].iter().any(|&i|context[i].is_none())||[1,2,9].iter().any(|&i|context[i].is_some()) {
   return Err("normal event incomplete restored projection");
  }
  self.normal_authority.set(Some(1));
  Ok(FinishedEventPermit{identity:self.identity,event:machine.event,binding,selected,context,stamp:1})
 }
 fn with_normal_calls<T>(&mut self,machine:&Machine,permit:&mut FinishedEventPermit,image:&FrameImage<RegistryHead>,body:impl FnOnce(&mut NormalCallEpoch<'_>)->RegistryResult<T>)->RegistryResult<T>{
  self.available()?;
  let start=(||{
   if self.normal_epoch.is_some()||self.normal_authority.get()!=Some(permit.stamp)||permit.identity!=self.identity
    ||permit.event!=machine.event||machine.owner()!=self.identity.owner||!machine.event_issued
    ||!machine.owned_storage||!machine.explicit_dispatch||!matches!(machine.phase,Phase::Done|Phase::Returning)
    ||machine.owned_context!=Some(permit.context)
    ||machine.owned_binding(machine.selected).map_err(|_|"normal call selected binding")?!=permit.binding
    ||self.registration(permit.binding)?!=permit.selected||self.target_ready()?!=permit.selected {
    return Err("normal call foreign, stale or active event");
   }
   self.validate_frame(permit.selected,image)?;
   if image.try_level!= -2{return Err("normal call selected scopes incomplete");}
   let selected=&self.frames[self.frame_index(permit.selected)?];
   if !selected.linked{return Err("normal call selected frame unlinked");}
   permit.stamp.checked_add(1).ok_or("normal call permit exhaustion")
  })();
  let next_stamp=match start{Ok(value)=>value,Err(e)=>return self.fail(e)};
  let generation=match self.next_id(){Ok(id)=>id.generation,Err(e)=>return self.fail(e)};
  self.normal_epoch=Some(NormalEpochState{generation,event:permit.event,selected:permit.selected,
   previous:self.head,next_unwind:self.next_unwind,context:permit.context,frames:Vec::new(),issued:0,pending_exception:None});
  let result=body(&mut NormalCallEpoch{registry:self,generation});
  let value=match result{Ok(value)=>value,Err(e)=>return self.fail(e)};
  self.available()?;
  let state=self.normal_epoch.as_ref().ok_or("normal call missing epoch")?;
  if state.generation!=generation||state.event!=permit.event||state.selected!=permit.selected
   ||state.pending_exception.is_some()||state.context!=permit.context||!state.frames.is_empty()||self.head!=state.previous
   ||self.next_unwind!=state.next_unwind||self.selected.as_ref().is_none_or(|p|p.target!=permit.selected)
   ||machine.owned_context!=Some(permit.context)||!matches!(machine.phase,Phase::Done|Phase::Returning) {
   return self.fail("normal call incomplete lifecycle or changed selected context");
  }
  if let Err(e)=self.validate_frame(permit.selected,image){return self.fail(e);}
  if !self.frames[self.frame_index(permit.selected)?].linked{return self.fail("normal call changed selected lifetime");}
  self.normal_epoch=None;
  self.normal_authority.set(Some(next_stamp));permit.stamp=next_stamp;Ok(value)
 }
}
impl NormalCallEpoch<'_> {
 fn state(&self)->RegistryResult<&NormalEpochState>{
  self.registry.available()?;
  let state=self.registry.normal_epoch.as_ref().ok_or("normal call expired epoch")?;
  if state.generation!=self.generation{return Err("normal call stale epoch");}
  if state.pending_exception.is_some(){return Err("normal call suspended for owned exception");}Ok(state)
 }
 fn head(&self)->RegistryResult<RegistryHead>{self.state()?;self.registry.head()}
 fn fail<T>(&mut self,error:&'static str)->RegistryResult<T>{self.registry.fail(error)}
 fn top(&self,id:NormalFrameId)->RegistryResult<&RegistryNormalFrame>{
  let state=self.state()?;
  let frame=state.frames.last().ok_or("normal call no live frame")?;
  if id.identity!=self.registry.identity||id.epoch!=self.generation||frame.id!=id{return Err("normal call stale, foreign or non-LIFO frame");}Ok(frame)
 }
 fn validate_image(&self,id:NormalFrameId,image:&FrameImage<RegistryHead>)->RegistryResult<()>{
  let frame=self.top(id)?;Self::check_image(frame,image)
 }
 fn check_image(frame:&RegistryNormalFrame,image:&FrameImage<RegistryHead>)->RegistryResult<()>{
  if frame.kind!=NormalRegistrationKind::Eh4{return Err("normal call registration kind mismatch");}
  let(previous,handler,scope,cookie,_)=ThreadRegistry::image_record(image)?;
  if frame.entry_sp!=image.entry_sp||frame.ebp!=image.ebp||frame.record!=image.record
   ||image.esp<frame.low||image.esp>image.entry_sp||previous!=frame.previous||handler!=frame.handler
   ||scope!=frame.scope||cookie!=frame.cookie||frame.protected.iter().any(|(key,value)|image.words.get(key)!=Some(value)) {
   return Err("normal call changed protected frame identity");
  }Ok(())
 }
 /// The compiler supplies this plan from the original EH4 prolog/epilog.
 /// C++ three-word registrations are a distinct representation, never inferred
 /// from these four-word EH4 records or granted handler behavior by this API.
 fn reserve_eh4(&mut self,image:&FrameImage<RegistryHead>,plan:NormalFramePlan)->RegistryResult<NormalFrameId>{
  let result=(||{
   let state=self.state()?;
   if state.frames.len()>=32||state.issued>=4096||plan.steps.is_empty()||plan.steps.len()>32
    ||plan.callee_pop%4!=0||plan.callee_pop>4096{return Err("normal call frame/plan budget");}
   if let Some(parent)=state.frames.last(){if !parent.installed||parent.unlinked||self.registry.head!=RegistryHead::Normal(parent.id){return Err("normal call parent not installed");}}
   let low=image.esp;let high=u64::from(image.entry_sp)+4;
   // RET n consumes the caller's argument words as well as the protected
   // return. Their complete extent must remain in the same owned thread
   // range and outside module storage even though the frame does not own
   // their contents or gain dereference authority here.
   let consumed_high=high+u64::from(plan.callee_pop);self.registry.range(low,consumed_high)?;
   let parent_low=state.frames.last().map(|f|f.low).unwrap_or(self.registry.frames[self.registry.frame_index(state.selected)?].low);
   if consumed_high>u64::from(parent_low){return Err("normal call stack grows outside caller activation");}
   if low%4!=0||image.entry_sp%4!=0||image.record<low||image.ebp<low||u64::from(image.ebp)+4>high
    ||self.registry.frames.iter().any(|f|f.live&&u64::from(low)<f.high&&u64::from(f.low)<consumed_high)
    ||state.frames.iter().any(|f|u64::from(low)<f.high&&u64::from(f.low)<consumed_high) {
    return Err("normal call frame overlap/alignment");
   }
   let(previous,handler,scope,cookie,_)=ThreadRegistry::image_record(image)?;
   if previous!=self.registry.head||!self.registry.module_contains_address(handler)||!self.registry.module_contains_address(scope)
    ||!matches!(image.words.get(&0),Some(FrameWord::Return)){return Err("normal call original predecessor/return/metadata");}
   if image.words.keys().any(|&key|{let at=i64::from(image.entry_sp)+i64::from(key);key%4!=0||at<i64::from(low)||at+4>high as i64}){return Err("normal call word outside owned frame");}
   let mut seen=std::collections::BTreeSet::new();let mut registers=std::collections::BTreeSet::new();let mut restored=false;let mut saw_ebp=false;
   for step in &plan.steps {
    match *step {
     NormalFrameStep::RestorePredecessor=>{if restored||!seen.is_empty(){return Err("normal call predecessor plan order");}restored=true;},
     NormalFrameStep::PopSaved{offset,register}=>{
      if !restored||saw_ebp||!matches!(register,3|5|6|7)||offset%4!=0||!seen.insert(offset)||!registers.insert(register)
       ||(register==5&&i64::from(image.entry_sp)+i64::from(offset)!=i64::from(image.ebp))
       ||!matches!(image.words.get(&offset),Some(FrameWord::Saved(r,_))if *r==register){return Err("normal call saved-slot plan");}
      saw_ebp=register==5;
     },
     NormalFrameStep::DiscardGuard{offset,register}=>{
      if !restored||saw_ebp||register!=1||offset%4!=0||!seen.insert(offset)
       ||!matches!(image.words.get(&offset),Some(FrameWord::Guard{frame,..})if *frame==image.ebp){return Err("normal call guard-discard plan");}
     },
     NormalFrameStep::CheckGuard{offset,target}=>{
      if !restored||saw_ebp||offset%4!=0||!self.registry.module_contains_address(target)
       ||!matches!(image.words.get(&offset),Some(FrameWord::Guard{frame,..})if *frame==image.ebp){return Err("normal call guard-check plan");}
     },
    }
   }
   if !restored||!saw_ebp||image.words.iter().any(|(offset,word)|matches!(word,FrameWord::Saved(..))&&!seen.contains(offset)) {
    return Err("normal call missing saved-register restoration");
   }
   let protected=image.words.iter().filter(|(_,word)|matches!(word,FrameWord::Saved(..)|FrameWord::Return|FrameWord::Guard{..}|FrameWord::Borrowed(_)|FrameWord::EncodedScope{..}|FrameWord::Cookie(_))).map(|(&key,value)|(key,value.clone())).collect();
   Ok((low,high,previous,handler,scope,cookie,protected))
  })();
  let(low,high,previous,handler,scope,cookie,protected)=match result{Ok(v)=>v,Err(e)=>return self.fail(e)};
  let generation=match self.registry.next_id(){Ok(id)=>id.generation,Err(e)=>return self.fail(e)};
  let id=NormalFrameId{identity:self.registry.identity,epoch:self.generation,generation};
  let state=self.registry.normal_epoch.as_mut().unwrap();state.issued+=1;
  state.frames.push(RegistryNormalFrame{id,kind:NormalRegistrationKind::Eh4,previous,low,high,entry_sp:image.entry_sp,ebp:image.ebp,record:image.record,
   handler,scope,cookie,protected,plan,next:0,saved:[None;8],installed:false,unlinked:false});Ok(id)
 }
 fn install_head(&mut self,id:NormalFrameId,image:&FrameImage<RegistryHead>)->RegistryResult<()>{
  let result=(||{
   self.validate_image(id,image)?;let frame=self.top(id)?;
   if frame.installed||frame.unlinked||self.registry.head!=frame.previous{return Err("normal call original FS install phase");}Ok(())
  })();if let Err(e)=result{return self.fail(e);}
  self.registry.normal_epoch.as_mut().unwrap().frames.last_mut().unwrap().installed=true;
  self.registry.head=RegistryHead::Normal(id);Ok(())
 }
 fn step(&mut self,id:NormalFrameId,image:&FrameImage<RegistryHead>,effect:NormalFrameStep)->RegistryResult<Option<u32>>{
  let result=(||{
   self.validate_image(id,image)?;let frame=self.top(id)?;
   if !frame.installed||frame.plan.steps.get(frame.next)!=Some(&effect){return Err("normal call original epilog order");}
   match effect {
    NormalFrameStep::RestorePredecessor=>{
     if frame.unlinked||self.registry.head!=RegistryHead::Normal(id)||image.try_level!= -2{return Err("normal call unlink active scope/head");}Ok(None)
    },
    NormalFrameStep::PopSaved{offset,register}=>{
     if !frame.unlinked||self.registry.head!=frame.previous{return Err("normal call saved pop before unlink");}
     match image.words.get(&offset){Some(FrameWord::Saved(r,value))if *r==register=>Ok(*value),_=>Err("normal call saved pop identity")}
    },
    NormalFrameStep::DiscardGuard{..}=>{
     if !frame.unlinked||self.registry.head!=frame.previous{return Err("normal call guard discard before unlink");}Ok(None)
    },
    NormalFrameStep::CheckGuard{offset,..}=>{
     if !frame.unlinked||self.registry.head!=frame.previous{return Err("normal call guard check before unlink");}
     match image.words.get(&offset){Some(FrameWord::Guard{frame:ebp,cookie,bits})if *ebp==frame.ebp&&*cookie==frame.cookie&&*bits^*ebp==*cookie=>Ok(None),_=>Err("normal call original cookie failure")}
    },
   }
  })();let value=match result{Ok(value)=>value,Err(e)=>return self.fail(e)};
  let frame=self.registry.normal_epoch.as_mut().unwrap().frames.last_mut().unwrap();
  match effect {NormalFrameStep::RestorePredecessor=>{frame.unlinked=true;self.registry.head=frame.previous;},NormalFrameStep::PopSaved{register,..}=>frame.saved[register as usize]=value,_=>{}}
  frame.next+=1;Ok(value)
 }
 fn restore_previous_head(&mut self,id:NormalFrameId,image:&FrameImage<RegistryHead>)->RegistryResult<()>{self.step(id,image,NormalFrameStep::RestorePredecessor).map(|_|())}
 fn restore_saved(&mut self,id:NormalFrameId,image:&FrameImage<RegistryHead>,offset:i32,register:u8)->RegistryResult<Option<u32>>{self.step(id,image,NormalFrameStep::PopSaved{offset,register})}
 fn discard_guard(&mut self,id:NormalFrameId,image:&FrameImage<RegistryHead>,offset:i32,register:u8)->RegistryResult<()>{self.step(id,image,NormalFrameStep::DiscardGuard{offset,register}).map(|_|())}
 fn check_guard(&mut self,id:NormalFrameId,image:&FrameImage<RegistryHead>,offset:i32,target:u32)->RegistryResult<()>{self.step(id,image,NormalFrameStep::CheckGuard{offset,target}).map(|_|())}
 fn return_to_caller(&mut self,id:NormalFrameId,image:&FrameImage<RegistryHead>,caller_sp:u32)->RegistryResult<NormalFrameReceipt>{
  let result=(||{
   self.validate_image(id,image)?;let frame=self.top(id)?;
   if !frame.installed||!frame.unlinked||frame.next!=frame.plan.steps.len()||self.registry.head!=frame.previous
    ||frame.entry_sp.checked_add(4).and_then(|sp|sp.checked_add(frame.plan.callee_pop))!=Some(caller_sp) {
    return Err("normal call protected return/stack/epilog incomplete");
   }Ok(frame.saved)
  })();let saved=match result{Ok(saved)=>saved,Err(e)=>return self.fail(e)};
  self.registry.normal_epoch.as_mut().unwrap().frames.pop();Ok(NormalFrameReceipt{frame:id,caller_sp,saved})
 }
}
impl LocalRecord<'_> {
 fn active_index(&self)->RegistryResult<usize>{
  self.registry.available()?;
  let index=self.registry.temporary.len().checked_sub(1).ok_or("registry no live temporary")?;
  let record=&self.registry.temporary[index];
  let expected=if record.installed{RegistryHead::Owned(self.id)}else{record.previous};
  if record.id!=self.id||record.restored||self.registry.head!=expected{return Err("registry stale/non-LIFO temporary");}Ok(index)
 }
 fn install_head(&mut self,below_entry:u32,handler:u32)->RegistryResult<()>{
  let i=match self.active_index(){Ok(i)=>i,Err(e)=>return self.registry.fail(e)};
  let record=&mut self.registry.temporary[i];
  if record.installed||below_entry!=40||record.words[1]!=RegistryWord::Handler(handler){return self.registry.fail("registry original FS install mismatch/replay");}
  record.installed=true;self.registry.head=RegistryHead::Owned(self.id);Ok(())
 }
 fn read_word(&mut self,offset:u32)->RegistryResult<RegistryWord>{
  let i=match self.active_index(){Ok(i)=>i,Err(e)=>return self.registry.fail(e)};
  if !self.registry.temporary[i].installed||offset%4!=0||offset>24{return self.registry.fail("registry temporary initialization/complete-word bounds");}
  Ok(self.registry.temporary[i].words[offset as usize/4])
 }
 fn address(&mut self)->RegistryResult<u32>{let i=match self.active_index(){Ok(i)=>i,Err(e)=>return self.registry.fail(e)};Ok(self.registry.temporary[i].low)}
 fn frame(&mut self)->RegistryResult<RegistrationId>{let i=match self.active_index(){Ok(i)=>i,Err(e)=>return self.registry.fail(e)};Ok(self.registry.temporary[i].frame)}
 fn validate_binding(&mut self,binding:OwnedFrameBinding,image:&FrameImage<RegistryHead>)->RegistryResult<()>{
  let result=(||{
   let i=self.active_index()?;let temporary=&self.registry.temporary[i];
   if !temporary.installed{return Err("registry frame binding before FS installation");}
   let frame=&self.registry.frames[self.registry.frame_index(temporary.frame)?];
   if frame.binding!=binding{return Err("registry local frame binding mismatch");}
   self.registry.validate_frame(temporary.frame,image)
  })();match result{Ok(())=>Ok(()),Err(e)=>self.registry.fail(e)}
 }
 fn restore_previous_head(&mut self)->RegistryResult<()>{
  let i=match self.active_index(){Ok(i)=>i,Err(e)=>return self.registry.fail(e)};
  let record=&mut self.registry.temporary[i];
  if !record.installed||record.words[0]!=RegistryWord::Previous(record.previous){return self.registry.fail("registry temporary previous word corruption/phase");}
  record.restored=true;self.registry.head=record.previous;Ok(())
 }
 fn execute_nested<T>(&mut self,image:&mut FrameImage<RegistryHead>,entry:LocalEntry,body:impl FnOnce(&mut LocalRecord<'_>,&mut FrameImage<RegistryHead>)->RegistryResult<T>)->RegistryResult<T>{
  let i=match self.active_index(){Ok(i)=>i,Err(e)=>return self.registry.fail(e)};
  if !self.registry.temporary[i].installed{return self.registry.fail("registry nested dispatch before FS installation");}
  let frame=self.registry.temporary[i].frame;
  self.registry.execute_local(frame,image,entry,body)
 }
}
"#;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::OnceLock;

    const CASES: &str = r#"
fn fixture()->(ThreadRegistry,Vec<FrameImage<RegistryHead>>,Vec<RegistrationId>){
 let owner=7;let mut registry=ThreadRegistry::new(owner,0x1000,0x10000,&[(0x400000,0x410000)],0x408000).unwrap();
 let mut images=Vec::new();let mut ids=Vec::new();
 for (index,entry_sp) in [0xf000u32,0xe000].into_iter().enumerate(){
  let previous=registry.head().unwrap();let ebp=entry_sp-4;let cookie=0xaabbccdd;
  let mut words=std::collections::BTreeMap::from([
   (-128,FrameWord::Unknown),(-68,FrameWord::Guard{frame:ebp,cookie,bits:ebp^cookie}),
   (-36,FrameWord::Scalar(10)),(-20,FrameWord::Borrowed(previous)),
   (-16,FrameWord::Scalar(0x401000)),(-12,FrameWord::EncodedScope{scope:0x402000,cookie,bits:0x402000^cookie}),
   (-8,FrameWord::Scalar(1)),(-4,FrameWord::Saved(5,None)),(0,FrameWord::Return),
  ]);
  words.insert(-28,FrameWord::StackAddress(entry_sp-128));
  let image=FrameImage{words,entry_sp,ebp,esp:entry_sp-128,record:ebp-16,scope_va:0x402000,handler_va:0x401000,try_level:1};
  let binding=OwnedFrameBinding{owner,frame:FrameId{owner,generation:index as u64+1},index};
  ids.push(registry.install_frame(binding,&image).unwrap());images.push(image);
 }
 (registry,images,ids)
}
fn entry(sp:u32)->LocalEntry{LocalEntry{entry_sp:sp,handler:0x403000,cookie_address:0x408000,cookie:0xaabbccdd,target_level:-2}}
fn finish_level(image:&mut FrameImage<RegistryHead>){image.try_level=-2;image.words.insert(-8,FrameWord::Scalar((-2i32)as u32));}
fn ordinary_receipt(registry:&mut ThreadRegistry,id:RegistrationId,image:&mut FrameImage<RegistryHead>)->HandlerCompletion{
 registry.execute_handler(id,image,|_,image|{finish_level(image);Ok(())}).unwrap().1
}
fn normal(){
 let(mut registry,mut images,ids)=fixture();let plan=registry.contain(ids[0]).unwrap();assert_eq!(plan.younger(),&[ids[1]]);assert_eq!(plan.target(),ids[0]);
 let previous=registry.head().unwrap();
 let(_,receipt)=registry.execute_handler(ids[1],&mut images[1],|registry,image|{
  registry.execute_local(ids[1],image,entry(0xd000),|local,image|{
   assert_eq!(local.registry.head,previous);local.install_head(40,0x403000)?;assert_eq!(local.address()?,0xcfd8);assert_eq!(local.frame()?,ids[1]);
   assert_eq!(local.read_word(0)?,RegistryWord::Previous(previous));
   assert_eq!(local.read_word(4)?,RegistryWord::Handler(0x403000));
   assert_eq!(local.read_word(8)?,RegistryWord::Guard{record:0xcfd8,cookie:0xaabbccdd,bits:0xcfd8^0xaabbccdd});
   assert_eq!(local.read_word(12)?,RegistryWord::Scalar((-2i32)as u32));
   assert_eq!(local.read_word(16)?,RegistryWord::Establisher(ids[1],0xdfec));
   assert_eq!(local.read_word(20)?,RegistryWord::CookieAddress(0x408000));
   assert_eq!(local.read_word(24)?,RegistryWord::FramePointer(ids[1],0xdffc));
   image.words.insert(-36,FrameWord::Scalar(31));finish_level(image);local.restore_previous_head()
  })?;assert_eq!(registry.head()?,previous);Ok(())
 }).unwrap();
 assert!(registry.frames[1].live);assert!(registry.frames[1].linked);assert!(registry.target_ready().is_err()); // callback completion alone
 registry.unlink_head(ids[1]).unwrap();assert!(registry.frames[1].live);
 assert!(registry.target_ready().is_err()); // completed and unlinked is still live
 registry.retire_frame(receipt,&images[1]).unwrap();assert!(!registry.frames[1].live);assert_eq!(registry.target_ready().unwrap(),ids[0]);
 assert!(matches!(images[1].words.get(&-36),Some(FrameWord::Scalar(31))));assert!(registry.frames[0].live);
 // The alternate unlink-before-callback ordering is mechanically supported,
 // but choosing it for RtlUnwind still requires separate effect evidence.
 let(mut registry,mut images,ids)=fixture();registry.contain(ids[0]).unwrap();registry.unlink_head(ids[1]).unwrap();
 let receipt=ordinary_receipt(&mut registry,ids[1],&mut images[1]);registry.retire_frame(receipt,&images[1]).unwrap();assert_eq!(registry.target_ready().unwrap(),ids[0]);
}
fn nested(){
 let(mut registry,mut images,ids)=fixture();registry.contain(ids[0]).unwrap();
 registry.execute_handler(ids[1],&mut images[1],|registry,image|{
  registry.execute_local(ids[1],image,entry(0xd000),|outer,image|{
   outer.install_head(40,0x403000)?;let outer_id=outer.id;let previous=outer.read_word(0)?;
   outer.execute_nested(image,entry(0xcf00),|inner,image|{
    inner.install_head(40,0x403000)?;assert_eq!(inner.read_word(0)?,RegistryWord::Previous(RegistryHead::Owned(outer_id)));
    image.words.insert(-36,FrameWord::Scalar(19));inner.restore_previous_head()
   })?;
   assert_eq!(outer.read_word(0)?,previous);assert_eq!(outer.address()?,0xcfd8);outer.restore_previous_head()
  })
 }).unwrap();assert!(registry.temporary.is_empty());
 let(mut registry,mut images,ids)=fixture();registry.contain(ids[0]).unwrap();
 assert!(registry.execute_handler(ids[1],&mut images[1],|registry,image|registry.execute_local(ids[1],image,entry(0xd000),|outer,image|{
  outer.install_head(40,0x403000)?;let old=outer.id;outer.execute_nested(image,entry(0xcf00),|inner,_|{
   inner.install_head(40,0x403000)?;let child_head=inner.registry.head;
   assert!(LocalRecord{registry:inner.registry,id:old}.restore_previous_head().is_err());
   assert_eq!(inner.registry.head,child_head);Ok(())
  })
 })).is_err());assert_eq!(registry.temporary.len(),2);assert!(registry.frames[1].live);
}
fn failures(){
 let(mut registry,mut images,ids)=fixture();registry.contain(ids[0]).unwrap();
 let result=registry.execute_handler(ids[1],&mut images[1],|registry,image|registry.execute_local(ids[1],image,entry(0xd000),|local,image|{
  local.install_head(40,0x403000)?;image.words.insert(-36,FrameWord::Scalar(99));Err::<(),_>("independent cleanup failure")
 }));assert_eq!(result.unwrap_err(),"independent cleanup failure");
 assert!(matches!(images[1].words.get(&-36),Some(FrameWord::Scalar(99))));assert_eq!(registry.temporary.len(),1);assert_eq!(registry.head,RegistryHead::Owned(registry.temporary[0].id));assert!(registry.frames[1].live);
 let mut invoked=false;assert!(registry.execute_handler(ids[1],&mut images[1],|_,_|{invoked=true;Ok(())}).is_err());assert!(!invoked);assert!(registry.target_ready().is_err());
 let(mut registry,mut images,ids)=fixture();registry.contain(ids[0]).unwrap();
 assert!(registry.execute_handler(ids[1],&mut images[1],|registry,image|registry.execute_local(ids[1],image,entry(0xd000),|local,_|{
  local.install_head(40,0x403000)?;assert!(local.read_word(2).is_err());Ok(())
 })).is_err());assert_eq!(registry.temporary.len(),1);
 let(mut registry,mut images,ids)=fixture();registry.contain(ids[0]).unwrap();
 assert!(registry.execute_handler(ids[1],&mut images[1],|registry,image|registry.execute_local(ids[1],image,entry(0xd000),|_,_|Ok(()))).is_err());
 assert_eq!(registry.temporary.len(),1);assert!(!registry.temporary[0].restored);
}
fn instruction_timing(){
 // Reservation does not perform MOV FS. A failure before that instruction
 // leaves the original head untouched, including any preceding guest writes.
 let(mut registry,mut images,ids)=fixture();registry.contain(ids[0]).unwrap();let previous=registry.head;
 assert_eq!(registry.execute_handler(ids[1],&mut images[1],|registry,image|registry.execute_local(ids[1],image,entry(0xd000),|local,image|{
  assert_eq!(local.registry.head,previous);image.words.insert(-36,FrameWord::Scalar(73));Err::<(),_>("before original FS install")
 })).unwrap_err(),"before original FS install");
 assert_eq!(registry.head,previous);assert!(!registry.temporary[0].installed);assert!(matches!(images[1].words.get(&-36),Some(FrameWord::Scalar(73))));
 // The compiled instruction operands, not merely a successful closure,
 // authorize the reserved record's exact installation.
 for (depth,handler) in [(36,0x403000),(40,0x403004)]{
  let(mut registry,mut images,ids)=fixture();registry.contain(ids[0]).unwrap();let previous=registry.head;
  assert!(registry.execute_handler(ids[1],&mut images[1],|registry,image|registry.execute_local(ids[1],image,entry(0xd000),|local,_|local.install_head(depth,handler))).is_err());
  assert_eq!(registry.head,previous);assert!(!registry.temporary[0].installed);
 }
 let(mut registry,mut images,ids)=fixture();registry.contain(ids[0]).unwrap();
 assert!(registry.execute_handler(ids[1],&mut images[1],|registry,image|registry.execute_local(ids[1],image,entry(0xd000),|local,_|{
  local.install_head(40,0x403000)?;local.install_head(40,0x403000)
 })).is_err());assert!(registry.temporary[0].installed);assert!(!registry.temporary[0].restored);assert_eq!(registry.head,RegistryHead::Owned(registry.temporary[0].id));
 // A later fault must not undo the original POP FS, nor manufacture a
 // completion receipt or discard the still-live temporary storage.
 let(mut registry,mut images,ids)=fixture();registry.contain(ids[0]).unwrap();let previous=registry.head;
 assert_eq!(registry.execute_handler(ids[1],&mut images[1],|registry,image|registry.execute_local(ids[1],image,entry(0xd000),|local,image|{
  local.install_head(40,0x403000)?;image.words.insert(-36,FrameWord::Scalar(81));local.restore_previous_head()?;Err::<(),_>("after original FS restore")
 })).unwrap_err(),"after original FS restore");
 assert_eq!(registry.head,previous);assert!(registry.temporary[0].installed&&registry.temporary[0].restored);assert!(registry.frames[1].completion.is_none());assert!(matches!(images[1].words.get(&-36),Some(FrameWord::Scalar(81))));assert!(registry.target_ready().is_err());
}
fn identities(){
 let(mut a,mut images,ids)=fixture();let(b,_,other)=fixture();assert_ne!(ids[0],other[0]);assert!(b.validate_frame(ids[0],&images[0]).is_err());
 a.contain(ids[0]).unwrap();let mut wrong=ids[1];wrong.generation+=100;assert!(a.validate_frame(wrong,&images[1]).is_err());
 images[1].words.insert(-12,FrameWord::Bytes([Some(0);4]));assert!(a.execute_handler(ids[1],&mut images[1],|_,_|Ok(())).is_err());
 let(mut a,mut images,ids)=fixture();a.contain(ids[0]).unwrap();let receipt=ordinary_receipt(&mut a,ids[1],&mut images[1]);
 let replay=HandlerCompletion{identity:receipt.identity,frame:receipt.frame,generation:receipt.generation};a.unlink_head(ids[1]).unwrap();a.retire_frame(receipt,&images[1]).unwrap();assert!(a.retire_frame(replay,&images[1]).is_err());
 for wrong in [false,true]{
  let(mut registry,mut images,ids)=fixture();registry.contain(ids[0]).unwrap();
  let binding=registry.frames[if wrong{0}else{1}].binding;
  let result=registry.execute_handler(ids[1],&mut images[1],|registry,image|registry.execute_local(ids[1],image,entry(0xd000),|record,image|{
   record.install_head(40,0x403000)?;record.validate_binding(binding,image)?;record.restore_previous_head()
  }));assert_eq!(result.is_err(),wrong);
 }
 let(mut registry,mut images,ids)=fixture();let binding=registry.frames[1].binding;let selected=registry.frames[0].binding;
 assert_eq!(registry.registration(binding).unwrap(),ids[1]);
 for field in 0..4{
  let mut bad=binding;match field{0=>bad.owner+=1,1=>bad.frame.owner+=1,2=>bad.frame.generation+=1,_=>bad.index=0};
  assert!(registry.registration(bad).is_err());
 }
 registry.contain(ids[0]).unwrap();registry.unlink_head(ids[1]).unwrap();
 assert_eq!(registry.registration(binding).unwrap(),ids[1]); // unlinked storage is still live
 let receipt=ordinary_receipt(&mut registry,ids[1],&mut images[1]);registry.retire_frame(receipt,&images[1]).unwrap();
 assert!(registry.registration(binding).is_err());assert_eq!(registry.registration(selected).unwrap(),ids[0]);
}
fn aliases(){
 for change in 0..5 {
  let(mut registry,mut images,ids)=fixture();registry.contain(ids[0]).unwrap();let before=registry.head;
  let mut e=entry(0xd000);match change{0=>e.entry_sp=0xe000,1=>e.entry_sp=0x1008,2=>e.cookie_address+=4,3=>e.cookie^=1,_=>e.entry_sp=0xd001};
  assert!(registry.execute_handler(ids[1],&mut images[1],|registry,image|registry.execute_local(ids[1],image,e,|_,_|Ok(()))).is_err());assert_eq!(registry.head,before);assert!(registry.temporary.is_empty());
 }
 let(mut registry,mut images,ids)=fixture();registry.contain(ids[0]).unwrap();
 assert!(registry.execute_handler(ids[1],&mut images[1],|registry,image|registry.execute_local(ids[1],image,entry(0xd000),|outer,image|{outer.install_head(40,0x403000)?;outer.execute_nested(image,entry(0xcff0),|_,_|Ok(()))})).is_err());assert_eq!(registry.temporary.len(),1);
}
fn retirement(){
 let(mut registry,mut images,ids)=fixture();registry.contain(ids[0]).unwrap();let receipt=ordinary_receipt(&mut registry,ids[1],&mut images[1]);
 assert!(registry.retire_frame(receipt,&images[1]).is_err());assert!(registry.frames[1].live); // no decoded unlink yet
 let(mut registry,mut images,ids)=fixture();registry.contain(ids[0]).unwrap();registry.unlink_head(ids[1]).unwrap();
 let receipt=registry.execute_handler(ids[1],&mut images[1],|_,_|Ok(())).unwrap().1;
 assert!(registry.retire_frame(receipt,&images[1]).is_err());assert!(registry.frames[1].live); // incomplete scopes
 let(mut registry,mut images,ids)=fixture();registry.contain(ids[0]).unwrap();registry.unlink_head(ids[1]).unwrap();let receipt=ordinary_receipt(&mut registry,ids[1],&mut images[1]);registry.retire_frame(receipt,&images[1]).unwrap();
 let selected=ordinary_receipt(&mut registry,ids[0],&mut images[0]);assert!(registry.retire_frame(selected,&images[0]).is_err());assert!(registry.frames[0].live);
}
fn borrowed(){
 let(mut registry,mut images,ids)=fixture();let original_root=registry.frames[0].previous;assert!(matches!(original_root,RegistryHead::BorrowedRoot(_)));registry.contain(ids[0]).unwrap();
 let previous=registry.head;
 registry.with_borrowed_dispatcher(|registry|{
  let borrowed=registry.head()?;assert!(matches!(borrowed,RegistryHead::BorrowedDispatcher{..}));
  registry.execute_handler(ids[1],&mut images[1],|registry,image|registry.execute_local(ids[1],image,entry(0xd000),|local,_|{
   local.install_head(40,0x403000)?;assert_eq!(local.read_word(0)?,RegistryWord::Previous(borrowed));local.restore_previous_head()
  }))?;
  assert_eq!(registry.head()?,borrowed);Ok(())
 }).unwrap();assert_eq!(registry.head,previous);assert_eq!(registry.frames[0].previous,original_root);
}
fn main(){match std::env::args().nth(1).unwrap().as_str(){"normal"=>normal(),"nested"=>nested(),"failures"=>failures(),"instruction_timing"=>instruction_timing(),"identities"=>identities(),"aliases"=>aliases(),"retirement"=>retirement(),"borrowed"=>borrowed(),_=>panic!("unknown case")}}
"#;

    fn run(case: &str) {
        static BINARY: OnceLock<PathBuf> = OnceLock::new();
        let binary = BINARY.get_or_init(|| {
            let dir =
                std::env::temp_dir().join(format!("w2l-thread-registry-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let source = format!(
                "#![allow(dead_code)]\n{}\n{}\n{}\n{}",
                include_str!("linker/unwind_runtime.rs").replace("//!", "//"),
                super::super::frame_proof::EMITTED_TYPES,
                super::EMITTED_TYPES,
                CASES
            );
            let path = dir.join("main.rs");
            std::fs::write(&path, source).unwrap();
            let binary = dir.join(if cfg!(windows) {
                "registry.exe"
            } else {
                "registry"
            });
            let result = std::process::Command::new("rustc")
                .arg("--edition=2021")
                .arg(&path)
                .arg("-o")
                .arg(&binary)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            binary
        });
        let result = std::process::Command::new(binary)
            .arg(case)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    #[test]
    fn actual_typed_words_and_separate_unlink_retirement() {
        run("normal");
    }
    #[test]
    fn nested_original_pop_is_lifo_and_stale_outer_token_rejects() {
        run("nested");
    }
    #[test]
    fn partial_failure_and_ignored_errors_preserve_effects_without_receipt() {
        run("failures");
    }
    #[test]
    fn original_fs_install_and_pop_control_failure_effects() {
        run("instruction_timing");
    }
    #[test]
    fn independent_registry_owner_generation_and_completion_replay_reject() {
        run("identities");
    }
    #[test]
    fn complete_temporary_bounds_cookie_and_alias_checks() {
        run("aliases");
    }
    #[test]
    fn no_early_retirement_and_selected_lifetime_is_preserved() {
        run("retirement");
    }
    #[test]
    fn opaque_original_and_dispatcher_roots_survive_temporary_teardown() {
        run("borrowed");
    }
}

#[cfg(test)]
#[path = "thread_registry_normal_tests.rs"]
mod normal_tests;
