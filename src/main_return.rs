//! A normal function-return receipt is distinct from an unwind completion.
//! Original instructions restore FS, consume saved slots and check the guard
//! before the protected return retires the selected activation. The caller's
//! continuation stays opaque; this is not CRT termination or process exit.
pub(crate) const EMITTED_TYPES: &str = r#"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum NormalReturnPhase {Linked,Unlinked,GuardChecked,CallerFrame,Returned,Failed}
struct NormalReturnPlan {pops:Vec<(i32,u8,bool)>,cookie_offset:i32,security_target:u32,return_offset:i32}
#[derive(Debug)]
struct NormalReturnReceipt {owner:u64,event:u64,registry:RegistryIdentity,frame:FrameId,caller_sp:u32,value:u32,context:[Option<u32>;10]}
struct NormalReturnSession<'a> {
 machine:&'a mut Machine,registry:&'a mut ThreadRegistry,binding:OwnedFrameBinding,
 registration:RegistrationId,event:OwnedEventId,previous:RegistryHead,entry_sp:u32,ebp:u32,
 plan:NormalReturnPlan,pop_values:Vec<Option<u32>>,guard:(u32,u32,u32),
 next_pop:usize,saved:[Option<u32>;8],phase:NormalReturnPhase,receipt:Option<NormalReturnReceipt>,
 normal_permit:FinishedEventPermit,
}
impl<'a> NormalReturnSession<'a> {
 fn new(machine:&'a mut Machine,registry:&'a mut ThreadRegistry,binding:OwnedFrameBinding,image:&FrameImage<RegistryHead>,event:&OwnedExceptionEvent,plan:NormalReturnPlan)->Result<Self,&'static str>{
  if machine.phase!=Phase::Done||!machine.owned_storage||!machine.explicit_dispatch
   ||event.captured.lifetime.get()!=EventLifetime::Finished||event.identity.owner!=machine.owner()
   ||event.identity.event!=machine.event||event.identity.registry!=registry.identity
   ||machine.owned_binding(machine.selected).map_err(|_|"normal return selected owner")?!=binding {
   return Err("normal return unfinished or foreign event");
  }
  let registration=registry.registration(binding)?;registry.validate_frame(registration,image)?;
  if registry.target_ready()?!=registration||image.try_level!= -2||plan.pops.is_empty()||plan.pops.len()>16
   ||plan.pops.last()!=Some(&(0,5,false))||plan.return_offset!=4
   ||!registry.module_contains_address(plan.security_target) {
   return Err("normal return target/plan bounds");
  }
  let index=registry.frame_index(registration)?;let previous=registry.frames[index].previous;
  let mut pop_values=Vec::new();let mut unique=std::collections::BTreeSet::new();
  for &(offset,register,discard_guard) in &plan.pops {
   if offset%4!=0||register>7||!unique.insert(offset){return Err("normal return pop plan");}
   let key=i32::try_from(i64::from(image.ebp)+i64::from(offset)-i64::from(image.entry_sp)).map_err(|_|"normal return pop offset")?;
   let value=match(image.words.get(&key),discard_guard){
    (Some(FrameWord::Saved(r,value)),false)if *r==register=>*value,
    (Some(FrameWord::Guard{frame,..}),true)if *frame==image.ebp&&register==1=>None,
    _=>return Err("normal return protected slot identity"),
   };pop_values.push(value);
  }
  let key=i32::try_from(i64::from(image.ebp)+i64::from(plan.cookie_offset)-i64::from(image.entry_sp)).map_err(|_|"normal return guard offset")?;
  let guard=match image.words.get(&key){Some(FrameWord::Guard{frame,cookie,bits})if *frame==image.ebp=>(*frame,*cookie,*bits),_=>return Err("normal return guard ownership")};
  if !matches!(image.words.get(&0),Some(FrameWord::Return)){return Err("normal return caller continuation");}
  let normal_permit=event.take_normal_permit()?;
  let entry_sp=image.entry_sp;let ebp=image.ebp;machine.phase=Phase::Returning;
  Ok(Self{machine,registry,binding,registration,event:event.identity,previous,entry_sp,ebp,plan,pop_values,guard,next_pop:0,saved:[None;8],phase:NormalReturnPhase::Linked,receipt:None,normal_permit})
 }
 fn fail<T>(&mut self,error:&'static str)->Result<T,&'static str>{
  self.phase=NormalReturnPhase::Failed;self.machine.phase=Phase::Blocked;self.registry.block(error);Err(error)
 }
 /// A real ordinary call may temporarily extend the original thread chain
 /// only before Main's original FS unlink. Its completed event/containment
 /// receipt stays owned by this session throughout the nested call epoch.
 fn with_normal_calls<T>(&mut self,image:&FrameImage<RegistryHead>,body:impl FnOnce(&mut NormalCallEpoch<'_>)->RegistryResult<T>)->Result<T,&'static str>{
  if self.phase!=NormalReturnPhase::Linked||self.machine.phase!=Phase::Returning{return self.fail("normal call after Main unlink/return");}
  match self.registry.with_normal_calls(self.machine,&mut self.normal_permit,image,body){Ok(value)=>Ok(value),Err(error)=>self.fail(error)}
 }
 fn apply(&mut self,effect:CompletionEffect<'_,RegistryHead>)->Result<(),&'static str>{
  if self.machine.phase!=Phase::Returning||self.registry.available().is_err(){return self.fail("normal return phase/lifetime");}
  let result=(||match effect{
   CompletionEffect::RestorePredecessor(previous)=>{
    if self.phase!=NormalReturnPhase::Linked||*previous!=self.previous||self.registry.target_ready()?!=self.registration{return Err("normal return original FS predecessor");}
    let index=self.registry.frame_index(self.registration)?;
    if !self.registry.frames[index].linked||self.registry.head!=RegistryHead::Owned(self.registration){return Err("normal return linked head");}
    self.registry.head=self.previous;self.registry.frames[index].linked=false;self.phase=NormalReturnPhase::Unlinked;Ok(())
   },
   CompletionEffect::Pop{offset,register,saved,guard}=>{
    if self.plan.pops.get(self.next_pop)!=Some(&(offset,register,guard))||self.pop_values.get(self.next_pop)!=Some(&saved)
     ||(register==5&&self.phase!=NormalReturnPhase::GuardChecked)||(register!=5&&self.phase!=NormalReturnPhase::Unlinked){return Err("normal return pop order/identity");}
    if !guard{self.saved[register as usize]=saved;}self.next_pop+=1;
    if register==5{self.phase=NormalReturnPhase::CallerFrame;}Ok(())
   },
   CompletionEffect::Cookie{offset,frame,cookie,bits,target}=>{
    if self.phase!=NormalReturnPhase::Unlinked||self.next_pop+1!=self.plan.pops.len()
     ||offset!=self.plan.cookie_offset||target!=self.plan.security_target||(frame,cookie,bits)!=self.guard
     ||frame!=self.ebp||bits^frame!=cookie{return Err("normal return original cookie failure");}
    self.phase=NormalReturnPhase::GuardChecked;Ok(())
   },
   CompletionEffect::Return{offset,value,saved,caller_sp}=>{
    if self.phase!=NormalReturnPhase::CallerFrame||self.next_pop!=self.plan.pops.len()||offset!=self.plan.return_offset
     ||saved!=self.saved||self.entry_sp.checked_add(4)!=Some(caller_sp)||self.registry.head!=self.previous{return Err("normal return protected continuation/stack");}
    let index=self.registry.frame_index(self.registration)?;
    if self.registry.frames[index].linked||!self.machine.frames[self.binding.index].live{return Err("normal return premature retirement");}
    self.registry.frames[index].live=false;self.machine.frames[self.binding.index].live=false;
    let mut context=[None;10];context[0]=Some(value);context[4]=Some(caller_sp);for r in [3,5,6,7]{context[r]=saved[r];}
    self.machine.owned_context=Some(context);self.machine.phase=Phase::Returned;self.phase=NormalReturnPhase::Returned;
    self.receipt=Some(NormalReturnReceipt{owner:self.binding.owner,event:self.event.event,registry:self.registry.identity,frame:self.binding.frame,caller_sp,value,context});Ok(())
   },
  })();if let Err(e)=result{return self.fail(e);}Ok(())
 }
 fn finish(&mut self,outcome:&CompletionOutcome<RegistryHead>)->Result<NormalReturnReceipt,&'static str>{
  if self.phase!=NormalReturnPhase::Returned||self.machine.phase!=Phase::Returned||outcome.predecessor!=self.previous||outcome.saved!=self.saved{return self.fail("normal return missing completion");}
  let receipt=self.receipt.take().ok_or("normal return replay")?;
  if receipt.owner!=self.binding.owner||receipt.frame!=self.binding.frame||receipt.event!=self.event.event||receipt.registry!=self.registry.identity
   ||receipt.value!=outcome.value||receipt.caller_sp!=outcome.caller_sp||self.machine.owned_context!=Some(receipt.context){return self.fail("normal return completion mismatch");}Ok(receipt)
 }
}
impl Drop for NormalReturnSession<'_>{fn drop(&mut self){if self.phase!=NormalReturnPhase::Returned{self.machine.phase=Phase::Blocked;self.registry.block("incomplete original normal return");}}}
"#;
