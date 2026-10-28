//! Private owned event for a compiler-proven selected RaiseException path.
//! Guest CALL state is separate from the OS-captured context. The latter is
//! represented only by the interval predicates justified by the explicit
//! closed, same-thread, non-intercepted delivery contract.
pub(crate) const EMITTED_TYPES: &str = r#"
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct OwnedEventId {owner:u64,event:u64,registry:RegistryIdentity,source:FrameId}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum EventLifetime {Live,Restoring,Finished,Expired}
#[derive(Clone)]
struct CapturedContext {
 identity:OwnedEventId,limit:u32,base:u32,
 lifetime:std::rc::Rc<std::cell::Cell<EventLifetime>>,
}
impl CapturedContext {
 fn preflight(&self,owner:u64)->Result<(),&'static str>{
  if owner==0||owner!=self.identity.owner||self.identity.registry.owner!=owner||self.identity.event==0
   ||self.identity.source.owner!=owner||self.identity.source.generation==0
   ||self.lifetime.get()!=EventLifetime::Live||self.limit==0||self.limit>=self.base {
   return Err("stale or foreign owned captured-context capability");
  }Ok(())
 }
 fn captured_below_limit(&self,owner:u64)->Result<bool,&'static str>{self.preflight(owner)?;Ok(false)}
 fn captured_at_most_base(&self,owner:u64)->Result<bool,&'static str>{self.preflight(owner)?;Ok(true)}
}
/// Emitted exclusively from RaiseCallProof. Integer fields are bindings of
/// validated original instructions, not a public OS effect attestation.
#[derive(Clone,Copy)]
struct RaiseSite {
 instruction:u32,return_ip:u32,iat:u32,code:u32,
 caller_sp_offset:i32,callee_sp_offset:i32,
}
#[derive(Clone,Copy)]
struct GuestRaiseCall {caller_sp:u32,callee_sp:u32,return_ip:u32}
struct OwnedExceptionEvent {
 identity:OwnedEventId,code:u32,guest:GuestRaiseCall,
 scratch_low:u32,scratch_high:u32,handler_sp:u32,
 captured:CapturedContext,
}
impl OwnedExceptionEvent {
 fn from_raise(machine:&mut Machine,registry:&ThreadRegistry,binding:OwnedFrameBinding,image:&FrameImage<RegistryHead>,site:RaiseSite,scratch_bytes:u32)->Result<Self,&'static str>{
  machine.check_raise_binding(binding).map_err(|_|"raise event source lifecycle")?;
  registry.available()?;
  let source=registry.registration(binding)?;registry.validate_frame(source,image)?;
  if registry.identity.owner!=machine.owner()||registry.head!=RegistryHead::Owned(source)
   ||registry.selected.is_some()||!registry.handlers.is_empty()||!registry.temporary.is_empty()||registry.borrowed_depth!=0 {
   return Err("raise event original thread/head identity");
  }
  if site.instruction==0||site.instruction.checked_add(6)!=Some(site.return_ip)||site.iat%4!=0
   ||site.code&0x10000000!=0||site.caller_sp_offset>=0
   ||site.callee_sp_offset< -4100||site.caller_sp_offset.checked_sub(4)!=Some(site.callee_sp_offset)
   ||site.caller_sp_offset.checked_add(16).is_none_or(|n|n>0) {
   return Err("raise event certified call shape");
  }
  // The containing compiler establishes executable and IAT permissions. These
  // checks retain complete range identity at runtime without manufacturing it.
  let contains=|address:u32,bytes:u32|address.checked_add(bytes).is_some_and(|end|registry.bound.iter().any(|&(a,b)|address>=a&&end<=b));
  if !contains(site.instruction,6)||!contains(site.return_ip,1)||!contains(site.iat,4){return Err("raise event original module range");}
  let caller_sp=frame_address(image.entry_sp,site.caller_sp_offset)?;
  let callee_sp=frame_address(image.entry_sp,site.callee_sp_offset)?;
  if image.esp!=caller_sp||caller_sp.checked_sub(4)!=Some(callee_sp){return Err("raise event original stack expression");}
  for (index,expected) in [site.code,0,0,0].into_iter().enumerate(){
   let address=caller_sp.checked_add(index as u32*4).ok_or("raise argument overflow")?;
   let key=ThreadRegistry::image_key(image,address)?;
   if !matches!(image.words.get(&key),Some(FrameWord::Scalar(value))if *value==expected){return Err("raise event original initialized argument");}
  }
  registry.range(callee_sp,u64::from(caller_sp))?;
  if registry.frames.iter().any(|f|f.live&&u64::from(callee_sp)<f.high&&u64::from(f.low)<u64::from(caller_sp)){
   return Err("raise event protected CALL slot alias");
  }
  // Reserve below all live guest frames and the actual CALL return slot. This
  // is owned native-dispatch scratch, not an assertion of Windows OS placement.
  if scratch_bytes==0||scratch_bytes>1024*1024||scratch_bytes%4!=0{return Err("raise event scratch budget/alignment");}
  let mut high=registry.frames.iter().filter(|f|f.live).map(|f|f.low).min().ok_or("raise event missing live frames")?.min(callee_sp);
  let extent=scratch_bytes.checked_add(4).ok_or("raise event scratch extent")?;
  let(low,handler_sp)=loop{
   let low=high.checked_sub(extent).ok_or("raise event scratch underflow")?;
   if low<registry.limit||high>registry.base{return Err("raise event insufficient owned thread scratch");}
   if let Some(next)=registry.bound.iter().filter(|&&(a,b)|low<b&&a<high).map(|&(a,_)|a).min(){high=next&!3;continue;}
   registry.range(low,u64::from(high))?;
   break(low,high.checked_sub(4).ok_or("raise event scratch return slot")?);
  };
  // All fallible provenance/resource checks precede the single issue latch.
  // No FS, frame byte, notification or cleanup effect has run here.
  let(owner,event)=machine.issue_owned_event(binding).map_err(|_|"raise event issue/replay")?;
  let identity=OwnedEventId{owner,event,registry:registry.identity,source:binding.frame};
  let lifetime=std::rc::Rc::new(std::cell::Cell::new(EventLifetime::Live));
  Ok(Self{identity,code:site.code,guest:GuestRaiseCall{caller_sp,callee_sp,return_ip:site.return_ip},scratch_low:low,scratch_high:high,handler_sp,
   captured:CapturedContext{identity,limit:registry.limit,base:registry.base,lifetime}})
 }
 fn owner(&self)->u64{self.identity.owner}
 fn code(&self)->u32{self.code}
 fn identity(&self)->OwnedEventId{self.identity}
 fn handler_sp(&self)->u32{self.handler_sp}
 fn captured_context(&self)->&CapturedContext{&self.captured}
 fn selected_identity(&self,machine:&Machine,registry:&ThreadRegistry)->Result<(),&'static str>{
  if self.identity.registry!=registry.identity||self.identity.event!=machine.event||!machine.event_issued
   ||machine.owner()!=self.identity.owner||!machine.owned_storage||!machine.explicit_dispatch {
   return Err("raise event foreign selected identity");
  }
  let selected=machine.owned_binding(machine.selected).map_err(|_|"raise event selected binding")?;
  if registry.target_ready()!=Ok(registry.registration(selected)?){return Err("raise event selected registration lifetime");}
  Ok(())
 }
 fn begin_restoration(&mut self,machine:&Machine,registry:&ThreadRegistry)->Result<(),&'static str>{
  self.captured.preflight(machine.owner())?;self.selected_identity(machine,registry)?;
  if machine.phase!=Phase::Restore{return Err("raise event selected transfer incomplete");}
  self.captured.lifetime.set(EventLifetime::Restoring);Ok(())
 }
 fn finish(&mut self,machine:&Machine,registry:&ThreadRegistry)->Result<(),&'static str>{
  if self.captured.lifetime.get()!=EventLifetime::Restoring||machine.phase!=Phase::Done{return Err("raise event original restoration incomplete/replayed");}
  self.selected_identity(machine,registry)?;
  if machine.owned_context.is_none_or(|c|c[0].is_none()||c[4].is_none()||c[5].is_none()||c[8].is_none()){
   return Err("raise event missing original restored projection");
  }
  self.captured.lifetime.set(EventLifetime::Finished);Ok(())
 }
}
impl Drop for OwnedExceptionEvent {
 fn drop(&mut self){if self.captured.lifetime.get()!=EventLifetime::Finished{self.captured.lifetime.set(EventLifetime::Expired);}}
}
"#;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::OnceLock;

    const CASES: &str = r#"
fn fixture()->(Machine,ThreadRegistry,Vec<FrameImage<RegistryHead>>,Vec<RegistrationId>){
 let machine=Machine::new_dispatch_known(vec![FrameSpec{scopes:vec![]},FrameSpec{scopes:vec![]}],0,[None;10],Some(0)).unwrap();
 let owner=machine.owner();let mut registry=ThreadRegistry::new(owner,0x1000,0x10000,&[(0x400000,0x420000)],0x41c000).unwrap();
 let mut images=Vec::new();let mut registrations=Vec::new();
 for(index,entry_sp)in[0xf000u32,0xe000].into_iter().enumerate(){
  let ebp=entry_sp-4;let cookie=0x12345678;let previous=registry.head().unwrap();
  let words=std::collections::BTreeMap::from([
   (-128,FrameWord::Scalar(0xe0424242)),(-124,FrameWord::Scalar(0)),(-120,FrameWord::Scalar(0)),(-116,FrameWord::Scalar(0)),
   (-20,FrameWord::Borrowed(previous)),(-16,FrameWord::Scalar(0x4021c0)),(-12,FrameWord::EncodedScope{scope:0x41b000,cookie,bits:0x41b000^cookie}),
   (-8,FrameWord::Scalar(0)),(-4,FrameWord::Saved(5,None)),(0,FrameWord::Return),
  ]);
  let image=FrameImage{words,entry_sp,ebp,esp:entry_sp-128,record:ebp-16,scope_va:0x41b000,handler_va:0x4021c0,try_level:0};
  registrations.push(registry.install_frame(machine.binding(index).unwrap(),&image).unwrap());images.push(image);
 }
 (machine,registry,images,registrations)
}
fn site()->RaiseSite{RaiseSite{instruction:0x401140,return_ip:0x401146,iat:0x415008,code:0xe0424242,caller_sp_offset:-128,callee_sp_offset:-132}}
fn successful(){
 let(mut machine,registry,images,_)=fixture();let binding=machine.binding(1).unwrap();let before=registry.head;
 let event=OwnedExceptionEvent::from_raise(&mut machine,&registry,binding,&images[1],site(),128).unwrap();
 assert_eq!(event.code(),0xe0424242);assert_eq!(event.identity().source,binding.frame);assert_eq!(event.owner(),machine.owner());
 assert_eq!((event.guest.caller_sp,event.guest.callee_sp,event.guest.return_ip),(0xdf80,0xdf7c,0x401146));
 assert_eq!((event.scratch_low,event.scratch_high,event.handler_sp()),(0xdef8,0xdf7c,0xdf78));
 assert_eq!(registry.head,before);assert!(registry.temporary.is_empty());assert_eq!(machine.owned_context,Some([None;10]));
 let captured=event.captured_context();assert!(!captured.captured_below_limit(machine.owner()).unwrap());assert!(captured.captured_at_most_base(machine.owner()).unwrap());
 assert!(captured.preflight(machine.owner()+1).is_err());assert!(captured.captured_below_limit(machine.owner()+1).is_err());
 assert!(OwnedExceptionEvent::from_raise(&mut machine,&registry,binding,&images[1],site(),128).is_err());
 let alias=captured.clone();drop(event);assert!(alias.preflight(machine.owner()).is_err());
}
fn bad_arguments(){
 for kind in 0..8{
  let(mut machine,registry,mut images,_)=fixture();let binding=machine.binding(1).unwrap();let head=registry.head;let mut call=site();
  match kind{0=>{images[1].words.insert(-124,FrameWord::Scalar(1));},1=>{images[1].words.insert(-120,FrameWord::Unknown);},2=>{images[1].words.insert(-116,FrameWord::StackAddress(0xdf80));},3=>call.code|=0x10000000,4=>call.caller_sp_offset+=4,5=>call.callee_sp_offset-=4,6=>call.return_ip+=1,_=>call.iat+=1};
  assert!(OwnedExceptionEvent::from_raise(&mut machine,&registry,binding,&images[1],call,128).is_err());assert!(!machine.event_issued);assert_eq!(registry.head,head);assert!(registry.temporary.is_empty());
 }
}
fn scratch(){
 for bytes in [0,1,1024*1024+4,0xe000]{
  let(mut machine,registry,images,_)=fixture();let binding=machine.binding(1).unwrap();assert!(OwnedExceptionEvent::from_raise(&mut machine,&registry,binding,&images[1],site(),bytes).is_err());assert!(!machine.event_issued);
 }
 let(mut machine,mut registry,images,_)=fixture();let binding=machine.binding(1).unwrap();registry.bound.push((0xdf00,0xdf40));
 let event=OwnedExceptionEvent::from_raise(&mut machine,&registry,binding,&images[1],site(),128).unwrap();assert_eq!((event.scratch_low,event.scratch_high),(0xde7c,0xdf00));assert_eq!(event.handler_sp(),0xdefc);
 let(mut machine,mut registry,images,_)=fixture();let binding=machine.binding(1).unwrap();registry.bound.push((0xdf7c,0xdf80));assert!(OwnedExceptionEvent::from_raise(&mut machine,&registry,binding,&images[1],site(),128).is_err());assert!(!machine.event_issued);
}
fn identities(){
 let(mut machine,registry,images,ids)=fixture();let top=machine.binding(1).unwrap();let lower=machine.binding(0).unwrap();
 assert!(OwnedExceptionEvent::from_raise(&mut machine,&registry,lower,&images[0],site(),128).is_err());assert!(!machine.event_issued);
 let(foreign,foreign_registry,_,_)=fixture();assert!(OwnedExceptionEvent::from_raise(&mut machine,&foreign_registry,top,&images[1],site(),128).is_err());
 let mut bad=top;bad.frame.generation+=1;assert!(OwnedExceptionEvent::from_raise(&mut machine,&registry,bad,&images[1],site(),128).is_err());
 let event=OwnedExceptionEvent::from_raise(&mut machine,&registry,top,&images[1],site(),128).unwrap();assert_ne!(event.owner(),foreign.owner());assert_eq!(event.identity().registry,ids[1].identity);
}
fn finish(){
 let(mut machine,mut registry,mut images,ids)=fixture();let top=machine.binding(1).unwrap();let selected=machine.binding(0).unwrap();
 let mut event=OwnedExceptionEvent::from_raise(&mut machine,&registry,top,&images[1],site(),128).unwrap();let alias=event.captured_context().clone();
 assert!(event.finish(&machine,&registry).is_err());assert!(alias.preflight(machine.owner()).is_ok());
 registry.contain(ids[0]).unwrap();let(_,receipt)=registry.execute_handler(ids[1],&mut images[1],|_,image|{image.try_level=-2;image.words.insert(-8,FrameWord::Scalar((-2i32)as u32));Ok(())}).unwrap();
 registry.unlink_head(ids[1]).unwrap();registry.retire_frame(receipt,&images[1]).unwrap();machine.retire_dispatched(top).unwrap();machine.finish_selected_dispatch(selected).unwrap();
 event.begin_restoration(&machine,&registry).unwrap();assert!(alias.preflight(machine.owner()).is_err());assert!(event.begin_restoration(&machine,&registry).is_err());
 let restored=[Some(7),None,None,None,Some(0xef80),Some(0xeffc),None,None,Some(0x401396),None];
 machine.restore_owned(0x401396,|lease,current|{assert_eq!(current,[None;10]);lease.bind_storage(selected)?;Ok(restored)}).unwrap();
 event.finish(&machine,&registry).unwrap();assert!(alias.preflight(machine.owner()).is_err());assert!(event.finish(&machine,&registry).is_err());assert_eq!(machine.owned_context,Some(restored));assert!(registry.frames[0].live);
}
fn main(){match std::env::args().nth(1).unwrap().as_str(){"successful"=>successful(),"arguments"=>bad_arguments(),"scratch"=>scratch(),"identities"=>identities(),"finish"=>finish(),_=>panic!("unknown test")}}
"#;

    fn run(case: &str) {
        static BINARY: OnceLock<PathBuf> = OnceLock::new();
        let binary = BINARY.get_or_init(|| {
            let source = format!(
                "#![allow(dead_code)]\n{}\n{}\n{}\n{}\n{}",
                include_str!("linker/unwind_runtime.rs").replace("//!", "//"),
                super::super::frame_proof::EMITTED_TYPES,
                super::super::thread_registry::EMITTED_TYPES,
                super::EMITTED_TYPES,
                CASES
            );
            let dir =
                std::env::temp_dir().join(format!("w2l-exception-event-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("main.rs");
            std::fs::write(&path, source).unwrap();
            let binary = dir.join(if cfg!(windows) { "check.exe" } else { "check" });
            let built = std::process::Command::new("rustc")
                .arg("--edition=2021")
                .arg(&path)
                .arg("-o")
                .arg(&binary)
                .output()
                .unwrap();
            assert!(
                built.status.success(),
                "{}",
                String::from_utf8_lossy(&built.stderr)
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
    fn original_call_state_does_not_fabricate_captured_registers() {
        run("successful");
    }
    #[test]
    fn malformed_arguments_and_call_shape_reject_before_issuance() {
        run("arguments");
    }
    #[test]
    fn scratch_is_derived_and_excludes_call_module_and_thread_boundaries() {
        run("scratch");
    }
    #[test]
    fn only_live_top_owner_binding_can_issue_one_event() {
        run("identities");
    }
    #[test]
    fn selected_restoration_finishes_event_and_invalidates_context_aliases() {
        run("finish");
    }
}
