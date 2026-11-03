//! Native tests of the shared normal-call lifecycle. The fixture establishes a
//! completed owned event; it is not a claim to execute Windows CRT startup.
use std::path::PathBuf;
use std::sync::OnceLock;

const CASES: &str = r#"
fn image(entry_sp:u32,previous:RegistryHead)->FrameImage<RegistryHead>{
 let ebp=entry_sp-4;let cookie=0x7319abdc;
 FrameImage{entry_sp,ebp,esp:entry_sp-128,record:ebp-16,scope_va:0x405800,handler_va:0x401500,try_level:-2,
 words:std::collections::BTreeMap::from([
  (-128,FrameWord::Unknown),(-72,FrameWord::Guard{frame:ebp,cookie,bits:ebp^cookie}),
  (-68,FrameWord::Saved(7,None)),(-64,FrameWord::Saved(6,Some(0x76543210))),(-60,FrameWord::Saved(3,None)),
  (-40,FrameWord::Scalar(7)),(-32,FrameWord::Guard{frame:ebp,cookie,bits:ebp^cookie}),
  (-20,FrameWord::Borrowed(previous)),(-16,FrameWord::Scalar(0x401500)),
  (-12,FrameWord::EncodedScope{scope:0x405800,cookie,bits:0x405800^cookie}),
  (-8,FrameWord::Scalar((-2i32)as u32)),(-4,FrameWord::Saved(5,None)),(0,FrameWord::Return)])}
}
fn plan()->NormalFramePlan{NormalFramePlan{steps:vec![
 NormalFrameStep::RestorePredecessor,NormalFrameStep::DiscardGuard{offset:-72,register:1},
 NormalFrameStep::PopSaved{offset:-68,register:7},NormalFrameStep::PopSaved{offset:-64,register:6},
 NormalFrameStep::PopSaved{offset:-60,register:3},NormalFrameStep::CheckGuard{offset:-32,target:0x401600},
 NormalFrameStep::PopSaved{offset:-4,register:5}],callee_pop:12}}
fn fixture()->(Machine,ThreadRegistry,FrameImage<RegistryHead>,FinishedEventPermit){fixture_with_extra(&[])}
fn fixture_with_extra(extra:&[(u32,u32)])->(Machine,ThreadRegistry,FrameImage<RegistryHead>,FinishedEventPermit){
 let mut m=Machine::new_dispatch_known(vec![FrameSpec{scopes:vec![]}],0,[None;10],Some(0)).unwrap();
 let mut ranges=vec![(0x400000,0x410000)];ranges.extend_from_slice(extra);
 let mut r=ThreadRegistry::new(m.owner(),0x1000,0x10000,&ranges,0x408000).unwrap();
 let im=image(0xf000,r.head().unwrap());let binding=m.owned_binding(0).unwrap();
 let id=r.install_frame(binding,&im).unwrap();m.issue_owned_event(binding).unwrap();r.contain(id).unwrap();
 m.finish_selected_dispatch(binding).unwrap();
 m.restore_owned(0x401200,|lease,current|{assert_eq!(current,[None;10]);lease.bind_storage(binding)?;
  Ok([Some(5),None,None,None,Some(im.esp),Some(im.ebp),None,None,Some(0x401200),None])}).unwrap();
 let permit=r.mint_finished_event(&m,binding).unwrap();(m,r,im,permit)
}
fn complete(epoch:&mut NormalCallEpoch<'_>,id:NormalFrameId,im:&FrameImage<RegistryHead>)->RegistryResult<NormalFrameReceipt>{
 epoch.restore_previous_head(id,im)?;epoch.discard_guard(id,im,-72,1)?;
 assert_eq!(epoch.restore_saved(id,im,-68,7)?,None);assert_eq!(epoch.restore_saved(id,im,-64,6)?,Some(0x76543210));
 assert_eq!(epoch.restore_saved(id,im,-60,3)?,None);epoch.check_guard(id,im,-32,0x401600)?;
 assert_eq!(epoch.restore_saved(id,im,-4,5)?,None);epoch.return_to_caller(id,im,im.entry_sp+16)
}
fn nested(){
 let(mut m,mut r,main,mut permit)=fixture();let before=m.owned_context;let selected=r.target_ready().unwrap();let previous=r.frames[0].previous;
 let containment=r.selected.as_ref().unwrap().younger.clone();let stamp=permit.stamp;
 for index in 0..3{
  if index==1{m.phase=Phase::Returning;}
  let receipt=r.with_normal_calls(&m,&mut permit,&main,|epoch|{
   let mut outer=image(0xe000,epoch.head()?);let a=epoch.reserve_eh4(&outer,plan())?;
   assert_eq!(epoch.head()?,RegistryHead::Owned(selected));epoch.install_head(a,&outer)?;
   let inner=image(0xd000,epoch.head()?);let b=epoch.reserve_eh4(&inner,plan())?;epoch.install_head(b,&inner)?;
   assert!(epoch.registry.target_ready().is_err());
   let inner_receipt=complete(epoch,b,&inner)?;assert_eq!(inner_receipt.frame,b);
   assert_eq!(epoch.head()?,RegistryHead::Normal(a));
   outer.words.insert(-40,FrameWord::Scalar(0xa5));complete(epoch,a,&outer)
  }).unwrap();
  assert_eq!(receipt.caller_sp,0xe010);assert_eq!(receipt.saved[6],Some(0x76543210));assert_eq!(receipt.saved[3],None);
  assert_eq!(m.owned_context,before);assert_eq!(r.target_ready().unwrap(),selected);assert!(r.frames[0].live&&r.frames[0].linked);
  assert_eq!(r.frames[0].previous,previous);assert_eq!(r.next_unwind,0);assert_eq!(r.selected.as_ref().unwrap().younger,containment);
 }
 assert_eq!(permit.stamp,stamp+3);assert!(r.normal_epoch.is_none());
}
fn authority(){
 for mode in 0..8{
  let(mut m,mut r,main,mut permit)=fixture();
  match mode{0=>m.phase=Phase::Cleanup,1=>m.phase=Phase::Restore,2=>m.phase=Phase::Returned,
   3=>m.owned_context.as_mut().unwrap()[3]=Some(0),4=>permit.event+=1,5=>permit.identity.instance+=1,
   6=>permit.binding.frame.generation+=1,_=>permit.stamp+=1};
  let mut ran=false;assert!(r.with_normal_calls(&m,&mut permit,&main,|_|{ran=true;Ok(())}).is_err());assert!(!ran);
  assert!(r.normal_epoch.is_none());assert!(r.frames[0].live&&r.frames[0].linked);
 }
 let(m,mut r,main,mut permit)=fixture();assert!(r.mint_finished_event(&m,permit.binding).is_err());
 let mut replay=FinishedEventPermit{identity:permit.identity,event:permit.event,binding:permit.binding,selected:permit.selected,context:permit.context,stamp:permit.stamp};
 r.with_normal_calls(&m,&mut permit,&main,|_|Ok(())).unwrap();
 assert!(r.with_normal_calls(&m,&mut replay,&main,|_|->RegistryResult<()>{panic!("stale permit executed")}).is_err());
 let(m,mut r,main,_)=fixture();let(_,_,_,mut foreign)=fixture();
 assert!(r.with_normal_calls(&m,&mut foreign,&main,|_|->RegistryResult<()>{panic!("foreign permit executed")}).is_err());
}
fn bounds(){
 for mode in 0..10{
  let(m,mut r,main,mut permit)=fixture();let before=r.head;
  assert!(r.with_normal_calls(&m,&mut permit,&main,|epoch|{
   let mut im=image(0xe000,epoch.head()?);let mut p=plan();
   match mode{
    0=>im.entry_sp=0xf000,1=>im.esp=0x0ffc,2=>{im.words.insert(4,FrameWord::Saved(6,None));},
    3=>{im.words.insert(0,FrameWord::Unknown);},4=>{im.words.insert(-20,FrameWord::Borrowed(RegistryHead::BorrowedRoot(epoch.registry.identity)));},
    5=>{p.steps.remove(3);},6=>{im.words.insert(-32,FrameWord::Scalar(0));},
    7=>{p.steps[2]=NormalFrameStep::PopSaved{offset:-64,register:6};},
    8=>{im=image(0xf100,epoch.head()?);},_=>{p.callee_pop=0x2000;},
   }
   epoch.reserve_eh4(&im,p)?;Ok(())
  }).is_err());assert_eq!(r.head,before);assert!(r.normal_epoch.as_ref().unwrap().frames.is_empty());
 }
}
fn order(){
 for mode in 0..8{
  let(m,mut r,main,mut permit)=fixture();
  assert!(r.with_normal_calls(&m,&mut permit,&main,|epoch|{
   let mut im=image(0xe000,epoch.head()?);let id=epoch.reserve_eh4(&im,plan())?;
   if mode==0{return epoch.return_to_caller(id,&im,0xe010).map(|_|());}
   epoch.install_head(id,&im)?;
   match mode{
    1=>epoch.return_to_caller(id,&im,0xe010).map(|_|()),
    2=>epoch.restore_saved(id,&im,-68,7).map(|_|()),
    3=>{im.try_level=0;im.words.insert(-8,FrameWord::Scalar(0));epoch.restore_previous_head(id,&im)},
    4=>{let child=image(0xd000,epoch.head()?);let _=epoch.reserve_eh4(&child,plan())?;epoch.restore_previous_head(id,&im)},
    5=>{im.words.insert(-64,FrameWord::Saved(6,Some(0)));epoch.restore_previous_head(id,&im)},
    6=>{complete(epoch,id,&im)?;epoch.install_head(id,&im)},
    _=>{let mut foreign=id;foreign.identity.instance+=1;epoch.restore_previous_head(foreign,&im)},
   }
  }).is_err());assert!(r.frames[0].live&&r.frames[0].linked);assert!(r.target_ready().is_err());
 }
}
fn failure(){
 for mode in 0..4{
  let(m,mut r,main,mut permit)=fixture();let previous=r.head;let mut effects=Vec::new();
  let result=r.with_normal_calls(&m,&mut permit,&main,|epoch|{
   let im=image(0xe000,epoch.head()?);let id=epoch.reserve_eh4(&im,plan())?;effects.push(1);
   if mode==0{return Err("before installation");}epoch.install_head(id,&im)?;effects.push(2);
   if mode==1{return Err("during original helper");}epoch.restore_previous_head(id,&im)?;effects.push(3);
   if mode==2{return Err("after original unlink");}Ok(())
  });assert!(result.is_err());assert!(r.available().is_err());
  let active=&r.normal_epoch.as_ref().unwrap().frames[0];assert_eq!(active.installed,mode>0);assert_eq!(active.unlinked,mode>1);
  if mode==1{assert_eq!(r.head,RegistryHead::Normal(active.id));}else{assert_eq!(r.head,previous);}
  assert_eq!(effects,match mode{0=>vec![1],1=>vec![1,2],_=>vec![1,2,3]});assert!(r.frames[0].live);
  assert!(r.with_normal_calls(&m,&mut permit,&main,|_|->RegistryResult<()>{panic!("failed call retried")}).is_err());
 }
}
fn exception_boundary(){
 for mode in 0..3{
  let(m,mut r,mut main,mut permit)=fixture();let selected=r.target_ready().unwrap();
  let frozen=image(main.entry_sp,r.frames[0].previous);
  assert!(r.with_normal_calls(&m,&mut permit,&frozen,|epoch|{
   match mode{0=>epoch.registry.execute_handler(selected,&mut main,|_,_|Ok(())).map(|_|()),
    1=>epoch.registry.with_borrowed_dispatcher(|_|Ok(())),_=>epoch.registry.unlink_head(selected)}
  }).is_err());assert!(r.frames[0].live&&r.frames[0].linked);
 }
}
fn observed_epilog(){
 // The actual FILE wrapper has POP ECX/EDI/ESI/EBX, LEAVE, RET 12 after
 // its original FS unlink, without a normal-path cookie-check call.
 let(m,mut r,main,mut permit)=fixture();
 r.with_normal_calls(&m,&mut permit,&main,|epoch|{
  let im=image(0xe000,epoch.head()?);let mut p=plan();p.steps.remove(5);
  let id=epoch.reserve_eh4(&im,p)?;epoch.install_head(id,&im)?;epoch.restore_previous_head(id,&im)?;
  epoch.discard_guard(id,&im,-72,1)?;epoch.restore_saved(id,&im,-68,7)?;
  epoch.restore_saved(id,&im,-64,6)?;epoch.restore_saved(id,&im,-60,3)?;epoch.restore_saved(id,&im,-4,5)?;
  let receipt=epoch.return_to_caller(id,&im,0xe010)?;assert_eq!(receipt.saved[5],None);Ok(())
 }).unwrap();
 // The distinct C++ representation does not gain EH4 validation by using
 // the same lifecycle storage or handler address.
 let(m,mut r,main,mut permit)=fixture();
 assert!(r.with_normal_calls(&m,&mut permit,&main,|epoch|{
  let im=image(0xe000,epoch.head()?);let id=epoch.reserve_eh4(&im,plan())?;
  epoch.registry.normal_epoch.as_mut().unwrap().frames.last_mut().unwrap().kind=NormalRegistrationKind::Cxx{metadata:0x19930522};
  epoch.install_head(id,&im)
 }).is_err());
}
fn argument_extent(){
 // Independent adversarial case: the protected return is below a module,
 // but RET 12 would consume three argument words inside that module.
 for module_start in [0x9000,0x9004,0x9008]{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(module_start,0x9100)]);let before=r.head;
  let result=r.with_normal_calls(&m,&mut permit,&main,|epoch|{
   let im=image(0x8ffc,epoch.head()?);let id=epoch.reserve_eh4(&im,plan())?;
   epoch.install_head(id,&im)?;complete(epoch,id,&im)
  });assert!(result.is_err());assert_eq!(r.head,before);assert!(r.normal_epoch.as_ref().unwrap().frames.is_empty());
 }
 // A non-overlapping module above the half-open consumed interval is fine.
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x900c,0x9100)]);
 r.with_normal_calls(&m,&mut permit,&main,|epoch|{
  let im=image(0x8ffc,epoch.head()?);let id=epoch.reserve_eh4(&im,plan())?;epoch.install_head(id,&im)?;complete(epoch,id,&im)
 }).unwrap();
}
fn returned_query(){
 let(mut m,mut r,_,permit)=fixture();let id=permit.binding.frame;let owner=m.owner();let event=m.event;
 assert!(r.validate_returned_event(&m,owner,event,id).is_err());
 // This is the query's independently labelled completed-return precondition;
 // original Main completion tests exercise the actual receipt issuer.
 m.phase=Phase::Returned;m.frames[0].live=false;r.frames[0].live=false;r.frames[0].linked=false;r.head=r.frames[0].previous;
 r.validate_returned_event(&m,owner,event,id).unwrap();
 assert!(r.validate_returned_event(&m,owner+1,event,id).is_err());
 assert!(r.validate_returned_event(&m,owner,event+1,id).is_err());
 assert!(r.validate_returned_event(&m,owner,event,FrameId{generation:id.generation+1,..id}).is_err());
 m.frames[0].live=true;assert!(r.validate_returned_event(&m,owner,event,id).is_err());m.frames[0].live=false;
 r.frames[0].linked=true;assert!(r.validate_returned_event(&m,owner,event,id).is_err());r.frames[0].linked=false;
 r.head=RegistryHead::Owned(r.frames[0].id);assert!(r.validate_returned_event(&m,owner,event,id).is_err());
}
fn main(){match std::env::args().nth(1).unwrap().as_str(){"nested"=>nested(),"authority"=>authority(),"bounds"=>bounds(),"order"=>order(),"failure"=>failure(),"exception_boundary"=>exception_boundary(),"observed_epilog"=>observed_epilog(),"argument_extent"=>argument_extent(),"returned_query"=>returned_query(),_=>panic!("case")}}
"#;

fn run(case: &str) {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    let binary = BINARY.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("w2l-normal-epoch-{}", std::process::id()));
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
        let binary = dir.join(if cfg!(windows) { "epoch.exe" } else { "epoch" });
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
fn nested_original_normal_epilogs_preserve_selected_context_and_return_authority() {
    run("nested");
}
#[test]
fn active_event_foreign_identity_and_replayed_permit_reject_before_calls() {
    run("authority");
}
#[test]
fn allocated_frame_full_word_bounds_aliases_and_protected_plans_reject() {
    run("bounds");
}
#[test]
fn actual_fs_saved_slots_and_protected_return_require_ordered_lifo_effects() {
    run("order");
}
#[test]
fn failed_or_abandoned_original_call_keeps_partial_effects_and_blocks_return() {
    run("failure");
}
#[test]
fn old_unwind_and_borrowed_dispatcher_cannot_run_in_normal_epoch() {
    run("exception_boundary");
}
#[test]
fn observed_file_wrapper_epilog_does_not_invent_cookie_call_or_cpp_authority() {
    run("observed_epilog");
}
#[test]
fn complete_ret_argument_extent_cannot_cross_module_storage() {
    run("argument_extent");
}
#[test]
fn returned_event_query_requires_exact_retired_selected_state() {
    run("returned_query");
}
