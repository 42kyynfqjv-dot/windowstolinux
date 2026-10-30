//! Independent native normal-return lifecycle checks. These exercise the
//! production completion emitter and event/registry adapters, not Windows CRT.
use super::main_completion::{self, Bindings, Layout, Word};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::OnceLock;

pub(super) fn original_completion() -> main_completion::ProvenCompletion {
    let origin = 0x411000u32;
    let mut code = vec![0xff, 0x75, 0xd0, 0x68]; // PUSH [EBP-48]; PUSH format
    code.extend(0x415000u32.to_le_bytes());
    let call = |code: &mut Vec<u8>, target: u32| {
        let next = origin + code.len() as u32 + 5;
        code.push(0xe8);
        code.extend(target.wrapping_sub(next).to_le_bytes());
    };
    call(&mut code, 0x412000);
    code.extend([
        0x83, 0xc4, 8, 0x8b, 0x45, 0xd0, 0x8b, 0x4d, 0xf0, 0x64, 0x89, 0x0d, 0, 0, 0, 0, 0x59,
        0x5f, 0x5e, 0x5b, 0x8b, 0x4d, 0xe4, 0x33, 0xcd,
    ]);
    call(&mut code, 0x413000);
    code.extend([0x8b, 0xe5, 0x5d, 0xc3]);
    main_completion::prove(
        &code,
        origin,
        &Layout {
            words: BTreeMap::from([(-48, Word::Scalar)]),
            esp: -64,
            saved: BTreeMap::from([(-60, 7), (-56, 6), (-52, 3), (0, 5)]),
            guards: BTreeSet::from([-64, -28]),
            predecessor: -16,
        },
        &Bindings {
            module_base: 0x400000,
            module_size: 0x20000,
            globals: BTreeMap::new(),
            printf: 0x412000,
            format: 0x415000,
            security_check: 0x413000,
        },
    )
    .unwrap()
}

pub(super) const CASES: &str = r#"
fn fixture(value:u32)->(Machine,ThreadRegistry,FrameImage<RegistryHead>,OwnedExceptionEvent){
 let mut machine=Machine::new_dispatch_known(vec![FrameSpec{scopes:vec![]}],0,[None;10],Some(23)).unwrap();
 let owner=machine.owner();let binding=machine.binding(0).unwrap();
 let mut registry=ThreadRegistry::new(owner,0x1000,0xa000,&[(0x400000,0x420000)],0x41c000).unwrap();
 let previous=registry.head().unwrap();let ebp=0x9000;let entry_sp=0x9004;let cookie=0x3210abef;
 let mut words=std::collections::BTreeMap::new();
 for(offset,word)in[
  (-80,FrameWord::Scalar(0xe0421735)),(-76,FrameWord::Scalar(0)),(-72,FrameWord::Scalar(0)),(-68,FrameWord::Scalar(0)),
  (-64,FrameWord::Guard{frame:ebp,cookie,bits:ebp^cookie}),(-60,FrameWord::Saved(7,None)),(-56,FrameWord::Saved(6,Some(0x10203040))),(-52,FrameWord::Saved(3,None)),
  (-48,FrameWord::Scalar(value)),(-28,FrameWord::Guard{frame:ebp,cookie,bits:ebp^cookie}),
  (-16,FrameWord::Borrowed(previous)),(-12,FrameWord::Scalar(0x411800)),(-8,FrameWord::EncodedScope{scope:0x416000,cookie,bits:0x416000^cookie}),(-4,FrameWord::Scalar(0)),
  (0,FrameWord::Saved(5,None)),(4,FrameWord::Return)]{words.insert(offset-4,word);}
 let mut image=FrameImage{words,entry_sp,ebp,esp:ebp-80,record:ebp-16,scope_va:0x416000,handler_va:0x411800,try_level:0};
 let id=registry.install_frame(binding,&image).unwrap();
 let mut event=OwnedExceptionEvent::from_raise(&mut machine,&registry,binding,&image,RaiseSite{instruction:0x411900,return_ip:0x411906,iat:0x415008,code:0xe0421735,caller_sp_offset:-84,callee_sp_offset:-88},64).unwrap();
 registry.contain(id).unwrap();image.try_level=-2;image.words.insert(-8,FrameWord::Scalar((-2i32)as u32));
 machine.finish_selected_dispatch(binding).unwrap();event.begin_restoration(&machine,&registry).unwrap();
 // A separately labelled lifecycle precondition, not a Windows landing claim.
 image.esp=ebp-64;machine.restore_owned(0x411000,|lease,current|{assert_eq!(current,[None;10]);lease.bind_storage(binding)?;Ok([Some(77),None,None,None,Some(ebp-64),Some(ebp),None,None,Some(0x411000),None])}).unwrap();
 event.finish(&machine,&registry).unwrap();(machine,registry,image,event)
}
fn plan()->NormalReturnPlan{NormalReturnPlan{pops:vec![(-64,1,true),(-60,7,false),(-56,6,false),(-52,3,false),(0,5,false)],cookie_offset:-28,security_target:0x413000,return_offset:4}}
fn execute(image:&mut FrameImage<RegistryHead>,owner:u64,cookie:u32,session:&mut NormalReturnSession<'_>,trace:&mut Vec<String>)->Result<CompletionOutcome<RegistryHead>,&'static str>{
 let mut memory=FrameMemory::new(image,owner,&[-48])?;let globals:&mut[u32]=&mut[];
 let mut printf=|request:PrintRequest<'_>|->Result<Option<u32>,&'static str>{assert_eq!((request.target,request.format),(0x412000,0x415000));assert_eq!(request.arguments.len(),1);trace.push(format!("print:{}",request.arguments[0]));Ok(None)};
 let mut effects=|effect:CompletionEffect<'_,RegistryHead>|->Result<(),&'static str>{
  match &effect{CompletionEffect::RestorePredecessor(_)=>{},CompletionEffect::Pop{..}=>{},CompletionEffect::Cookie{..}=>{},CompletionEffect::Return{..}=>{}}
  session.apply(effect)
 };
 EXECUTION_SOURCE
}
fn success(){for value in [0,21,u32::MAX]{
 let(mut machine,mut registry,mut image,event)=fixture(value);let owner=machine.owner();let binding=machine.binding(0).unwrap();let previous=registry.frames[0].previous;
 let outcome;
 {let mut session=NormalReturnSession::new(&mut machine,&mut registry,binding,&image,&event,plan()).unwrap();let mut log=vec![];
  outcome=execute(&mut image,owner,0x3210abef,&mut session,&mut log).unwrap();assert_eq!(log,[format!("print:{value}")]);
  assert_eq!(outcome.value,value);assert_eq!(outcome.predecessor,previous);assert_eq!(outcome.caller_sp,0x9008);
  assert_eq!(outcome.saved,[None,None,None,None,None,None,Some(0x10203040),None]);
  assert_eq!(session.phase,NormalReturnPhase::Returned);assert!(!session.machine.frames[0].live);assert!(!session.registry.frames[0].live);
  let receipt=session.finish(&outcome).unwrap();assert_eq!((receipt.value,receipt.caller_sp),(value,0x9008));assert!(session.finish(&outcome).is_err());}
 assert_eq!(registry.head,previous);assert_eq!(machine.phase,Phase::Returned);
 assert!(NormalReturnSession::new(&mut machine,&mut registry,binding,&image,&event,plan()).is_err());
}}
fn partial_failure(){
 let(mut machine,mut registry,mut image,event)=fixture(21);let owner=machine.owner();let binding=machine.binding(0).unwrap();let previous=registry.frames[0].previous;
 if let Some(FrameWord::Guard{bits,..})=image.words.get_mut(&-32){*bits^=1;}else{panic!("guard fixture");}
 {let mut session=NormalReturnSession::new(&mut machine,&mut registry,binding,&image,&event,plan()).unwrap();let mut log=vec![];
  assert!(execute(&mut image,owner,0x3210abef,&mut session,&mut log).is_err());assert_eq!(log,["print:21"]);
  assert_eq!(session.registry.head,previous);assert!(!session.registry.frames[0].linked);assert!(session.registry.frames[0].live);assert!(session.machine.frames[0].live);
  assert_eq!(session.next_pop,4);assert_eq!(session.saved[6],Some(0x10203040));assert_eq!(session.saved[3],None);assert!(session.receipt.is_none());}
 assert_eq!(registry.head,previous);assert!(registry.frames[0].live);assert_eq!(machine.phase,Phase::Blocked);assert!(registry.available().is_err());
}
fn incomplete_and_order(){for mode in 0..4{
 let(mut machine,mut registry,image,event)=fixture(3);let binding=machine.binding(0).unwrap();let previous=registry.frames[0].previous;
 {let mut session=NormalReturnSession::new(&mut machine,&mut registry,binding,&image,&event,plan()).unwrap();
  if mode!=0{session.apply(CompletionEffect::RestorePredecessor(&previous)).unwrap();}
  if mode==2{assert!(session.apply(CompletionEffect::Pop{offset:-60,register:7,saved:None,guard:false}).is_err());}
  if mode==3{assert!(session.apply(CompletionEffect::Return{offset:4,value:3,saved:[None;8],caller_sp:0x9008}).is_err());}
  assert!(session.registry.frames[0].live);assert!(session.machine.frames[0].live);assert!(session.receipt.is_none());}
 assert_eq!(machine.phase,Phase::Blocked);assert!(registry.available().is_err());assert!(registry.frames[0].live);
 assert_eq!(registry.head,if mode==0{RegistryHead::Owned(registry.frames[0].id)}else{previous});
}}
fn wrong_authority(){
 for mode in 0..7{
  let(mut machine,mut registry,mut image,mut event)=fixture(5);let(foreign,_,_,foreign_event)=fixture(9);let mut binding=machine.binding(0).unwrap();
  if mode==0{binding.owner=foreign.owner();}if mode==1{binding.frame.generation+=1;}
  if mode==2{image.words.insert(-60,FrameWord::Saved(7,None));} // ESI slot has wrong owner register.
  if mode==3{image.words.insert(0,FrameWord::Scalar(0x411000));} // Numeric code address is no protected return token.
  if mode==5{event.identity.event+=1;} // A stale event generation is not return authority.
  if mode==6{event.captured.lifetime.set(EventLifetime::Expired);}
  let result=NormalReturnSession::new(&mut machine,&mut registry,binding,&image,if mode==4{&foreign_event}else{&event},plan());
  assert!(result.is_err());drop(result);assert_eq!(machine.phase,Phase::Done);assert!(registry.frames[0].live);
 }
}
fn main(){match std::env::args().nth(1).unwrap().as_str(){"success"=>success(),"failure"=>partial_failure(),"order"=>incomplete_and_order(),"authority"=>wrong_authority(),_=>panic!("case")}}
"#;

fn run(case: &str) {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    let binary = BINARY.get_or_init(|| {
        let proof = original_completion();
        assert_eq!(
            proof.pops,
            [
                (-64, 1, true),
                (-60, 7, false),
                (-56, 6, false),
                (-52, 3, false),
                (0, 5, false)
            ]
        );
        assert_eq!(
            (
                proof.cookie_offset,
                proof.security_target,
                proof.return_offset
            ),
            (-28, 0x413000, 4)
        );
        let source = format!(
            "#![allow(dead_code,unused_assignments,unused_mut)]\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            include_str!("linker/unwind_runtime.rs").replace("//!", "//"),
            super::frame_proof::EMITTED_TYPES,
            super::frame_memory::EMITTED_TYPES,
            super::thread_registry::EMITTED_TYPES,
            super::exception_event::EMITTED_TYPES,
            main_completion::EMITTED_TYPES,
            super::main_return::EMITTED_TYPES,
            CASES.replace("EXECUTION_SOURCE", proof.source()),
        );
        let dir =
            std::env::temp_dir().join(format!("w2l-main-return-review-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let rust = dir.join("main.rs");
        let binary = dir.join(if cfg!(windows) { "check.exe" } else { "check" });
        std::fs::write(&rust, source).unwrap();
        let build = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(&rust)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            build.status.success(),
            "{}",
            String::from_utf8_lossy(&build.stderr)
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
fn original_completion_returns_only_after_saved_slots_guard_and_protected_ret() {
    run("success");
}
#[test]
fn guard_failure_keeps_reached_fs_and_pop_effects_without_retirement() {
    run("failure");
}
#[test]
fn incomplete_or_out_of_order_completion_blocks_without_retiring_storage() {
    run("order");
}
#[test]
fn wrong_owner_stale_generation_saved_identity_and_numeric_return_reject() {
    run("authority");
}
