//! Independent emitted-code review of source-call state. These executions do
//! not observe Windows exception delivery or identify an OS-captured CONTEXT.
use super::{frame_proof, raise_call};
use std::collections::BTreeSet;

const ENTRY: u32 = 0x18000;
const COOKIE: u32 = 0x48000;
const TABLE: u32 = 0x49000;
const HANDLER: u32 = 0x25000;
const IAT: u32 = 0x4a000;
const EVENT: u32 = 0xe0421735;

fn independent_frame(allocation: u8) -> frame_proof::ProvenFrame {
    let mut code = vec![0x55, 0x8b, 0xec, 0x6a, 0xfe, 0x68];
    code.extend(TABLE.to_le_bytes());
    code.push(0x68);
    code.extend(HANDLER.to_le_bytes());
    code.extend([
        0x64, 0xa1, 0, 0, 0, 0, 0x50, 0x83, 0xec, allocation, 0x53, 0x56, 0x57, 0xa1,
    ]);
    code.extend(COOKIE.to_le_bytes());
    code.extend([
        0x31, 0x45, 0xf8, 0x33, 0xc5, 0x50, 0x8d, 0x45, 0xf0, 0x64, 0xa3, 0, 0, 0, 0, 0xc7, 0x45,
        0xfc, 0, 0, 0, 0, 0xbb,
    ]);
    // Original live EBX becomes known; its previously saved value stays unknown.
    code.extend(0xa5b6_c7d8u32.to_le_bytes());
    for argument in [0, 0, 0, EVENT] {
        code.push(0x68);
        code.extend(argument.to_le_bytes());
    }
    frame_proof::prove_frame(
        &code,
        ENTRY,
        COOKIE,
        &BTreeSet::from([TABLE]),
        &BTreeSet::from([HANDLER]),
    )
    .unwrap()
}

fn compile_and_run(source: &str, suffix: &str) {
    let directory =
        std::env::temp_dir().join(format!("w2l-raised-review-{}-{suffix}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let rust = directory.join("check.rs");
    let executable = directory.join(if cfg!(windows) { "check.exe" } else { "check" });
    std::fs::write(&rust, source).unwrap();
    let built = std::process::Command::new("rustc")
        .args(["--edition=2021", "-Awarnings"])
        .arg(&rust)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let ran = std::process::Command::new(&executable).output().unwrap();
    assert!(
        ran.status.success(),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn emitted_source_frame_preserves_unknown_saves_and_separate_call_return_extent() {
    let mut source = String::from(frame_proof::EMITTED_TYPES);
    let mut checks = String::new();
    for allocation in [32u8, 40] {
        let frame = independent_frame(allocation);
        let mut call = vec![0xff, 0x15];
        call.extend(IAT.to_le_bytes());
        let proof = raise_call::prove_call(&frame, &call, frame.end(), IAT, EVENT).unwrap();
        assert_eq!(
            proof.registers()[3],
            frame_proof::GuestRegister::Scalar(0xa5b6_c7d8)
        );
        for register in [1usize, 2, 6, 7] {
            assert_eq!(
                proof.registers()[register],
                frame_proof::GuestRegister::EntryRegister(register as u8)
            );
            assert_eq!(proof.registers()[register].known_bits(), (0, 0));
        }
        // Literal x86 PUSH accounting, not another production-derived getter.
        let caller_depth = 52 + u32::from(allocation);
        let callee_depth = caller_depth + 4;
        assert_eq!(proof.caller_sp_offset(), -(caller_depth as i32));
        assert_eq!(proof.call_stack_extent(), callee_depth);
        source.push_str(&format!("fn init_{allocation}(entry_sp:u32,cookie:u32,saved:[Option<u32>;8])->Result<FrameImage<()>,&'static str>{{let predecessor=();{}}}\n",frame.initializer_body()));
        checks.push_str(&format!(
            r#"
 let image=init_{allocation}(0x9000,0x12345678,[None;8]).unwrap();
 assert_eq!(image.esp,0x9000-{caller_depth});
 assert_eq!(image.words.get(&-4),Some(&FrameWord::Saved(5,None)));
 for (offset,register) in [(-{ebx},3),(-{esi},6),(-{edi},7)]{{
  assert_eq!(image.words.get(&offset),Some(&FrameWord::Saved(register,None)));
 }}
 assert!(!image.words.contains_key(&-{callee_depth}));
 let mut saved=[None;8];saved[3]=Some(0x10203040);
 let image=init_{allocation}(0x9000,0x12345678,saved).unwrap();
 assert_eq!(image.words.get(&-{ebx}),Some(&FrameWord::Saved(3,Some(0x10203040))));
 assert!(init_{allocation}({caller_depth},0,[None;8]).is_err());
 assert!(init_{allocation}(0x9001,0,[None;8]).is_err());
"#,
            ebx = 24 + u32::from(allocation),
            esi = 28 + u32::from(allocation),
            edi = 32 + u32::from(allocation)
        ));
    }
    source.push_str(&format!("fn main(){{{checks}}}"));
    compile_and_run(&source, "call-snapshot");
}

fn native_event_fixture() -> String {
    let frame = independent_frame(32);
    let mut call = vec![0xff, 0x15];
    call.extend(IAT.to_le_bytes());
    let site = raise_call::prove_call(&frame, &call, frame.end(), IAT, EVENT).unwrap();
    format!(
        r#"
{runtime}
{frames}
{registry}
{event}
fn initialize(entry_sp:u32,cookie:u32,predecessor:RegistryHead)->Result<FrameImage<RegistryHead>,&'static str>{{
 let saved=[None;8];{initializer}
}}
fn fixture()->(Machine,ThreadRegistry,FrameImage<RegistryHead>,RegistrationId){{
 let machine=Machine::new_dispatch_known(vec![FrameSpec{{scopes:vec![]}}],0,[None;10],Some(17)).unwrap();
 let mut registry=ThreadRegistry::new(machine.owner(),0x1000,0x10000,&[(0x10000,0x50000)],{cookie}).unwrap();
 let image=initialize(0xf000,0x12345678,registry.head().unwrap()).unwrap();
 let id=registry.install_frame(machine.binding(0).unwrap(),&image).unwrap();
 (machine,registry,image,id)
}}
fn site()->RaiseSite{{RaiseSite{{instruction:{pc},return_ip:{next},iat:{iat},code:{code},caller_sp_offset:{caller},callee_sp_offset:{callee}}}}}
"#,
        runtime = include_str!("linker/unwind_runtime.rs").replace("//!", "//"),
        frames = frame_proof::EMITTED_TYPES,
        registry = super::thread_registry::EMITTED_TYPES,
        event = super::exception_event::EMITTED_TYPES,
        initializer = frame.initializer_body(),
        cookie = COOKIE,
        pc = site.call_pc(),
        next = site.next_pc(),
        iat = IAT,
        code = EVENT,
        caller = site.caller_sp_offset(),
        callee = site.callee_sp_offset(),
    )
}

#[test]
fn original_emitted_frame_event_preserves_unknowns_and_rejects_call_scratch_aliases() {
    let source = native_event_fixture()
        + r#"
fn main(){
 let(mut machine,registry,image,_)=fixture();let binding=machine.binding(0).unwrap();
 let original_words=image.words.clone();let original_head=registry.head().unwrap();
 let(foreign,foreign_registry,_,_)=fixture();
 assert!(OwnedExceptionEvent::from_raise(&mut machine,&foreign_registry,binding,&image,site(),64).is_err());
 assert!(OwnedExceptionEvent::from_raise(&mut machine,&registry,foreign.binding(0).unwrap(),&image,site(),64).is_err());
 assert!(!machine.event_issued);assert_eq!(image.words,original_words);assert_eq!(registry.head().unwrap(),original_head);
 let event=OwnedExceptionEvent::from_raise(&mut machine,&registry,binding,&image,site(),64).unwrap();
 // Original caller ESP and protected CALL word are distinct from OS capture.
 assert_eq!((event.guest.caller_sp,event.guest.callee_sp),(0xefac,0xefa8));
 assert_eq!((event.scratch_low,event.scratch_high,event.handler_sp()),(0xef64,0xefa8,0xefa4));
 assert_eq!(machine.owned_context,Some([None;10]));
 let alias=event.captured_context().clone();assert!(alias.preflight(machine.owner()).is_ok());
 assert!(alias.preflight(foreign.owner()).is_err());assert!(alias.captured_at_most_base(foreign.owner()).is_err());
 assert!(alias.preflight(machine.owner()).is_ok());
 assert!(OwnedExceptionEvent::from_raise(&mut machine,&registry,binding,&image,site(),64).is_err());
 drop(event);assert!(alias.preflight(machine.owner()).is_err());assert!(alias.captured_below_limit(machine.owner()).is_err());
 assert!(OwnedExceptionEvent::from_raise(&mut machine,&registry,binding,&image,site(),64).is_err());

 let(mut machine,mut registry,image,_)=fixture();let binding=machine.binding(0).unwrap();
 registry.bound.push((0xef80,0xef90));
 let event=OwnedExceptionEvent::from_raise(&mut machine,&registry,binding,&image,site(),64).unwrap();
 assert_eq!((event.scratch_low,event.scratch_high),(0xef3c,0xef80));
 let(mut machine,mut registry,image,_)=fixture();let binding=machine.binding(0).unwrap();
 registry.bound.push((0xefa8,0xefac));
 assert!(OwnedExceptionEvent::from_raise(&mut machine,&registry,binding,&image,site(),64).is_err());assert!(!machine.event_issued);
 for(limit,accepted)in[(0xef64,true),(0xef68,false)]{
  let(mut machine,mut registry,image,_)=fixture();let binding=machine.binding(0).unwrap();registry.limit=limit;
  assert_eq!(OwnedExceptionEvent::from_raise(&mut machine,&registry,binding,&image,site(),64).is_ok(),accepted);
  assert_eq!(machine.event_issued,accepted);
 }
 // A caller-known value is not evidence about an API-captured register.
 let(mut machine,registry,image,_)=fixture();let binding=machine.binding(0).unwrap();
 machine.owned_context=Some([Some(0);10]);
 assert!(OwnedExceptionEvent::from_raise(&mut machine,&registry,binding,&image,site(),64).is_err());assert!(!machine.event_issued);
}
"#;
    compile_and_run(&source, "event-owned-bounds");
}

#[test]
fn context_aliases_expire_before_original_restoration_and_cannot_finish_foreign_event() {
    let source = native_event_fixture()
        + r#"
fn main(){
 let(mut machine,mut registry,image,id)=fixture();let binding=machine.binding(0).unwrap();
 let mut event=OwnedExceptionEvent::from_raise(&mut machine,&registry,binding,&image,site(),64).unwrap();
 let alias=event.captured_context().clone();let token=event.identity();
 assert!(event.finish(&machine,&registry).is_err());assert!(event.begin_restoration(&machine,&registry).is_err());
 assert!(alias.preflight(machine.owner()).is_ok());
 registry.contain(id).unwrap();machine.finish_selected_dispatch(binding).unwrap();
 event.begin_restoration(&machine,&registry).unwrap();
 assert!(alias.preflight(machine.owner()).is_err());assert!(alias.captured_at_most_base(machine.owner()).is_err());
 assert!(event.begin_restoration(&machine,&registry).is_err());assert!(event.finish(&machine,&registry).is_err());
 // This independently declared test restoration is a component operation,
 // not claimed execution of a Windows landing instruction sequence.
 let restored=[Some(19),None,None,None,Some(image.esp),Some(image.ebp),None,None,Some(0x26000),None];
 machine.restore_owned(0x26000,|lease,current|{assert_eq!(current,[None;10]);lease.bind_storage(binding)?;Ok(restored)}).unwrap();
 let(foreign,foreign_registry,_,_)=fixture();
 assert!(event.finish(&foreign,&foreign_registry).is_err());
 assert!(event.finish(&machine,&foreign_registry).is_err());
 event.finish(&machine,&registry).unwrap();assert_eq!(event.identity(),token);
 assert!(event.finish(&machine,&registry).is_err());assert!(alias.preflight(machine.owner()).is_err());
 assert_eq!(machine.owned_context,Some(restored));

 let(mut machine,mut registry,image,id)=fixture();let binding=machine.binding(0).unwrap();
 let mut event=OwnedExceptionEvent::from_raise(&mut machine,&registry,binding,&image,site(),64).unwrap();
 let alias=event.captured_context().clone();registry.contain(id).unwrap();machine.finish_selected_dispatch(binding).unwrap();event.begin_restoration(&machine,&registry).unwrap();
 assert!(machine.restore_owned(0x26000,|lease,_|{lease.bind_storage(binding)?;Err(Error::Restoration)}).is_err());
 assert!(event.finish(&machine,&registry).is_err());assert!(alias.preflight(machine.owner()).is_err());drop(event);assert!(alias.preflight(machine.owner()).is_err());
}
"#;
    compile_and_run(&source, "event-context-lifetime");
}
