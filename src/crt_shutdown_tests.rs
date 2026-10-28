//! Component composition tests: original Main completion emits the receipt;
//! original exit callback traversal and process termination are still unbound.
#[path = "crt_stream_runtime.rs"]
mod runtime_support;

use std::path::PathBuf;
use std::sync::OnceLock;

const CASES: &str = r#"
fn complete(machine:&mut Machine,registry:&mut ThreadRegistry,image:&mut FrameImage<RegistryHead>,event:&OwnedExceptionEvent)->NormalReturnReceipt{
 let owner=machine.owner();let selected=machine.binding(0).unwrap();
 let mut session=NormalReturnSession::new(machine,registry,selected,image,event,plan()).unwrap();
 let outcome=execute(image,owner,0x3210abef,&mut session,&mut vec![]).unwrap();
 session.finish(&outcome).unwrap()
}
fn lifecycle(){
 for value in [0,21,u32::MAX]{
  let(mut machine,mut registry,mut image,event)=fixture(value);
  let mut runtime=CrtStreamRuntime::new(machine.owner(),registry.identity.instance,0x5000,32768).unwrap();
  let binding=CrtReturnBinding::bind(&runtime,&machine,&registry,&event).unwrap();
  let receipt=complete(&mut machine,&mut registry,&mut image,&event);
  let shutdown=binding.begin(&mut runtime,&machine,&registry,receipt).unwrap();
  assert_eq!(machine.owned_context.unwrap()[0],Some(value));
  // The bridge performs no output, buffering, or instruction-driven teardown.
  assert!(runtime.end_shutdown(shutdown).is_err());
  runtime.destroy_lock_shutdown(shutdown,runtime.file()).unwrap();runtime.end_shutdown(shutdown).unwrap();
  assert!(runtime.end_shutdown(shutdown).is_err());
  assert_eq!(machine.owned_context.unwrap()[0],Some(value));
 }
}
fn wrong_arena(){
 let(mut machine,mut registry,mut image,event)=fixture(21);
 let runtime=CrtStreamRuntime::new(machine.owner(),registry.identity.instance,0x5000,32768).unwrap();
 let mut same_labels=CrtStreamRuntime::new(machine.owner(),registry.identity.instance,0x5000,32768).unwrap();
 assert_ne!(runtime.anchor,same_labels.anchor);
 let binding=CrtReturnBinding::bind(&runtime,&machine,&registry,&event).unwrap();
 let receipt=complete(&mut machine,&mut registry,&mut image,&event);
 assert!(binding.begin(&mut same_labels,&machine,&registry,receipt).is_err());
 assert!(same_labels.shutdown.is_none());assert!(!same_labels.closed);
}
fn wrong_completion(){
 for case in 0..18 {
  let(mut machine,mut registry,mut image,event)=fixture(21);
  let mut runtime=CrtStreamRuntime::new(machine.owner(),registry.identity.instance,0x5000,32768).unwrap();
  let binding=CrtReturnBinding::bind(&runtime,&machine,&registry,&event).unwrap();
  let mut receipt=complete(&mut machine,&mut registry,&mut image,&event);
  match case {
   0=>receipt.event+=1,1=>receipt.frame.generation+=1,2=>receipt.caller_sp+=4,3=>receipt.value=22,
   4=>machine.phase=Phase::Done,5=>registry.frames[0].live=true,
   6=>registry.frames[0].linked=true,7=>registry.head=RegistryHead::Owned(registry.frames[0].id),
   8..=17=>{let index=case-8;let context=machine.owned_context.as_mut().unwrap();context[index]=Some(context[index].unwrap_or(17).wrapping_add(1));},_=>unreachable!(),
  }
  assert!(binding.begin(&mut runtime,&machine,&registry,receipt).is_err());
  assert!(runtime.shutdown.is_none());assert!(!runtime.closed);
 }
}
fn phase_and_leases(){
 for case in 0..5 {
  let(mut machine,mut registry,mut image,event)=fixture(21);
  let mut runtime=CrtStreamRuntime::new(machine.owner(),registry.identity.instance,0x5000,32768).unwrap();
  if case==0 {runtime.thread+=1;assert!(CrtReturnBinding::bind(&runtime,&machine,&registry,&event).is_err());continue;}
  if case==1 {let lock=runtime.lock(runtime.thread).unwrap();assert!(CrtReturnBinding::bind(&runtime,&machine,&registry,&event).is_err());runtime.unlock(lock).unwrap();continue;}
  let binding=CrtReturnBinding::bind(&runtime,&machine,&registry,&event).unwrap();
  let receipt=complete(&mut machine,&mut registry,&mut image,&event);
  assert!(CrtReturnBinding::bind(&runtime,&machine,&registry,&event).is_err());
  match case {
   2=>{let _live=runtime.lock(runtime.thread).unwrap();},
   3=>{let file=runtime.lock(runtime.thread).unwrap();let descriptor=runtime.bind_descriptor(1,7).unwrap();runtime.unlock(file).unwrap();let _live=runtime.lock_descriptor(runtime.thread,descriptor).unwrap();},
   4=>{runtime.initialization=Some(23);},_=>unreachable!(),
  }
  assert!(binding.begin(&mut runtime,&machine,&registry,receipt).is_err());assert!(runtime.shutdown.is_none());
 }
}
fn main(){match std::env::args().nth(1).unwrap().as_str(){"lifecycle"=>lifecycle(),"arena"=>wrong_arena(),"completion"=>wrong_completion(),"phase"=>phase_and_leases(),_=>panic!("case")}}
"#;

fn run(case: &str) {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    let binary = BINARY.get_or_init(|| {
        let proof = super::main_return_tests::original_completion();
        let fixture = super::main_return_tests::CASES
            .split("fn main(){")
            .next()
            .unwrap()
            .replace("EXECUTION_SOURCE", proof.source());
        let memory = include_str!("guest_memory.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n");
        let parts = [
            include_str!("linker/unwind_runtime.rs").replace("//!", "//"),
            super::frame_proof::EMITTED_TYPES.into(),
            super::frame_memory::EMITTED_TYPES.into(),
            super::thread_registry::EMITTED_TYPES.into(),
            super::exception_event::EMITTED_TYPES.into(),
            super::main_completion::EMITTED_TYPES.into(),
            super::main_return::EMITTED_TYPES.into(),
            runtime_support::EMITTED_TYPES.into(),
            super::crt_shutdown::EMITTED_TYPES.into(),
            fixture,
            CASES.into(),
        ];
        let source = format!(
            "#![allow(dead_code,unused_assignments,unused_mut)]\nmod guest_memory{{{memory}}}\n{}",
            parts.join("\n")
        );
        let dir = std::env::temp_dir().join(format!("w2l-crt-return-{}", std::process::id()));
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
    let output = std::process::Command::new(binary)
        .arg(case)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn original_main_receipt_authorizes_only_bound_local_teardown() {
    run("lifecycle");
}
#[test]
fn same_numeric_labels_do_not_authorize_another_crt_arena() {
    run("arena");
}
#[test]
fn altered_receipt_or_unretired_state_reject_before_teardown() {
    run("completion");
}
#[test]
fn unfinished_return_and_live_leases_cannot_grant_shutdown() {
    run("phase");
}
