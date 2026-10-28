//! Native execution of the authored helper; no enclosing wrapper admission.
use super::{PrologProof, Region};
use crate::{crt_stream_cpu, crt_stream_runtime};

#[test]
fn original_native_prolog_relocation_and_failure_boundaries() {
    let mut helpers = String::new();
    for allocation in [12, 20, 44] {
        helpers.push_str(
            &PrologProof::prove(
                Region {
                    bytes: &super::tests::bytes(),
                    origin: 0x401e60,
                },
                allocation,
                0x41b400,
                0x41c000,
                0x402210,
            )
            .unwrap()
            .emit(&format!("prolog_{allocation}"))
            .unwrap(),
        );
    }
    let memory = include_str!("guest_memory.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap()
        .lines()
        .filter(|line| !line.starts_with("//!"))
        .collect::<Vec<_>>()
        .join("\n");
    let body = r#"
fn setup(allocation:u32)->(CrtStreamRuntime,CrtCpu,CrtThreadHead){
 let mut rt=CrtStreamRuntime::new(13,17,0x8000,32768).unwrap();
 let stack=rt.map_region(0x9000,4096,CrtRegionKind::Stack,None).unwrap();let caller=rt.offset(stack,3072).unwrap();
 let module=rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();
 assert_eq!(module.address(),0x41c000);rt.store(caller,32,CrtValue::ProtectedReturn(71)).unwrap();
 let mut cpu=CrtCpu::new(caller,71).unwrap();
 cpu.r[3]=CrtValue::Scalar{bits:0xabcdef01,known:0xffff0000};
 cpu.push(&mut rt,CrtValue::scalar(allocation)).unwrap();cpu.push(&mut rt,CrtValue::scalar(0x41b400)).unwrap();
 cpu.push(&mut rt,CrtValue::ProtectedReturn(99)).unwrap();
 let head=rt.thread_head(7,11,[0,0,0]).unwrap();(rt,cpu,head)
}
type Helper=fn(&mut CrtStreamRuntime,&mut CrtCpu,u64,CrtThreadHead,fn(&mut CrtStreamRuntime,&CrtCpu,CrtPointer,CrtThreadHead)->Result<(),&'static str>)->Result<(),&'static str>;
fn install(rt:&mut CrtStreamRuntime,_cpu:&CrtCpu,record:CrtPointer,head:CrtThreadHead)->Result<(),&'static str>{
 assert_eq!(rt.load(record,32)?,CrtValue::ThreadHead(head));
 assert_eq!(rt.load(rt.offset(record,4)?,32)?.known_scalar()?,0x402210);Ok(())
}
for (allocation,run) in [(12,prolog_12 as Helper),(20,prolog_20 as Helper),(44,prolog_44 as Helper)]{
 let(mut rt,mut cpu,head)=setup(allocation);let entry=cpu.entry;let return_id=cpu.return_id;
 run(&mut rt,&mut cpu,99,head,install).unwrap();
 assert_eq!(cpu.entry,entry);assert_eq!(cpu.return_id,return_id);assert!(!cpu.returned);
 assert_eq!(CrtCpu::pointer(cpu.r[4]).unwrap().address(),0x9c00-36-allocation);
 assert_eq!(CrtCpu::pointer(cpu.r[5]).unwrap().address(),0x9bfc);
 assert_eq!(rt.load(rt.resolve_absolute(0x9bfc,CrtRegionKind::Stack).unwrap(),32).unwrap(),CrtValue::OpaqueSaved(5));
 assert!(!rt.tags.values().any(|v|*v==CrtValue::ProtectedReturn(99)));
 assert_eq!(rt.load(CrtCpu::pointer(entry[4]).unwrap(),32).unwrap(),CrtValue::ProtectedReturn(71));
 assert!(cpu.finish(&mut rt).is_err());
}
// Entry rejection leaves registers and the unique original helper token intact.
for mode in 0..4{
 let(mut rt,mut cpu,mut head)=setup(12);let snapshot=cpu.r;
 if mode==1 {let p=rt.offset(CrtCpu::pointer(cpu.r[4]).unwrap(),-4).unwrap();rt.store(p,32,CrtValue::ProtectedReturn(301)).unwrap();}
 if mode==2 {head.thread+=1;}
 if mode==3 {let p=rt.offset(CrtCpu::pointer(cpu.r[4]).unwrap(),-4).unwrap();rt.store(p,32,CrtValue::ProtectedReturn(99)).unwrap();}
 assert!(prolog_12(&mut rt,&mut cpu,if mode==0{98}else{99},head,install).is_err());
 assert_eq!(cpu.r,snapshot);assert_eq!(rt.load(CrtCpu::pointer(cpu.r[4]).unwrap(),32).unwrap(),CrtValue::ProtectedReturn(99));
}
// Callback failure retains original reached memory and the relocated token.
let(mut rt,mut cpu,head)=setup(12);let entry=cpu.entry;let mut installed_effect=None;
let observable=rt.map_region(0xb000,4,CrtRegionKind::Result,Some(&[0;4])).unwrap();
assert_eq!(prolog_12(&mut rt,&mut cpu,99,head,|rt,_cpu,record,head|{installed_effect=Some((record,head));rt.store(observable,32,CrtValue::scalar(93))?;Err("install failure")}),Err("install failure"));
assert_eq!(installed_effect,Some((rt.resolve_absolute(0x9bec,CrtRegionKind::Stack).unwrap(),head)));
assert_eq!(rt.load(observable,32).unwrap().known_scalar().unwrap(),93);
assert_eq!(cpu.entry,entry);assert_eq!(CrtCpu::pointer(cpu.r[4]).unwrap().address(),0x9c00-52);
assert_eq!(rt.load(CrtCpu::pointer(cpu.r[4]).unwrap(),32).unwrap(),CrtValue::ProtectedReturn(99));
assert_eq!(rt.load(rt.resolve_absolute(0x9bf4,CrtRegionKind::Stack).unwrap(),32).unwrap().known_scalar().unwrap(),0x41b400^0x12345678);
// A callback cannot substitute a record and still obtain helper completion.
for field in [4,8,-28]{
 let(mut rt,mut cpu,head)=setup(12);
 assert!(prolog_12(&mut rt,&mut cpu,99,head,|rt,_cpu,record,_|{rt.store(rt.offset(record,field)?,32,CrtValue::scalar(0))?;Ok(())}).is_err());
 assert_eq!(rt.load(CrtCpu::pointer(cpu.r[4]).unwrap(),32).unwrap(),CrtValue::ProtectedReturn(99));
}
// The ordinary ABI rejects this helper's changed ESP/EBP even if its effects ran.
struct Backend;impl CrtBackend for Backend{fn write_once(&mut self,_:CrtDescriptorId,_:&[u8])->Result<CrtWriteResult,&'static str>{panic!("no IO")}}
let(mut rt,mut cpu,head)=setup(12);cpu.pop(&mut rt).unwrap();let lease=rt.lock(17).unwrap();
assert!(cpu.call(&mut rt,lease,&mut Backend,0x1005,|rt,child,_,_|{
 let mut outer=CrtCpu::new(CrtCpu::pointer(child.entry[4]).and_then(|p|rt.offset(p,12))?,71)?;
 outer.r=child.r;prolog_12(rt,&mut outer,child.return_id,head,install)?;
 child.r=outer.r;child.finish(rt)
}).is_err());
"#;
    let source = format!("#![allow(dead_code)]\nmod guest_memory{{{memory}}}\n{}\n{}\n{helpers}\nfn main(){{{body}}}",crt_stream_runtime::EMITTED_TYPES,crt_stream_cpu::EMITTED_TYPES);
    let dir = std::env::temp_dir().join(format!("w2l-eh4-native-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("run.rs");
    let binary = dir.join(if cfg!(windows) { "run.exe" } else { "run" });
    std::fs::write(&file, source).unwrap();
    let built = std::process::Command::new("rustc")
        .args(["--edition=2021", "-Awarnings"])
        .arg(&file)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let ran = std::process::Command::new(&binary).output().unwrap();
    assert!(
        ran.status.success(),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    std::fs::remove_dir_all(dir).unwrap();
}
