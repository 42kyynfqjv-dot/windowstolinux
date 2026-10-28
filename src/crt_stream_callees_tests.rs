//! Independent original-helper protocol and generated-native boundary tests.
//! These exercise a committed, fault-free owned stack, not Windows stack growth.
use super::{crt_stream_callees, crt_stream_cpu, crt_stream_runtime};

fn raw(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&s[at..at + 2], 16).unwrap())
        .collect()
}
fn probe() -> Vec<u8> {
    // Unchanged authored PE at RVA146e0, ending before padding at1470b.
    raw("518d4c24042bc81bc0f7d023c88bc42500f0ffff3bc8720a8bc159948b00890424c32d001000008500ebe9")
}
fn security() -> Vec<u8> {
    // Unchanged authored PE at RVA154c; failure remains the external JMP target.
    raw("3b0d00c041007501c3e97c020000")
}
fn native(extra: &str, body: &str, name: &str) {
    let memory = include_str!("guest_memory.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap()
        .lines()
        .filter(|line| !line.starts_with("//!"))
        .collect::<Vec<_>>()
        .join("\n");
    let source = format!(
        "#![allow(dead_code)]\nmod guest_memory{{{memory}}}\n{}\n{}\n{extra}\nfn main(){{{body}}}",
        crt_stream_runtime::EMITTED_TYPES,
        crt_stream_cpu::EMITTED_TYPES
    );
    let dir = std::env::temp_dir().join(format!(
        "w2l-crt-original-callees-{}-{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("run.rs");
    let binary = dir.join(if cfg!(windows) { "run.exe" } else { "run" });
    std::fs::write(&file, source).unwrap();
    let built = std::process::Command::new("rustc")
        .args(["--edition=2021"])
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
    let result = std::process::Command::new(&binary).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn original_helpers_require_32_bit_returns_and_complete_original_control_edges() {
    let p = probe();
    let s = security();
    let valid_probe = crt_stream_callees::prove_stack_probe(&p, 0x4146e0).unwrap();
    let valid_guard = crt_stream_callees::prove_security(&s, 0x40154c).unwrap();
    assert_eq!(valid_probe.page_bytes(), 4096);
    assert_eq!(valid_guard.cookie(), 0x41c000);
    assert_eq!(valid_guard.failure_target(), 0x4017d6);
    let mut short_return = s.clone();
    short_return.insert(8, 0x66);
    short_return[7] = 2; // Keep JNE targeting the actual failure JMP.
    assert!(crt_stream_callees::prove_security(&short_return, 0x40154c).is_err());
    let mut short_return = p.clone();
    short_return.insert(33, 0x66);
    short_return[23] = 11; // Preserve JB's decoded target after inserted prefix.
    short_return[43] = 0xe8; // Preserve the loop's original CMP target as well.
    assert!(crt_stream_callees::prove_stack_probe(&short_return, 0x4146e0).is_err());
}

#[test]
fn generated_probe_handles_page_edges_opaque_ecx_and_exact_committed_top() {
    let p = crt_stream_callees::prove_stack_probe(&probe(), 0x4146e0).unwrap();
    let extra = format!(
        "fn run(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<(),&'static str>{{{} Ok(())}}",
        p.call_source(0x40dc35)
    );
    native(
        &extra,
        r#"
for before in [0x28000,0x28004,0x28ffc] {for allocation in [4,8,4092,4096,4100,65536] {
 let mut rt=CrtStreamRuntime::new(7,9,0x4000,262144).unwrap();
 let stack=rt.map_region(0x10000,0x20000,CrtRegionKind::Stack,None).unwrap();
 let sp=rt.offset(stack,i64::from(before)-0x10000).unwrap();let mut cpu=CrtCpu::new(sp,17).unwrap();
 cpu.r[0]=CrtValue::scalar(allocation);cpu.r[1]=CrtValue::OpaqueSaved(1);cpu.r[2]=CrtValue::Scalar{bits:0x55,known:0xff};let previous=cpu.r;
 run(&mut rt,&mut cpu).unwrap();assert_eq!(CrtCpu::pointer(cpu.r[4]).unwrap().address(),before-allocation);
 for index in [1,2,3,5,6,7]{assert_eq!(cpu.r[index],previous[index]);}
 assert!(cpu.r[0].known_scalar().is_err());assert_eq!((cpu.flags.cf,cpu.flags.zf,cpu.flags.sf,cpu.flags.of),(None,None,None,None));
 assert!(!rt.tags.values().any(|v|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_))));
 // TEST's contents are unknown and dead; probing must not initialize page data.
 let bottom=(before-allocation-4)&!4095;let page=rt.offset(stack,i64::from(bottom)-0x10000).unwrap();
 assert_eq!(rt.load(page,32).unwrap(),CrtValue::Scalar{bits:0,known:0});
}}
// The original helper never reads or writes the word above the caller's ESP.
let mut rt=CrtStreamRuntime::new(7,9,0x4000,32768).unwrap();let stack=rt.map_region(0x16000,0x2000,CrtRegionKind::Stack,None).unwrap();
let sp=rt.offset(stack,0x2000).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();cpu.r[0]=CrtValue::scalar(4096);run(&mut rt,&mut cpu).unwrap();assert_eq!(CrtCpu::pointer(cpu.r[4]).unwrap().address(),0x17000);
"#,
        "probe-success",
    );
}

#[test]
fn generated_probe_preserves_noncanonical_unknown_ecx_and_typed_identity() {
    let p = crt_stream_callees::prove_stack_probe(&probe(), 0x4146e0).unwrap();
    let extra = format!(
        "fn run(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<(),&'static str>{{{} Ok(())}}",
        p.call_source(0x40dc35)
    );
    native(
        &extra,
        r#"
for allocation in [4,0x140c] {
 let mut rt=CrtStreamRuntime::new(7,9,0x4000,65536).unwrap();
 let stack=rt.map_region(0x10000,0x8000,CrtRegionKind::Stack,None).unwrap();
 let source=rt.map_region(0x30000,4,CrtRegionKind::Input,Some(b"safe")).unwrap();
 for original in [CrtValue::Scalar{bits:u32::MAX,known:0},CrtValue::Scalar{bits:0xfaceb00c,known:0xffff0000},CrtValue::Scalar{bits:0xa5a55a5a,known:0x00ff00ff},CrtValue::Pointer(source),CrtValue::OpaqueSaved(1)] {
  let sp=rt.offset(stack,0x7000).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();cpu.r[0]=CrtValue::scalar(allocation);cpu.r[1]=original;
  run(&mut rt,&mut cpu).unwrap();assert_eq!(cpu.r[1],original);assert_eq!(CrtCpu::pointer(cpu.r[4]).unwrap().address(),sp.address()-allocation);
  // Unknown bits remain unknown and a live pointer retains its exact token.
  match cpu.r[1]{CrtValue::Scalar{bits,known}=>{let(ob,ok)=CrtCpu::bits(original).unwrap();assert_eq!((bits,known),(ob,ok));assert!(cpu.r[1].known_scalar().is_err());},CrtValue::Pointer(pointer)=>assert_eq!(pointer,source),CrtValue::OpaqueSaved(r)=>assert_eq!(r,1),_=>panic!("changed ECX type")}
  assert!(!rt.tags.values().any(|value|matches!(value,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_))));
 }
}
"#,
        "probe-unknown-ecx",
    );
}

#[test]
fn generated_probe_rejects_unmapped_pages_or_protected_extent_before_writes() {
    let p = crt_stream_callees::prove_stack_probe(&probe(), 0x4146e0).unwrap();
    let extra = format!(
        "fn run(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<(),&'static str>{{{} Ok(())}}",
        p.call_source(0x40dc35)
    );
    native(
        &extra,
        r#"
// The target word is mapped, but the lower page actually touched by TEST is not.
let mut rt=CrtStreamRuntime::new(7,9,0x4000,32768).unwrap();let stack=rt.map_region(0x16ffc,0x1004,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,0x1004).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();cpu.r[0]=CrtValue::scalar(4096);let registers=cpu.r;
assert!(run(&mut rt,&mut cpu).is_err());assert_eq!(cpu.r,registers);assert!(rt.tags.is_empty());assert_eq!(rt.load(rt.offset(sp,-4).unwrap(),32).unwrap(),CrtValue::Scalar{bits:0,known:0});
for protected_delta in [-4,-8,-2052] {
 let mut rt=CrtStreamRuntime::new(7,9,0x4000,65536).unwrap();let stack=rt.map_region(0x10000,0x8000,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,0x7000).unwrap();let protected=rt.offset(sp,protected_delta).unwrap();rt.store(protected,32,CrtValue::ProtectedReturn(99)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();cpu.r[0]=CrtValue::scalar(4096);let registers=cpu.r;
 assert!(run(&mut rt,&mut cpu).is_err());assert_eq!(cpu.r,registers);assert_eq!(rt.tags.len(),1);assert_eq!(rt.load(protected,32).unwrap(),CrtValue::ProtectedReturn(99));
}
for allocation in [0,1,65540,u32::MAX] {
 let mut rt=CrtStreamRuntime::new(7,9,0x4000,32768).unwrap();let stack=rt.map_region(0x10000,0x4000,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,0x3000).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();cpu.r[0]=CrtValue::scalar(allocation);let registers=cpu.r;assert!(run(&mut rt,&mut cpu).is_err());assert_eq!(cpu.r,registers);assert!(rt.tags.is_empty());
}
"#,
        "probe-rejection",
    );
}

#[test]
fn generated_security_call_preserves_registers_and_has_owned_transient_return() {
    let p = crt_stream_callees::prove_security(&security(), 0x40154c).unwrap();
    let extra = format!(
        "fn run(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<(),&'static str>{{{} Ok(())}}",
        p.call_source(0x40dcff)
    );
    native(
        &extra,
        r#"
let mut rt=CrtStreamRuntime::new(7,9,0x4000,32768).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();let stack=rt.map_region(0x10000,0x1000,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,0x800).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();cpu.r[0]=CrtValue::OpaqueSaved(0);cpu.r[1]=CrtValue::scalar(0x12345678);cpu.r[2]=CrtValue::Scalar{bits:0x42,known:255};let registers=cpu.r;
run(&mut rt,&mut cpu).unwrap();assert_eq!(cpu.r,registers);assert_eq!((cpu.flags.cf,cpu.flags.zf,cpu.flags.sf,cpu.flags.of),(Some(false),Some(true),Some(false),Some(false)));assert!(rt.tags.is_empty());assert_eq!(rt.load(rt.offset(sp,-4).unwrap(),32).unwrap(),CrtValue::Scalar{bits:0,known:0});
cpu.r[1]=CrtValue::scalar(0x12345679);let registers=cpu.r;assert!(run(&mut rt,&mut cpu).is_err());assert_eq!(cpu.r,registers);assert!(rt.tags.is_empty());
cpu.r[1]=CrtValue::Scalar{bits:0x12345678,known:0xfffffffe};assert!(run(&mut rt,&mut cpu).is_err());assert!(rt.tags.is_empty());
cpu.r[1]=CrtValue::scalar(0x12345678);let call=rt.offset(sp,-4).unwrap();rt.store(call,32,CrtValue::ProtectedReturn(99)).unwrap();assert!(run(&mut rt,&mut cpu).is_err());assert_eq!(rt.load(call,32).unwrap(),CrtValue::ProtectedReturn(99));
// Equality does not authorize writing an unmapped original CALL slot.
let mut rt=CrtStreamRuntime::new(7,9,0x4000,32768).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();let sp=rt.map_region(0x10000,4,CrtRegionKind::Stack,None).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();cpu.r[1]=CrtValue::scalar(0x12345678);assert!(run(&mut rt,&mut cpu).is_err());assert!(rt.tags.is_empty());
"#,
        "security-call",
    );
}
