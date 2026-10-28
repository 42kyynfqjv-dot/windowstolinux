//! Independent native checks of the shared CRT primitive boundary. These do
//! not constitute original Windows observations or whole-CRT admission.
use super::{crt_stream_cpu, crt_stream_runtime};

fn native(body: &str, name: &str) {
    let memory = include_str!("guest_memory.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap()
        .lines()
        .filter(|line| !line.starts_with("//!"))
        .collect::<Vec<_>>()
        .join("\n");
    let source = format!(
        "#![allow(dead_code)]\nmod guest_memory{{{memory}}}\n{}\n{}\nfn main(){{{body}}}",
        crt_stream_runtime::EMITTED_TYPES,
        crt_stream_cpu::EMITTED_TYPES,
    );
    let dir =
        std::env::temp_dir().join(format!("w2l-crt-independent-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("run.rs");
    let binary = dir.join(if cfg!(windows) { "run.exe" } else { "run" });
    std::fs::write(&file, source).unwrap();
    let compiled = std::process::Command::new("rustc")
        .args(["--edition=2021", "-Awarnings"])
        .arg(&file)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
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
fn unknown_bytes_foreign_capabilities_and_dead_aliases_never_reach_backend() {
    native(
        r#"
struct Backend{calls:usize}impl CrtBackend for Backend{
 fn write_once(&mut self,_:CrtDescriptorId,bytes:&[u8])->Result<CrtWriteResult,&'static str>{self.calls+=1;assert_eq!(bytes,b"ABCD");Ok(CrtWriteResult{success:true,written:4,last_error:None})}
}
let mut a=CrtStreamRuntime::new(31,41,0x8000,32768).unwrap();let lease=a.lock(41).unwrap();let fd=a.bind_descriptor(1,93).unwrap();let descriptor_lease=a.lock_descriptor(41,fd).unwrap();let data=a.alloc_buffer(lease,4,true).unwrap().unwrap();let mut backend=Backend{calls:0};
// Stored bits are not evidence of initialization. The missing bit cannot be
// silently zeroed, nor can a failed write attempt consume the owned buffer.
a.store(data,32,CrtValue::Scalar{bits:0x44434241,known:0xffff7fff}).unwrap();
assert!(a.load(data,32).unwrap().known_scalar().is_err());assert!(a.write_once(fd,data,4,&mut backend).is_err());assert_eq!(backend.calls,0);
a.store(a.offset(data,1).unwrap(),8,CrtValue::scalar(b'B' as u32)).unwrap();
assert_eq!(a.load(data,32).unwrap().known_scalar().unwrap(),0x44434241);
assert!(a.write_once(fd,a.offset(data,1).unwrap(),4,&mut backend).is_err());assert_eq!(backend.calls,0);
let end=a.offset(data,4).unwrap();assert!(a.load(end,8).is_err());
let mut b=CrtStreamRuntime::new(31,41,0x8000,32768).unwrap();let foreign_lock=b.lock(41).unwrap();let foreign_fd=b.bind_descriptor(1,93).unwrap();let _foreign_descriptor_lease=b.lock_descriptor(41,foreign_fd).unwrap();
assert!(b.load(data,8).is_err());assert!(b.store(b.file(),32,CrtValue::Pointer(data)).is_err());assert!(b.write_once(fd,data,4,&mut backend).is_err());assert!(a.write_once(foreign_fd,data,4,&mut backend).is_err());assert!(a.free_buffer(foreign_lock,data).is_err());assert_eq!(backend.calls,0);
let pointer_field=a.file();a.store(pointer_field,32,CrtValue::Pointer(data)).unwrap();
assert!(a.store(a.offset(pointer_field,1).unwrap(),16,CrtValue::scalar(0)).is_err());assert!(a.load(a.offset(pointer_field,1).unwrap(),16).is_err());assert_eq!(a.load(pointer_field,32).unwrap(),CrtValue::Pointer(data));
assert_eq!(a.write_once(fd,data,4,&mut backend).unwrap().written,4);assert_eq!(backend.calls,1);
a.free_buffer(lease,data).unwrap();assert_eq!(a.load(pointer_field,32).unwrap(),CrtValue::Pointer(data));assert!(a.load(data,8).is_err());assert!(a.offset(data,0).is_err());assert!(a.write_once(fd,data,4,&mut backend).is_err());assert_eq!(backend.calls,1);
// Copying an unchanged dangling word grants no access authority. Numeric
// address reuse in another mapped region cannot revive its old capability.
let replacement=a.map_region(data.base,4,CrtRegionKind::Input,Some(b"ABCD")).unwrap();assert!(a.load(data,8).is_err());assert_eq!(a.load(pointer_field,32).unwrap(),CrtValue::Pointer(data));assert_eq!(a.write_once(fd,replacement,4,&mut backend).unwrap().written,4);assert_eq!(backend.calls,2);
a.unlock_descriptor(descriptor_lease).unwrap();a.unlock(lease).unwrap();assert!(a.write_once(fd,replacement,4,&mut backend).is_err());assert_eq!(backend.calls,2);
"#,
        "byte-identity",
    );
}

#[test]
fn failed_write_count_is_unobserved_and_backend_effects_are_never_retried_or_rolled_back() {
    native(
        r#"
struct Backend{calls:usize,physical:Vec<u8>,success:bool,count:u32}impl CrtBackend for Backend{
 fn write_once(&mut self,_:CrtDescriptorId,bytes:&[u8])->Result<CrtWriteResult,&'static str>{self.calls+=1;assert_eq!(bytes,b"A\r\nB");self.physical.push(bytes[0]);Ok(CrtWriteResult{success:self.success,written:self.count,last_error:if self.success{None}else{Some(5)}})}
}

let mut r=CrtStreamRuntime::new(13,17,0x8000,32768).unwrap();let lease=r.lock(17).unwrap();let fd=r.bind_descriptor(1,93).unwrap();let _descriptor_lease=r.lock_descriptor(17,fd).unwrap();let data=r.map_region(0x9000,4,CrtRegionKind::Input,Some(b"A\r\nB")).unwrap();r.set_errors(lease,Some(19),Some(23)).unwrap();
// The original FALSE edge reads GetLastError, not the output-count cell. A
// backend error can have effects; rejecting/continuing must not undo them.
let mut failed=Backend{calls:0,physical:vec![],success:false,count:u32::MAX};let outcome=r.write_once(fd,data,4,&mut failed).unwrap();assert!(!outcome.success);assert_eq!(outcome.last_error,Some(5));assert_eq!(failed.calls,1);assert_eq!(failed.physical,b"A");assert_eq!((r.errno,r.doserrno),(Some(19),Some(23)));
let mut short=Backend{calls:0,physical:vec![],success:true,count:1};assert_eq!(r.write_once(fd,data,4,&mut short).unwrap().written,1);assert_eq!(short.calls,1);assert_eq!(short.physical,b"A");
// Successful over-report remains an invalid provider contract. Its already
// performed external prefix stays visible, and no second call is introduced.
let mut bad=Backend{calls:0,physical:vec![],success:true,count:5};assert!(r.write_once(fd,data,4,&mut bad).is_err());assert_eq!(bad.calls,1);assert_eq!(bad.physical,b"A");assert_eq!((r.errno,r.doserrno),(Some(19),Some(23)));
"#,
        "failed-count",
    );
}

#[test]
fn narrow_signed_shifts_partial_registers_and_unknown_flags_keep_x86_boundaries() {
    native(
        r#"
let mut rt=CrtStreamRuntime::new(13,17,0x8000,32768).unwrap();let stack=rt.map_region(0x9000,128,CrtRegionKind::Stack,None).unwrap();let entry=rt.offset(stack,64).unwrap();let mut cpu=CrtCpu::new(entry,71).unwrap();
// Literal x86 integer results; no expected value is computed by CPU helpers.
for (bits,width,count,kind,expected,cf,of,sf,zf) in [
 (0x80,8,1,2,0xc0,Some(false),Some(false),true,false),
 (0x8001,16,1,2,0xc000,Some(true),Some(false),true,false),
 (0x80000000,32,31,2,0xffffffff,Some(false),None,true,false),
 (0x80,8,8,2,0xff,Some(true),None,true,false),
 (0x81,8,1,0,2,Some(true),Some(true),false,false),
 (0x80,8,1,1,0x40,Some(false),Some(true),false,false),
 (0x81,8,8,0,0,None,None,false,true),
] {
 assert_eq!(cpu.shift(CrtValue::scalar(bits),count,kind,width).unwrap().known_scalar().unwrap(),expected);
 assert_eq!((cpu.flags.cf,cpu.flags.of,cpu.flags.sf,cpu.flags.zf),(cf,of,Some(sf),Some(zf)));
}
assert!(cpu.condition(2).is_err());
cpu.flags=CrtFlags{cf:Some(true),zf:None,sf:Some(false),of:Some(true)};
assert_eq!(cpu.shift(CrtValue::scalar(0x80),32,2,8).unwrap().known_scalar().unwrap(),0x80);
assert_eq!((cpu.flags.cf,cpu.flags.zf,cpu.flags.sf,cpu.flags.of),(Some(true),None,Some(false),Some(true)));
cpu.set(0,8,0,CrtValue::scalar(0xab)).unwrap();assert!(CrtCpu::number(cpu.r[0]).is_err());assert_eq!(CrtCpu::number(cpu.get(0,8,0).unwrap()).unwrap(),0xab);assert!(CrtCpu::number(cpu.get(0,8,8).unwrap()).is_err());
cpu.clobber(CrtValue::scalar(3));assert!(cpu.condition(0).is_err());assert!(CrtCpu::number(cpu.r[1]).is_err());assert!(CrtCpu::number(cpu.r[2]).is_err());
"#,
        "scalar-boundaries",
    );
}

#[test]
fn rejected_cleanup_and_copied_return_cannot_consume_original_stack_authority() {
    native(
        r#"
let mut rt=CrtStreamRuntime::new(13,17,0x8000,32768).unwrap();let stack=rt.map_region(0x9000,128,CrtRegionKind::Stack,None).unwrap();let entry=rt.offset(stack,64).unwrap();rt.store(entry,32,CrtValue::ProtectedReturn(71)).unwrap();let mut cpu=CrtCpu::new(entry,71).unwrap();cpu.r[0]=CrtValue::scalar(7);
cpu.push(&mut rt,CrtValue::scalar(19)).unwrap();let arg=CrtCpu::pointer(cpu.r[4]).unwrap();assert!(cpu.discard(&mut rt,8).is_err());
assert_eq!(cpu.r[4],CrtValue::Pointer(arg));assert_eq!(rt.load(arg,32).unwrap().known_scalar().unwrap(),19);assert_eq!(rt.load(entry,32).unwrap(),CrtValue::ProtectedReturn(71));
cpu.discard(&mut rt,4).unwrap();
// Equal token bits at another word do not move the protected caller-return
// location. Even a correctly typed token copy must not make an imbalanced RET.
let token=rt.load(entry,32).unwrap();cpu.push(&mut rt,token).unwrap();let copy=CrtCpu::pointer(cpu.r[4]).unwrap();assert!(cpu.finish(&mut rt).is_err());assert_eq!(rt.load(entry,32).unwrap(),token);assert_eq!(rt.load(copy,32).unwrap(),token);
assert_eq!(cpu.pop(&mut rt).unwrap(),token);assert_eq!(cpu.finish(&mut rt).unwrap().known_scalar().unwrap(),7);assert_eq!(CrtCpu::pointer(cpu.r[4]).unwrap().address(),0x9044);assert!(rt.load(entry,32).unwrap().known_scalar().is_err());
"#,
        "protected-stack",
    );
}

#[test]
fn freeing_a_narrowed_base_view_cannot_leak_tags_into_reused_storage() {
    native(
        r#"
let mut r=CrtStreamRuntime::new(13,17,0x8000,32768).unwrap();let lease=r.lock(17).unwrap();let old=r.alloc_buffer(lease,32,true).unwrap().unwrap();let target=r.map_region(0x9000,4,CrtRegionKind::Input,Some(b"ABCD")).unwrap();
r.store(r.offset(old,16).unwrap(),32,CrtValue::Pointer(target)).unwrap();r.store(r.offset(old,24).unwrap(),8,CrtValue::Scalar{bits:0xa5,known:0x0f}).unwrap();
let narrow=r.subrange(old,4).unwrap();
// Either reject a narrowed free atomically or free its complete underlying
// allocation. Clearing only the narrowed metadata extent is never sound.
if r.free_buffer(lease,narrow).is_err(){assert_eq!(r.load(r.offset(old,16).unwrap(),32).unwrap(),CrtValue::Pointer(target));r.free_buffer(lease,old).unwrap();}
let fresh=r.map_region(old.base,32,CrtRegionKind::Result,None).unwrap();
assert_eq!(r.load(r.offset(fresh,16).unwrap(),32).unwrap(),CrtValue::Scalar{bits:0,known:0});
assert_eq!(r.load(r.offset(fresh,24).unwrap(),8).unwrap(),CrtValue::Scalar{bits:0,known:0xffffff00});
assert!(r.load(old,8).is_err());assert_eq!(r.load(target,32).unwrap().known_scalar().unwrap(),0x44434241);
"#,
        "narrow-free",
    );
}

#[test]
fn original_pointer_test_zero_cannot_prune_the_taken_native_edge() {
    use super::crt_stream_worker::{Bindings, Proof, Region};
    // This independently authored selector observes an input capability with
    // TEST EAX,0. Its JE is always taken: no pointer address supplies the answer.
    // The prior proof confused TEST with CMP(pointer,0), removed the taken edge,
    // and the emitted native program failed at the removed instruction.
    let selector = [
        0x8b, 0x44, 0x24, 8, 0xa9, 0, 0, 0, 0, 0x74, 6, 0xb8, 5, 0, 0, 0, 0xc3, 0xb8, 7, 0, 0, 0,
        0xc3,
    ];
    let zero = [0x31, 0xc0, 0xc3];
    let proof = Proof::prove(
        Region {
            bytes: &selector,
            origin: 0x1000,
        },
        Region {
            bytes: &zero,
            origin: 0x2000,
        },
        Region {
            bytes: &zero,
            origin: 0x3000,
        },
        Bindings {
            descriptor_number: 1,
            descriptor_limit: 64,
            descriptor_table: 0x6000,
            descriptor_limit_address: 0x7000,
            text_writer: 0x4000,
            errno_update: 0x5000,
        },
    )
    .unwrap();
    let emitted = proof
        .emit("independent", |_, _| Err("unexpected call".into()))
        .unwrap();
    let body = format!(
        r#"
{emitted}
struct Backend;impl CrtBackend for Backend{{fn write_once(&mut self,_:CrtDescriptorId,_:&[u8])->Result<CrtWriteResult,&'static str>{{panic!("no IO")}}}}
let mut rt=CrtStreamRuntime::new(13,17,0x8000,32768).unwrap();let lease=rt.lock(17).unwrap();
let stack=rt.map_region(0x9000,128,CrtRegionKind::Stack,None).unwrap();let entry=rt.offset(stack,64).unwrap();rt.store(entry,32,CrtValue::ProtectedReturn(71)).unwrap();
let input=rt.map_region(0xa000,4,CrtRegionKind::Input,Some(b"ABCD")).unwrap();
for (at,v) in [(4,CrtValue::scalar(1)),(8,CrtValue::Pointer(input)),(12,CrtValue::scalar(4))]{{rt.store(rt.offset(entry,at).unwrap(),32,v).unwrap();}}
let mut cpu=CrtCpu::new(entry,71).unwrap();let result=independent_selector(&mut rt,&mut cpu,lease,&mut Backend).unwrap();
assert_eq!(result.known_scalar().unwrap(),7);
assert_eq!(CrtCpu::pointer(cpu.r[4]).unwrap().address(),0x9044);
"#
    );
    native(&body, "pointer-test-zero");
}

#[test]
fn branch_enumeration_cannot_make_clobbered_machine_bits_available() {
    use super::crt_stream_worker::{Bindings, Proof, Region};
    let zero = [0x31, 0xc0, 0xc3];
    let prove = |selector: &[u8]| {
        Proof::prove(
            Region {
                bytes: selector,
                origin: 0x1000,
            },
            Region {
                bytes: &zero,
                origin: 0x2000,
            },
            Region {
                bytes: &zero,
                origin: 0x3000,
            },
            Bindings {
                descriptor_number: 1,
                descriptor_limit: 64,
                descriptor_table: 0x6000,
                descriptor_limit_address: 0x7000,
                text_writer: 0x4000,
                errno_update: 0x5000,
            },
        )
    };
    // The console contract establishes AL=0, while upper EAX, ECX and EDX
    // remain unavailable. Enumerating both CMP branches does not supply those
    // bits. The old proof admitted this and emitted native code then rejected
    // its own certified CMP with "unknown scalar bits observed".
    for operand in [0xf8, 0xf9, 0xfa] {
        let mut code = vec![0xff, 0x74, 0x24, 16, 0x6a, 1, 0xe8];
        code.extend_from_slice(&(0x2000u32 - 0x100b).to_le_bytes());
        code.extend_from_slice(&[
            0x83, 0xc4, 8, 0x83, operand, 0, 0x74, 6, 0xb8, 5, 0, 0, 0, 0xc3, 0xb8, 7, 0, 0, 0,
            0xc3,
        ]);
        assert!(prove(&code).is_err(), "clobbered CMP operand {operand:#x}");
    }
    // Defined but variable caller input is different: the compiler may retain
    // both outcomes and evaluate the actual count at native runtime.
    let defined_count = [
        0x8b, 0x54, 0x24, 12, 0x83, 0xfa, 0, 0x74, 6, 0xb8, 5, 0, 0, 0, 0xc3, 0xb8, 7, 0, 0, 0,
        0xc3,
    ];
    assert!(prove(&defined_count).is_ok());
}

#[test]
fn certified_argument_cleanup_cannot_discard_protected_or_revive_dead_words() {
    use super::crt_stream_worker::{Bindings, Proof, Region};
    let zero = [0x31, 0xc0, 0xc3];
    for (name, code) in [
        (
            "copied protected return",
            &[0xff, 0x34, 0x24, 0x83, 0xc4, 4, 0xb8, 7, 0, 0, 0, 0xc3][..],
        ),
        (
            "read discarded scalar",
            &[0x6a, 7, 0x83, 0xc4, 4, 0x8b, 0x44, 0x24, 0xfc, 0xc3][..],
        ),
    ] {
        let result = Proof::prove(
            Region {
                bytes: code,
                origin: 0x1000,
            },
            Region {
                bytes: &zero,
                origin: 0x2000,
            },
            Region {
                bytes: &zero,
                origin: 0x3000,
            },
            Bindings {
                descriptor_number: 1,
                descriptor_limit: 64,
                descriptor_table: 0x6000,
                descriptor_limit_address: 0x7000,
                text_writer: 0x4000,
                errno_update: 0x5000,
            },
        );
        assert!(result.is_err(), "admitted {name}");
    }
}

#[test]
fn nested_native_calls_preserve_entry_authority_and_failed_partial_effects() {
    native(
        r#"
struct Backend;impl CrtBackend for Backend{fn write_once(&mut self,_:CrtDescriptorId,_:&[u8])->Result<CrtWriteResult,&'static str>{panic!("no IO")}}
fn setup()->(CrtStreamRuntime,CrtLock,CrtCpu,CrtPointer){
 let mut rt=CrtStreamRuntime::new(13,17,0x8000,32768).unwrap();let lease=rt.lock(17).unwrap();
 let stack=rt.map_region(0x9000,256,CrtRegionKind::Stack,None).unwrap();let entry=rt.offset(stack,224).unwrap();
 let output=rt.map_region(0xa000,4,CrtRegionKind::Result,Some(&[0;4])).unwrap();
 rt.store(entry,32,CrtValue::ProtectedReturn(71)).unwrap();let mut cpu=CrtCpu::new(entry,71).unwrap();
 cpu.r[0]=CrtValue::scalar(31);cpu.r[1]=CrtValue::scalar(42);cpu.flags.zf=Some(true);
 (rt,lease,cpu,output)
}
let(mut rt,lease,mut cpu,_)=setup();let original=cpu.entry;
let value=cpu.call(&mut rt,lease,&mut Backend,0x1005,|rt,child,lease,backend|{
 assert_eq!(CrtCpu::pointer(child.entry[4])?.address(),0x90dc);assert_eq!(child.r[0],CrtValue::scalar(31));assert_eq!(child.r[1],CrtValue::scalar(42));assert_eq!(child.flags.zf,Some(true));
 let first_identity=child.return_id;child.tick(30)?;
 let value=child.call(rt,lease,backend,0x2005,|rt,nested,_,_|{
  assert_ne!(nested.return_id,first_identity);assert_eq!(CrtCpu::pointer(nested.entry[4])?.address(),0x90d8);
  nested.tick(30)?;nested.r[0]=CrtValue::scalar(17);nested.flags.zf=Some(false);nested.finish(rt)
 })?;
 assert_eq!(value,CrtValue::scalar(17));assert_eq!(CrtCpu::pointer(child.r[4])?.address(),0x90dc);
 child.tick(30)?;child.finish(rt)
}).unwrap();
assert_eq!(value,CrtValue::scalar(17));assert_eq!(cpu.entry,original);assert_eq!(cpu.steps,3);assert_eq!(cpu.flags.zf,Some(false));assert_eq!(CrtCpu::pointer(cpu.r[4]).unwrap().address(),0x90e0);
assert_eq!(rt.load(CrtCpu::pointer(cpu.r[4]).unwrap(),32).unwrap(),CrtValue::ProtectedReturn(71));cpu.finish(&mut rt).unwrap();assert!(cpu.finish(&mut rt).is_err());
// A result without the original protected RET is not completion.
let(mut rt,lease,mut cpu,output)=setup();let original=cpu.entry;
assert!(cpu.call(&mut rt,lease,&mut Backend,0x1005,|rt,child,_,_|{rt.store(output,32,CrtValue::scalar(93))?;child.r[0]=CrtValue::scalar(9);Ok(child.r[0])}).is_err());
assert_eq!(rt.load(output,32).unwrap(),CrtValue::scalar(93));assert_eq!(cpu.entry,original);assert_eq!(CrtCpu::pointer(cpu.r[4]).unwrap().address(),0x90dc);assert!(matches!(rt.load(CrtCpu::pointer(cpu.r[4]).unwrap(),32).unwrap(),CrtValue::ProtectedReturn(_)));
// Failure preserves writes and current stack; it does not restore a snapshot.
let(mut rt,lease,mut cpu,output)=setup();
assert_eq!(cpu.call(&mut rt,lease,&mut Backend,0x1005,|rt,child,_,_|{rt.store(output,32,CrtValue::scalar(107))?;child.push(rt,CrtValue::scalar(8))?;Err("injected callee failure")}),Err("injected callee failure"));
assert_eq!(rt.load(output,32).unwrap(),CrtValue::scalar(107));assert_eq!(CrtCpu::pointer(cpu.r[4]).unwrap().address(),0x90d8);assert_eq!(rt.load(CrtCpu::pointer(cpu.r[4]).unwrap(),32).unwrap(),CrtValue::scalar(8));
"#,
        "nested-call-authority",
    );
}
