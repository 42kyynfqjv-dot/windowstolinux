//! Independent instruction/prerequisite tests; no formatter/startup admission.
use super::{crt_stream_cpu, crt_stream_emit, crt_stream_ir, crt_stream_runtime};
use std::collections::BTreeMap;
fn native(extra: &str, body: &str, name: &str) {
    let memory = include_str!("guest_memory.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with("//!"))
        .collect::<Vec<_>>()
        .join("\n");
    let source = format!(
        "#![allow(dead_code)]\nmod guest_memory{{{memory}}}\n{}\n{}\n{extra}\nfn main(){{{body}}}",
        crt_stream_runtime::EMITTED_TYPES,
        crt_stream_cpu::EMITTED_TYPES
    );
    let dir = std::env::temp_dir().join(format!("w2l-formatter-ir-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.rs");
    let exe = dir.join(if cfg!(windows) { "test.exe" } else { "test" });
    std::fs::write(&path, source).unwrap();
    let o = std::process::Command::new("rustc")
        .arg("--edition=2021")
        .arg(&path)
        .arg("-o")
        .arg(&exe)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let o = std::process::Command::new(&exe).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    std::fs::remove_dir_all(dir).unwrap();
}
const SETUP: &str = r#"
let mut rt=CrtStreamRuntime::new(1,2,0x4000,65536).unwrap();let lease=rt.lock(2).unwrap();let stack=rt.map_region(0x10000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,2048).unwrap();let mut cpu=CrtCpu::new(sp,9).unwrap();
"#;
#[test]
fn width_and_fault_domains_are_explicit() {
    use crt_stream_ir::{Graph, Op};
    let g = Graph::decode(&[0x99, 0x83, 0xd2, 0, 0xf7, 0xf1, 0xc2, 8, 0], 0x1000).unwrap();
    assert!(matches!(g.nodes[&0x1000].op, Op::SignDividend));
    assert!(matches!(g.nodes[&0x1001].op, Op::AddCarry { .. }));
    assert!(matches!(g.nodes[&0x1004].op, Op::DivideUnsigned(_)));
    assert!(matches!(g.nodes[&0x1006].op, Op::ReturnPop(8)));
    for c in [
        &[0x66, 0x99, 0xc3][..],
        &[0x66, 0xf7, 0xf1, 0xc3],
        &[0xf7, 0xf9, 0xc3],
        &[0xf6, 0xf1, 0xc3],
        &[0xc2, 2, 0],
        &[0xc2, 4, 1],
        &[0x66, 0xc2, 8, 0],
        &[0x14, 1, 0xc3],
        &[0xff, 0xe0],
    ] {
        assert!(Graph::decode(c, 0x1000).is_err(), "{c:?}");
    }
    let g = Graph::decode(
        &[
            0x0f, 0xbf, 0x45, 0xfe, 0x0f, 0xb7, 0x4d, 0xfc, 0xff, 0x4f, 0x30, 0xc3,
        ],
        0x1000,
    )
    .unwrap();
    assert!(matches!(g.nodes[&0x1008].op, Op::DecrementMemory(_)));
}
#[test]
fn cdq_adc_div_independent_boundaries_and_fault_atomicity() {
    native(
        "",
        &format!(
            "{SETUP}{}",
            r#"
for (input,expected)in[(0,0),(0x7fffffff,0),(0x80000000,u32::MAX),(u32::MAX,u32::MAX)]{cpu.r[0]=CrtValue::scalar(input);cpu.flags=CrtFlags{cf:Some(true),zf:None,sf:Some(false),of:None};cpu.sign_dividend().unwrap();assert_eq!(cpu.r[0],CrtValue::scalar(input));assert_eq!(cpu.r[2],CrtValue::scalar(expected));assert_eq!((cpu.flags.cf,cpu.flags.zf,cpu.flags.sf,cpu.flags.of),(Some(true),None,Some(false),None));}
cpu.r[0]=CrtValue::Scalar{bits:0x1234,known:0x7fffffff};cpu.sign_dividend().unwrap();assert_eq!(cpu.r[2],CrtValue::Scalar{bits:0,known:0});cpu.r[0]=CrtValue::Scalar{bits:0x80000000,known:0x80000000};cpu.sign_dividend().unwrap();assert_eq!(cpu.r[2],CrtValue::scalar(u32::MAX));
for(x,y,carry,result,cf,of)in[(u32::MAX,0,true,0,true,false),(0x7fffffff,0,true,0x80000000,false,true),(0x80000000,u32::MAX,false,0x7fffffff,true,true),(0x80000000,0x7fffffff,true,0,true,false),(1,2,false,3,false,false)]{cpu.flags.cf=Some(carry);assert_eq!(cpu.add_carry(CrtValue::scalar(x),CrtValue::scalar(y)).unwrap(),CrtValue::scalar(result));assert_eq!((cpu.flags.cf,cpu.flags.of),(Some(cf),Some(of)));}
cpu.flags=CrtFlags::unknown();assert!(cpu.add_carry(CrtValue::scalar(1),CrtValue::scalar(2)).is_err());assert!(cpu.flags.cf.is_none());
for(high,low,divisor,q,r)in[(0,0,10,0,0),(0,u32::MAX,10,429496729,5),(1,0,2,2147483648,0),(9,u32::MAX,10,u32::MAX,9),(u32::MAX-1,u32::MAX,u32::MAX,u32::MAX,u32::MAX-1)]{cpu.r[0]=CrtValue::scalar(low);cpu.r[2]=CrtValue::scalar(high);cpu.divide_unsigned(CrtValue::scalar(divisor)).unwrap();assert_eq!((cpu.r[0],cpu.r[2]),(CrtValue::scalar(q),CrtValue::scalar(r)));assert_eq!((cpu.flags.cf,cpu.flags.zf,cpu.flags.sf,cpu.flags.of),(None,None,None,None));}
for(high,divisor)in[(0,0),(1,1),(10,10),(u32::MAX,u32::MAX)]{cpu.r[0]=CrtValue::scalar(7);cpu.r[2]=CrtValue::scalar(high);cpu.flags=CrtFlags{cf:Some(true),zf:Some(false),sf:Some(true),of:Some(false)};let before=cpu.r;assert!(cpu.divide_unsigned(CrtValue::scalar(divisor)).is_err());assert_eq!(cpu.r,before);assert_eq!((cpu.flags.cf,cpu.flags.zf,cpu.flags.sf,cpu.flags.of),(Some(true),Some(false),Some(true),Some(false)));}
cpu.r[0]=CrtValue::Scalar{bits:5,known:0xfffffff7};cpu.r[2]=CrtValue::scalar(0);let before=cpu.r;assert!(cpu.divide_unsigned(CrtValue::scalar(10)).is_err());assert_eq!(cpu.r,before);
"#
        ),
        "arithmetic",
    );
}
#[test]
fn ret_cleanup_requires_caller_authority_and_protected_range_preflight() {
    native(
        "",
        &format!(
            "{SETUP}{}",
            r#"
struct B;impl CrtBackend for B{fn write_once(&mut self,_:CrtDescriptorId,_:&[u8])->Result<CrtWriteResult,&'static str>{panic!("no backend")}}
rt.store(sp,32,CrtValue::ProtectedReturn(9)).unwrap();cpu.push(&mut rt,CrtValue::scalar(22)).unwrap();cpu.push(&mut rt,CrtValue::scalar(11)).unwrap();let mut backend=B;
let returned=cpu.call_pop(&mut rt,lease,&mut backend,0x1234,8,|rt,child,_,_|{let entry=CrtCpu::pointer(child.r[4])?;assert_eq!(rt.load(rt.offset(entry,4)?,32)?,CrtValue::scalar(11));assert_eq!(rt.load(rt.offset(entry,8)?,32)?,CrtValue::scalar(22));child.r[0]=CrtValue::scalar(33);child.finish_pop(rt,8)}).unwrap();assert_eq!(returned,CrtValue::scalar(33));assert_eq!(cpu.r[4],CrtValue::Pointer(sp));assert_eq!(rt.load(sp,32).unwrap(),CrtValue::ProtectedReturn(9));
let before=cpu.r;let tags=rt.tags.clone();assert!(cpu.call_pop(&mut rt,lease,&mut backend,0x1234,4,|_,_,_,_|panic!("protected argument must reject before callback")).is_err());assert_eq!(cpu.r,before);assert_eq!(rt.tags,tags);
let mut cpu=CrtCpu::new(sp,9).unwrap();cpu.r[0]=CrtValue::scalar(0);assert!(cpu.finish_pop(&mut rt,4).is_err());assert_eq!(cpu.r[4],CrtValue::Pointer(sp));assert_eq!(rt.load(sp,32).unwrap(),CrtValue::ProtectedReturn(9));
cpu.return_pop=4;rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::OpaqueSaved(3)).unwrap();let tags=rt.tags.clone();assert!(cpu.finish_pop(&mut rt,4).is_err());assert_eq!(rt.tags,tags);assert_eq!(cpu.r[4],CrtValue::Pointer(sp));assert!(!cpu.returned);
"#
        ),
        "ret-cleanup",
    );
}
#[test]
fn partial_address_projection_retains_unknown_bits_without_capability() {
    native(
        "",
        &format!(
            "{SETUP}{}",
            r#"
cpu.r[1]=CrtValue::Pointer(stack);cpu.set(1,8,0,CrtValue::scalar(65)).unwrap();assert_eq!(cpu.r[1],CrtValue::scalar(0x10041));cpu.flags=CrtFlags{cf:Some(true),zf:None,sf:Some(false),of:None};let x=cpu.lea(&rt,Some(1),None,1,(-32i32)as u32,None).unwrap();assert_eq!(x,CrtValue::scalar(0x10021));assert!(CrtCpu::pointer(x).is_err());assert!(cpu.address(&rt,Some(1),None,1,0,None).is_err());assert_eq!((cpu.flags.cf,cpu.flags.zf,cpu.flags.sf,cpu.flags.of),(Some(true),None,Some(false),None));
cpu.r[1]=CrtValue::Scalar{bits:65,known:255};let v=cpu.lea(&rt,Some(1),None,1,(-32i32)as u32,None).unwrap();let(bits,known)=CrtCpu::bits(v).unwrap();assert_eq!(bits&255,33);assert_eq!(known&255,255);assert_ne!(known,u32::MAX);
for input in [0u32,1,31,32,65,127,128,255]{cpu.r[1]=CrtValue::Scalar{bits:input,known:255};let v=cpu.lea(&rt,Some(1),None,1,(-32i32)as u32,None).unwrap();let(b,k)=CrtCpu::bits(v).unwrap();for upper in [0,0x0100,0xffff0000]{let concrete=(upper|input).wrapping_sub(32);assert_eq!(concrete&k,b&k);}}
"#
        ),
        "scalar-lea",
    );
}
fn switch_bytes(origin: u32, mapped: bool) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut c = vec![0x83, 0xf8, if mapped { 2 } else { 1 }, 0x77, 0];
    if mapped {
        c.extend([0x0f, 0xb6, 0x80, 0, 0x60, 0, 0]);
    }
    c.extend([0xff, 0x24, 0x85, 0, 0x50, 0, 0]);
    let a = origin + c.len() as u32;
    c.extend([0xb8, 11, 0, 0, 0, 0xc3]);
    let b = origin + c.len() as u32;
    c.extend([0xb8, 22, 0, 0, 0, 0xc3]);
    let d = c.len();
    c.extend([0xb8, 33, 0, 0, 0, 0xc3]);
    c[4] = (d - 5) as u8;
    (
        c,
        [a.to_le_bytes(), b.to_le_bytes()].concat(),
        vec![1, 0, 1],
    )
}
#[test]
fn table_bounds_targets_and_guard_entry_cannot_be_forged() {
    use crt_stream_ir::{ByteTable, Graph, JumpTable};
    for mapped in [false, true] {
        let (c, t, m) = switch_bytes(0x1000, mapped);
        let tables = [JumpTable {
            address: 0x5000,
            bytes: &t,
        }];
        let maps = if mapped {
            vec![ByteTable {
                address: 0x6000,
                bytes: &m,
            }]
        } else {
            vec![]
        };
        Graph::decode_with_table_maps(&c, 0x1000, &tables, &maps).unwrap();
        assert!(Graph::decode(&c, 0x1000).is_err());
        for (at, value) in [(2, c[2] + 1), (3, 0x73)] {
            let mut bad = c.clone();
            bad[at] = value;
            assert!(Graph::decode_with_table_maps(&bad, 0x1000, &tables, &maps).is_err());
        }
        let mut bad = t.clone();
        bad[0] += 1;
        assert!(Graph::decode_with_table_maps(
            &c,
            0x1000,
            &[JumpTable {
                address: 0x5000,
                bytes: &bad
            }],
            &maps
        )
        .is_err());
        let jump = 0x1000 + if mapped { 12 } else { 5 };
        let mut bad = t.clone();
        bad[..4].copy_from_slice(&u32::to_le_bytes(jump));
        assert!(Graph::decode_with_table_maps(
            &c,
            0x1000,
            &[JumpTable {
                address: 0x5000,
                bytes: &bad
            }],
            &maps
        )
        .is_err());
        if mapped {
            assert!(Graph::decode_with_table_maps(
                &c,
                0x1000,
                &tables,
                &[ByteTable {
                    address: 0x6000,
                    bytes: &[2, 0, 1]
                }]
            )
            .is_err());
        }
    }
    // Exact embedded table: two leading NOPs align the source table at 0x1020.
    let (c, _, _) = switch_bytes(0x1000, false);
    let mut code = vec![0x90, 0x90];
    code.extend(c);
    code[10..14].copy_from_slice(&0x1020u32.to_le_bytes());
    let table = [0x100eu32.to_le_bytes(), 0x1014u32.to_le_bytes()].concat();
    assert_eq!(code.len(), 32);
    code.extend(&table);
    Graph::decode_with_tables(
        &code,
        0x1000,
        &[JumpTable {
            address: 0x1020,
            bytes: &table,
        }],
    )
    .unwrap();
    let mut bad = table.clone();
    bad[0] += 1;
    assert!(Graph::decode_with_tables(
        &code,
        0x1000,
        &[JumpTable {
            address: 0x1020,
            bytes: &bad
        }]
    )
    .is_err());
}
#[test]
fn emitted_table_branch_uses_actual_owned_words_and_checks_mutation() {
    let (c, t, m) = switch_bytes(0x1000, true);
    let g = crt_stream_ir::Graph::decode_with_table_maps(
        &c,
        0x1000,
        &[crt_stream_ir::JumpTable {
            address: 0x5000,
            bytes: &t,
        }],
        &[crt_stream_ir::ByteTable {
            address: 0x6000,
            bytes: &m,
        }],
    )
    .unwrap();
    let source = crt_stream_emit::emit_graph(
        &g,
        "dispatch",
        |_, _| Err("no calls".into()),
        &BTreeMap::from([(0x6000, "CrtRegionKind::Module".into())]),
        64,
    )
    .unwrap();
    let body = format!(
        r#"
struct B;impl CrtBackend for B{{fn write_once(&mut self,_:CrtDescriptorId,_:&[u8])->Result<CrtWriteResult,&'static str>{{panic!("no backend")}}}}
for(input,expected)in[(0,22),(1,11),(2,22),(3,33),(u32::MAX,33)]{{{SETUP}rt.map_region(0x5000,8,CrtRegionKind::Module,Some(&{t:?})).unwrap();rt.map_region(0x6000,3,CrtRegionKind::Module,Some(&[1,0,1])).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(9)).unwrap();cpu.r[0]=CrtValue::scalar(input);assert_eq!(dispatch(&mut rt,&mut cpu,lease,&mut B).unwrap(),CrtValue::scalar(expected));}}
{SETUP}let table=rt.map_region(0x5000,8,CrtRegionKind::Module,Some(&{t:?})).unwrap();rt.map_region(0x6000,3,CrtRegionKind::Module,Some(&[1,0,1])).unwrap();rt.store(rt.offset(table,4).unwrap(),32,CrtValue::scalar(0xdeadbeef)).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(9)).unwrap();cpu.r[0]=CrtValue::scalar(0);assert!(dispatch(&mut rt,&mut cpu,lease,&mut B).is_err());assert!(!cpu.returned);
"#
    );
    native(&source, &body, "table-native");
}

#[test]
fn external_tail_inventory_cannot_silently_become_emission() {
    let code = [0xe9, 0xfb, 0x0f, 0, 0];
    assert!(crt_stream_ir::Graph::decode(&code, 0x1000).is_err());
    let g = crt_stream_ir::Graph::decode_with_exits(&code, 0x1000, &[0x2000]).unwrap();
    assert_eq!(g.nodes[&0x1000].successors, vec![0x2000]);
    assert!(
        crt_stream_emit::emit_graph(&g, "bad", |_, _| Ok(String::new()), &BTreeMap::new(), 8)
            .is_err()
    );
    assert!(crt_stream_ir::Graph::decode_with_exits(&code, 0x1000, &[0x2001]).is_err());
    assert!(crt_stream_ir::Graph::decode_with_exits(&[0xeb, 0xff], 0x1000, &[0x1001]).is_err());
}

#[test]
fn fs_hooks_require_binding_and_thread_heads_never_become_scalar_authority() {
    for code in [
        &[0x64, 0xff, 0x35, 0, 0, 0, 0, 0xc3][..],
        &[0x64, 0xa1, 0, 0, 0, 0, 0xc3],
    ] {
        let graph = crt_stream_ir::Graph::decode(code, 0x1000).unwrap();
        assert!(crt_stream_emit::emit_graph(
            &graph,
            "unbound",
            |_, _| Err("no calls".into()),
            &BTreeMap::new(),
            16
        )
        .is_err());
    }
    native(
        "",
        &format!(
            r#"{SETUP}
let head=rt.thread_head(17,23,[1,2,3]).unwrap();let value=CrtValue::ThreadHead(head);
assert!(CrtCpu::number(value).is_err());assert!(CrtCpu::bits(value).is_err());
cpu.push(&mut rt,value).unwrap();let before=cpu.r[4];let slot=CrtCpu::pointer(before).unwrap();assert!(rt.store(slot,32,CrtValue::scalar(0)).is_err());assert_eq!(rt.load(slot,32).unwrap(),value);assert!(rt.retire_region(stack).is_err());assert!(cpu.discard(&mut rt,4).is_err());assert_eq!(cpu.r[4],before);assert_eq!(cpu.pop(&mut rt).unwrap(),value);
let mut other=CrtStreamRuntime::new(1,2,0x4000,65536).unwrap();assert!(other.validate_thread_head(head).is_err());
"#
        ),
        "fs-authority",
    );
}

#[test]
fn signed_index_wrap_is_bounded_by_the_original_capability() {
    native(
        "",
        &format!(
            r#"{SETUP}
let table=rt.map_region(0x20000,8,CrtRegionKind::Module,Some(&[0;8])).unwrap();
cpu.r[1]=CrtValue::scalar(u32::MAX);cpu.r[0]=CrtValue::Pointer(rt.offset(table,2).unwrap());
assert_eq!(cpu.address(&rt,Some(0),Some(1),2,0,None).unwrap().address(),0x20000);
cpu.r[0]=CrtValue::Pointer(table);assert!(cpu.address(&rt,Some(0),Some(1),2,0,None).is_err());
cpu.r[1]=CrtValue::Scalar{{bits:0,known:0}};assert!(cpu.address(&rt,Some(0),Some(1),2,0,None).is_err());
let unrelated=rt.map_region(0x21000,8,CrtRegionKind::Module,Some(&[0;8])).unwrap();cpu.r[1]=CrtValue::scalar(0x800);assert!(cpu.address(&rt,Some(0),Some(1),2,0,None).is_err());assert_eq!(unrelated.address(),0x21000);
"#
        ),
        "index-bounds",
    );
}
