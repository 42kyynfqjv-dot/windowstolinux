//! Mechanical native basic-block emission from the same proved normalized graph.
use super::{graph::*, Bound, Function};
use std::fmt::Write;
fn addr(a: &Address) -> String {
    format!(
        "{}u32.wrapping_add({}).wrapping_add({})",
        a.displacement,
        a.base.map_or("0".into(), |i| format!("r[{i}]")),
        a.index
            .map_or("0".into(), |i| format!("r[{i}].wrapping_mul({})", a.scale))
    )
}
fn value(o: &Operand, load: bool) -> String {
    match o {
        Operand::Reg(r) => {
            if r.width == 8 {
                format!("((r[{}]>>{})&255)", r.index, r.shift)
            } else {
                format!("r[{}]", r.index)
            }
        }
        Operand::Immediate(n) => format!("{n}u32"),
        Operand::Memory(_, _) if load => "0u32".into(), // Bound function token, never scalar-observable.
        Operand::Memory(a, w) => format!("m.get({}, {})", addr(a), w / 8),
    }
}
fn store(o: &Operand, v: &str) -> String {
    match o {
        Operand::Reg(r) => {
            if r.width == 8 {
                format!(
                    "r[{}]=(r[{}]&!{}u32)|((({v})&255)<<{});",
                    r.index,
                    r.index,
                    255u32 << r.shift,
                    r.shift
                )
            } else {
                format!("r[{}]={v};", r.index)
            }
        }
        Operand::Memory(a, w) => format!("m.put({}, {}, {v});", addr(a), w / 8),
        _ => unreachable!(),
    }
}
pub(super) fn emit(bound: &Bound) -> String {
    // The same checked core is tested directly and compiled into native output.
    // Proof identity is runtime-local; no process IDs enter generated source.
    let core = include_str!("../../guest_memory.rs")
        .split("\n#[cfg(test)]")
        .next()
        .unwrap();
    let mut out = include_str!("runtime.txt").replace(
        "// CHECKED_MEMORY_MODULE",
        &format!("#[allow(dead_code)]\nmod guest_memory {{\n{core}\n}}"),
    );
    writeln!(out,"pub fn run<B: StreamIo>(io:&mut B)->u32 {{\nlet mut r=[0u32;8];r[4]=4096;let mut m=Frame::new();let mut cf=false;let mut zf=false;let mut error=0u32;let mut pc={}u32;loop{{match pc{{",bound.graph.entry).unwrap();
    for (&pc, node) in &bound.graph.nodes {
        writeln!(out, "{pc}=>{{").unwrap();
        match &node.operation {
            Operation::Binary(op, dst, src) => {
                let b = value(src, bound.loads.contains_key(&pc));
                let width = match dst {
                    Operand::Reg(r) => r.width,
                    Operand::Memory(_, w) => *w,
                    _ => unreachable!(),
                };
                if *op == Binary::Move {
                    writeln!(out, "let v={b};{}", store(dst, "v")).unwrap();
                } else {
                    let a = value(dst, false);
                    let mask = if width == 8 { 255u32 } else { u32::MAX };
                    writeln!(out, "let a={a};let b={b};").unwrap();
                    let expr = match op {
                        Binary::Add => "a.wrapping_add(b)",
                        Binary::Sub | Binary::Compare => "a.wrapping_sub(b)",
                        Binary::Sbb => "a.wrapping_sub(b).wrapping_sub(u32::from(cf))",
                        Binary::And => "a&b",
                        Binary::Or => "a|b",
                        Binary::Test => "a&b",
                        Binary::Xor => "a^b",
                        _ => unreachable!(),
                    };
                    writeln!(
                        out,
                        "let _borrow=cf;let v=({expr})&{mask};zf=v==0;cf={};",
                        match op {
                            Binary::Add => format!("u64::from(a)+u64::from(b)>{mask}"),
                            Binary::Sub | Binary::Compare => "a<b".into(),
                            Binary::Sbb => "u64::from(a)<u64::from(b)+u64::from(_borrow)".into(),
                            _ => "false".into(),
                        }
                    )
                    .unwrap();
                    if !matches!(op, Binary::Compare | Binary::Test) {
                        writeln!(out, "{}", store(dst, "v")).unwrap();
                    }
                    if matches!(
                        dst,
                        Operand::Reg(Reg {
                            shift: 0,
                            index: 4,
                            width: 32
                        })
                    ) && *op == Binary::Sub
                    {
                        writeln!(out, "m.invalidate(r[4],b);").unwrap();
                    }
                }
            }
            Operation::Shift { left, dst, count } => {
                if *count != 0 {
                    let a = value(&Operand::Reg(*dst), false);
                    let mask = if dst.width == 32 { u32::MAX } else { 255 };
                    let bit = if *count < dst.width {
                        let bit = if *left { dst.width - count } else { count - 1 };
                        format!("((a >> {bit}) & 1) != 0")
                    } else {
                        "false".into()
                    }; // Undefined CF cannot be read by proved code.
                    let op = if *left { "<<" } else { ">>" };
                    writeln!(
                        out,
                        "let a={a};let v=(a {op} {count})&{mask};cf={bit};zf=v==0;{}",
                        store(&Operand::Reg(*dst), "v")
                    )
                    .unwrap();
                }
            }
            Operation::ZeroExtend(dst, src) => {
                writeln!(out, "r[{}]={};", dst.index, value(src, false)).unwrap();
            }
            Operation::Set(_, dst) => {
                writeln!(out, "{}", store(&Operand::Reg(*dst), "u32::from(!zf)")).unwrap();
            }
            Operation::Not(dst) => {
                writeln!(out, "r[{}]=!r[{}];", dst.index, dst.index).unwrap();
            }
            Operation::ConditionalMove(cond, dst, src) => {
                let predicate = if *cond == Condition::Above {
                    "!cf&&!zf"
                } else if *cond == Condition::AboveEqual {
                    "!cf"
                } else {
                    "zf"
                };
                writeln!(out, "if {predicate} {{r[{}]=r[{}];}}", dst.index, src.index).unwrap();
            }
            Operation::Address(r, a) => {
                writeln!(out, "r[{}]={};", r.index, addr(a)).unwrap();
            }
            Operation::Increment(r) => {
                writeln!(
                    out,
                    "r[{}]=r[{}].wrapping_add(1);zf=r[{}]==0;",
                    r.index, r.index, r.index
                )
                .unwrap();
            }
            Operation::Decrement(r) => {
                writeln!(
                    out,
                    "r[{}]=r[{}].wrapping_sub(1);zf=r[{}]==0;",
                    r.index, r.index, r.index
                )
                .unwrap();
            }
            Operation::Negate(r) => {
                writeln!(
                    out,
                    "cf=r[{}]!=0;r[{}]=r[{}].wrapping_neg();zf=r[{}]==0;",
                    r.index, r.index, r.index, r.index
                )
                .unwrap();
            }
            Operation::Push(o) => {
                writeln!(out, "let v={};r[4]-=4;m.put(r[4],4,v);", value(o, false)).unwrap();
            }
            Operation::Pop(r) => {
                writeln!(out, "r[{}]=m.get(r[4],4);r[4]+=4;", r.index).unwrap();
            }
            Operation::Leave => {
                out.push_str("r[4]=r[5];r[5]=m.get(r[4],4);r[4]+=4;\n");
            }
            Operation::Call(_) => match bound.calls[&pc] {
                Function::ProcessHeap => out.push_str("r[0]=3;\n"),
                Function::HeapAlloc => out.push_str("assert_contract(m.get(r[4],4)==3);let flags=m.get(r[4]+4,4);let n=m.get(r[4]+8,4);r[0]=m.heap_alloc(flags,n,io.heap_available());r[4]+=12;\n"),
                Function::HeapReAlloc => out.push_str("assert_contract(m.get(r[4],4)==3);let flags=m.get(r[4]+4,4);let p=m.get(r[4]+8,4);let n=m.get(r[4]+12,4);r[0]=m.heap_resize(flags,p,n,io.heap_available());r[4]+=16;\n"),
                Function::HeapFree => out.push_str("assert_contract(m.get(r[4],4)==3);let flags=m.get(r[4]+4,4);let p=m.get(r[4]+8,4);r[0]=m.heap_free(flags,p);r[4]+=12;\n"),
                Function::StandardHandle => {
                    out.push_str("r[0]=io.standard(m.get(r[4],4));r[4]+=4;\n");
                }
                Function::LastError => {
                    out.push_str("r[0]=error;\n");
                }
                Function::Read | Function::Write => {
                    out.push_str("let h=m.get(r[4],4);let p=m.get(r[4]+4,4);let n=m.get(r[4]+8,4);let c=m.get(r[4]+12,4);assert_contract(m.get(r[4]+16,4)==0);m.pair(p,n,c);m.put(c,4,0);\n");
                    if bound.calls[&pc] == Function::Read {
                        out.push_str(
                            "m.invalidate(p,n);let result=io.read(h,m.destination(p,n));\n",
                        );
                    } else {
                        out.push_str("let result=io.write(h,m.source(p,n));\n");
                    }
                    out.push_str("match result{Ok(k)=>{assert_contract(k<=n as usize);m.put(c,4,k as u32);r[0]=1;");
                    if bound.calls[&pc] == Function::Read {
                        out.push_str("m.initialize(p,k as u32);");
                    }
                    out.push_str("},Err(e)=>{r[0]=0;error=e;}}r[4]+=20;\n");
                }
            },
            Operation::Return => {
                out.push_str("assert_contract(r[0]<=255);return r[0];\n");
            }
            _ => {}
        }
        match node.operation {
            Operation::Return => {}
            Operation::Branch(c, target) => {
                let other = *node
                    .successors
                    .iter()
                    .find(|&&n| n != target)
                    .unwrap_or(&target);
                let condition = match c {
                    Condition::Equal => "zf",
                    Condition::NotEqual => "!zf",
                    Condition::Below => "cf",
                    Condition::Above => "!cf&&!zf",
                    Condition::BelowEqual => "cf||zf",
                    Condition::AboveEqual => "!cf",
                };
                writeln!(out, "pc=if {condition}{{{target}}}else{{{other}}};").unwrap();
            }
            _ => {
                writeln!(out, "pc={};", node.successors[0]).unwrap();
            }
        }
        out.push_str("}\n");
    }
    out.push_str("_=>unreachable!(),}}}\nfn main(){let mut io=Native::new();std::process::exit(run(&mut io) as i32);}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_byte_alias_and_flag_preservation_vectors() {
        let mut programs = Vec::new();
        for lane in 0u8..8 {
            let reg = lane % 4;
            let shift = if lane < 4 { 0 } else { 8 };
            for (initial, byte, want) in [
                (
                    0x12345678u32,
                    0xa5u32,
                    if shift == 0 {
                        0x123456a5u32
                    } else {
                        0x1234a578
                    },
                ),
                (
                    0xffffffff,
                    0,
                    if shift == 0 { 0xffffff00 } else { 0xffff00ff },
                ),
            ] {
                let mut b = vec![0xb8 + reg];
                b.extend(initial.to_le_bytes());
                b.extend([0xb0 + lane, byte as u8, 0x8b, 0xc0 | reg, 0x3d]);
                b.extend(want.to_le_bytes());
                b.extend([0x0f, 0x95, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3]);
                programs.push((b, 0));
            }
            // SETNE preserves all other bytes and flags; both predicate values.
            for (a, b) in [(7u32, 7u32), (7, 8)] {
                let mut code = vec![0xb8];
                code.extend(a.to_le_bytes());
                code.push(0x3d);
                code.extend(b.to_le_bytes());
                code.push(0xb8 + reg);
                code.extend(0xaabbccddu32.to_le_bytes());
                code.extend([0x0f, 0x95, 0xc0 | lane, 0x8b, 0xc0 | reg, 0x3d]);
                let want = (0xaabbccddu32 & !(255 << shift)) | (u32::from(a != b) << shift);
                code.extend(want.to_le_bytes());
                code.extend([0x0f, 0x95, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3]);
                programs.push((code, 0));
            }
            for (a, b, result, carry) in [
                (255u8, 1u8, 0u32, true),
                (127, 1, 128, false),
                (0, 255, 255, false),
            ] {
                for observe_carry in [false, true] {
                    let mut code = vec![0xb8 + reg];
                    code.extend(0x12345678u32.to_le_bytes());
                    code.extend([0xb0 + lane, a, 0x80, 0xc0 | lane, b]);
                    code.extend([0x0f, 0xb6, 0xc0 | lane]); // Must preserve ADD's flags.
                    if observe_carry {
                        code.extend([0xb9, 7, 0, 0, 0, 0xb8, 3, 0, 0, 0, 0x0f, 0x43, 0xc1]);
                    }
                    code.push(0xc3);
                    programs.push((
                        code,
                        if observe_carry {
                            if carry {
                                3
                            } else {
                                7
                            }
                        } else {
                            result
                        },
                    ));
                }
            }
        }
        // Independently specified result and carry tables, including x86 count masking.
        for (opcode, modrm, count, input, want) in [
            (0xc0u8, 0xe0u8, 4u8, 0x12345681u32, 0x12345610u32),
            (0xc0, 0xe8, 7, 0xaabbccff, 0xaabbcc01),
            (0xc0, 0xe0, 8, 0x123456ff, 0x12345600),
            (0xc0, 0xec, 1, 0xaabb8102, 0xaabb4002),
            (0xc1, 0xe8, 31, 0x80000000, 1),
            (0xc1, 0xe0, 31, 3, 0x80000000),
            (0xc1, 0xe8, 32, 0x87654321, 0x87654321),
            (0xc1, 0xe0, 255, 2, 0),
        ] {
            let mut code = vec![0xb8];
            code.extend(input.to_le_bytes());
            code.extend([opcode, modrm, count, 0x3d]);
            code.extend(want.to_le_bytes());
            code.extend([0x0f, 0x95, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3]);
            programs.push((code, 0));
        }
        for (input, count, carry) in [
            (0x81u32, 1u8, true),
            (0x80, 1, false),
            (1, 31, false),
            (0x80000000, 31, false),
        ] {
            let mut code = vec![0xb8];
            code.extend(input.to_le_bytes());
            code.extend([
                0xc1, 0xe8, count, 0xb8, 3, 0, 0, 0, 0xb9, 7, 0, 0, 0, 0x0f, 0x43, 0xc1, 0xc3,
            ]);
            programs.push((code, if carry { 3 } else { 7 }));
        }
        for (a, b, want) in [
            (0x80000001u32, 0x40000002u32, 0xc0000003u32),
            (0, 0, 0),
            (0xffff0000, 0x0000ffff, u32::MAX),
        ] {
            let mut code = vec![0xb8];
            code.extend(a.to_le_bytes());
            code.push(0xb9);
            code.extend(b.to_le_bytes());
            code.extend([0x0b, 0xc1, 0x3d]);
            code.extend(want.to_le_bytes());
            code.extend([0x0f, 0x95, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3]);
            programs.push((code, 0));
        }
        // NOT preserves CF and ZF; memory MOVZX reads exactly one initialized byte.
        for a in [0u32, 1, u32::MAX, 0x80000000] {
            let mut code = vec![0xb8];
            code.extend(a.to_le_bytes());
            code.extend([0xf7, 0xd0, 0x3d]);
            code.extend((!a).to_le_bytes());
            code.extend([0x0f, 0x95, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3]);
            programs.push((code, 0));
        }
        for (b, z, c) in [(0u8, 0u32, 7u32), (1, 1, 3)] {
            let start = vec![
                0x31, 0xc0, 0x83, 0xf8, b, 0xb8, 0x78, 0x56, 0x34, 0x12, 0xf7, 0xd0,
            ];
            let mut code = start.clone();
            code.extend([0x0f, 0x95, 0xc1, 0x0f, 0xb6, 0xc1, 0xc3]);
            programs.push((code, z));
            let mut code = start;
            code.extend([0xb8, 3, 0, 0, 0, 0xb9, 7, 0, 0, 0, 0x0f, 0x43, 0xc1, 0xc3]);
            programs.push((code, c));
        }
        programs.push((
            vec![
                0x83, 0xec, 4, 0xc6, 0x44, 0x24, 2, 0xff, 0x0f, 0xb6, 0x44, 0x24, 2, 0x83, 0xc4, 4,
                0xc3,
            ],
            255,
        ));
        // Full-width column wrap near 2^32: expected steps to the next
        // four-column stop are specified independently of the lifted loop.
        for (column, steps) in [
            (0u32, 4u32),
            (1, 3),
            (2, 2),
            (3, 1),
            (0xfffffffc, 4),
            (0xfffffffd, 3),
            (0xfffffffe, 2),
            (u32::MAX, 1),
        ] {
            let mut code = vec![0xbb];
            code.extend(column.to_le_bytes());
            code.extend([
                0x31, 0xc0, 0x40, 0x8d, 0x53, 1, 0xf7, 0xd3, 0xf6, 0xc3, 3, 0x89, 0xd3, 0x75, 0xf3,
                0xc3,
            ]);
            programs.push((code, steps));
        }
        let dir = std::env::temp_dir().join(format!("w2l-lanes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut source = String::from("struct NoIo;\n");
        let mut checks = String::new();
        for (id, (code, expected)) in programs.iter().enumerate() {
            let bound = Bound {
                graph: super::super::graph::decode(code, 0, 0).unwrap(),
                calls: Default::default(),
                loads: Default::default(),
            };
            writeln!(source, "mod g{id} {{ {} }}", emit(&bound)).unwrap();
            writeln!(source,"impl g{id}::StreamIo for NoIo {{fn standard(&mut self,_:u32)->u32{{panic!()}} fn read(&mut self,_:u32,_:&mut[u8])->Result<usize,u32>{{panic!()}} fn write(&mut self,_:u32,_:&[u8])->Result<usize,u32>{{panic!()}}}}").unwrap();
            writeln!(
                checks,
                "assert_eq!(g{id}::run(&mut NoIo),{expected},\"vector {id}\");"
            )
            .unwrap();
        }
        writeln!(source, "fn main(){{{checks}}}").unwrap();
        std::fs::write(dir.join("vectors.rs"), source).unwrap();
        let compiled = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(dir.join("vectors.rs"))
            .arg("-o")
            .arg(dir.join("vectors"))
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let ran = std::process::Command::new(dir.join("vectors"))
            .output()
            .unwrap();
        assert!(
            ran.status.success(),
            "{}",
            String::from_utf8_lossy(&ran.stderr)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn unsigned_selection_and_extension_native_truth_tables() {
        let mut programs = Vec::new();
        // Concrete unsigned comparisons, including opposite signed ordering.
        for (a, b) in [
            (0u32, 0u32),
            (0, 1),
            (1, 0),
            (u32::MAX, 0),
            (0x80000000, 0x7fffffff),
            (0x7fffffff, 0x80000000),
        ] {
            for (dst, src) in [(0u8, 1u8), (2, 3), (6, 7)] {
                for observed in 0..3 {
                    let mut code = vec![0xb8];
                    code.extend(a.to_le_bytes());
                    code.push(0x3d);
                    code.extend(b.to_le_bytes());
                    code.push(0xb8 + dst);
                    code.extend(17u32.to_le_bytes());
                    code.push(0xb8 + src);
                    code.extend(213u32.to_le_bytes());
                    code.extend([0x0f, 0x47, 0xc0 | dst << 3 | src]);
                    let expected = if observed == 0 {
                        code.extend([0x8b, 0xc0 | dst, 0xc3]);
                        if a > b {
                            213
                        } else {
                            17
                        }
                    } else {
                        code.extend([
                            if observed == 1 { 0x72 } else { 0x74 },
                            6,
                            0xb8,
                            0,
                            0,
                            0,
                            0,
                            0xc3,
                            0xb8,
                            1,
                            0,
                            0,
                            0,
                            0xc3,
                        ]);
                        u32::from(if observed == 1 { a < b } else { a == b })
                    };
                    programs.push((code, expected));
                }
            }
        }
        for (input, expected) in [
            (0xffffff00u32, 0u32),
            (0x123456ff, 255),
            (0x80000080, 128),
            (0xabcdef01, 1),
        ] {
            for src in 0u8..4 {
                for dst in [0u8, 1, 2, 3, 5, 6, 7] {
                    let mut code = vec![0xb8 + src];
                    code.extend(input.to_le_bytes());
                    code.extend([0x0f, 0xb6, 0xc0 | dst << 3 | src, 0x8b, 0xc0 | dst, 0xc3]);
                    programs.push((code, expected));
                }
            }
        }
        let dir = std::env::temp_dir().join(format!("w2l-zext-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut source = String::from("struct NoIo;\n");
        let mut checks = String::new();
        for (id, (code, expected)) in programs.iter().enumerate() {
            let bound = Bound {
                graph: super::super::graph::decode(code, 0, 0).unwrap(),
                calls: Default::default(),
                loads: Default::default(),
            };
            writeln!(source, "mod g{id} {{ {} }}", emit(&bound)).unwrap();
            writeln!(source,"impl g{id}::StreamIo for NoIo {{fn standard(&mut self,_:u32)->u32{{panic!()}} fn read(&mut self,_:u32,_:&mut[u8])->Result<usize,u32>{{panic!()}} fn write(&mut self,_:u32,_:&[u8])->Result<usize,u32>{{panic!()}}}}").unwrap();
            writeln!(
                checks,
                "assert_eq!(g{id}::run(&mut NoIo),{expected},\"vector {id}\");"
            )
            .unwrap();
        }
        writeln!(source, "fn main(){{{checks}}}").unwrap();
        std::fs::write(dir.join("vectors.rs"), source).unwrap();
        let compiled = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(dir.join("vectors.rs"))
            .arg("-o")
            .arg(dir.join("vectors"))
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let ran = std::process::Command::new(dir.join("vectors"))
            .output()
            .unwrap();
        assert!(
            ran.status.success(),
            "{}",
            String::from_utf8_lossy(&ran.stderr)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn independent_native_wrap_and_carry_vectors() {
        // Literal architectural expectations, exercised through decoded IR and
        // emitted native instructions. This isolates emission from admission.
        let vectors = [
            (0u8, 0u32, 0u32, false, 0u32, false),
            (0, 1, 0, false, 0xffffffff, true),
            (0, 0x80000000, 0, false, 0x80000000, true),
            (0, 0xffffffff, 0, false, 1, true),
            (1, 0, 0, false, 0, false),
            (1, 0, 0, true, 0xffffffff, true),
            (1, 0, 0xffffffff, true, 0, true),
            (1, 0xffffffff, 0xffffffff, true, 0xffffffff, true),
            (1, 0x80000000, 1, false, 0x7fffffff, false),
            (2, 1, 0, true, 0, true),
            (2, 0, 0, false, 0xffffffff, false),
            (3, 7, 42, false, 42, false),
            (3, 7, 42, true, 7, true),
        ];
        let dir = std::env::temp_dir().join(format!(
            "w2l-scalar-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let mut source = String::new();
        let mut checks = String::new();
        let mut id = 0;
        for (op, a, b, carry, result, out_carry) in vectors {
            for flags in 0..3 {
                let mut code = vec![0x33, 0xd2, 0x83, 0xfa, u8::from(carry), 0xb8];
                code.extend(a.to_le_bytes());
                code.push(0xbb);
                code.extend(b.to_le_bytes());
                code.extend(match op {
                    0 => vec![0xf7, 0xd8],
                    1 => vec![0x1b, 0xc3],
                    2 => vec![0x48],
                    _ => vec![0x0f, 0x44, 0xc3],
                });
                let expected = if flags == 1 {
                    code.extend([0x72, 6]);
                    u32::from(out_carry)
                } else if flags == 2 {
                    code.extend([0x74, 6]);
                    u32::from(if op == 3 { !carry } else { result == 0 })
                } else {
                    code.push(0x3d);
                    code.extend(result.to_le_bytes());
                    code.extend([0x75, 6]);
                    0
                };
                code.extend([0xb8, 0, 0, 0, 0, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3]);
                let bound = Bound {
                    graph: super::super::graph::decode(&code, 0, 0).unwrap(),
                    calls: Default::default(),
                    loads: Default::default(),
                };
                writeln!(source, "mod g{id} {{ {} }}", emit(&bound)).unwrap();
                writeln!(source,"impl g{id}::StreamIo for NoIo {{ fn standard(&mut self,_:u32)->u32{{panic!()}} fn read(&mut self,_:u32,_:&mut[u8])->Result<usize,u32>{{panic!()}} fn write(&mut self,_:u32,_:&[u8])->Result<usize,u32>{{panic!()}} }}").unwrap();
                writeln!(
                    checks,
                    "assert_eq!(g{id}::run(&mut NoIo),{expected},\"vector {id}\");"
                )
                .unwrap();
                id += 1;
            }
        }
        writeln!(source, "struct NoIo;fn main(){{{checks}}}").unwrap();
        let rust = dir.join("vectors.rs");
        let exe = dir.join("vectors");
        std::fs::write(&rust, source).unwrap();
        let compiled = std::process::Command::new("rustc")
            .args(["--edition=2021"])
            .arg(&rust)
            .arg("-o")
            .arg(&exe)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let ran = std::process::Command::new(&exe).output().unwrap();
        assert!(
            ran.status.success(),
            "{}",
            String::from_utf8_lossy(&ran.stderr)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
