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
                format!("(r[{}]&255)", r.index)
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
                format!("r[{}]=(r[{}]&!255)|(({v})&255);", r.index, r.index)
            } else {
                format!("r[{}]={v};", r.index)
            }
        }
        Operand::Memory(a, w) => format!("m.put({}, {}, {v});", addr(a), w / 8),
        _ => unreachable!(),
    }
}
pub(super) fn emit(bound: &Bound) -> String {
    let mut out = include_str!("runtime.txt").to_string();
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
                            index: 4,
                            width: 32
                        })
                    ) && *op == Binary::Sub
                    {
                        writeln!(out, "m.invalidate(r[4],b);").unwrap();
                    }
                }
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
