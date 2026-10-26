//! Private bounded environment-input admission. No observed host input participates.
use super::*;
use iced_x86::{Decoder, DecoderOptions};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
mod proof;
use proof::{prove, Proven};
#[derive(Clone, Copy, Debug)]
enum Op {
    Allocate,
    Buffer,
    Push(u32),
    PushEax,
    Name,
    Acquire,
    Move(usize, usize),
    Mov(usize, u32),
    Test(usize),
    Compare(usize, u8, u32),
    Load(usize, u8),
    Save,
    Restore,
    Cleanup,
    Ret,
    Lea(usize, usize, usize, u32, u32),
    Scaled(usize, usize, u32, u32),
    ZeroExtend(usize, usize),
    Arithmetic(usize, u32, bool),
    Binary(usize, usize, bool),
    Call(u32),
    BufferAt(u8),
    Argument(usize, u8),
    CompareArgument(u8, u32),
    ReadWord(usize, usize, u8),
    Branch(Condition, u32),
}
#[derive(Clone, Copy, Debug)]
enum Condition {
    Ne,
    Be,
    A,
}
type Graph = BTreeMap<u32, (Op, u32)>;
fn decode(image: &Candidate<'_>) -> Result<Graph, String> {
    need(image.api == Api::Environment, "input: import identity")?;
    let code = image
        .sections
        .iter()
        .find(|s| s.flags == CODE)
        .ok_or("input: code")?;
    need(
        image.entry >= code.rva
            && image.entry < end(code.rva, code.virtual_size)?
            && code.virtual_size <= 512,
        "input: complete code extent",
    )?;
    let finish = end(code.rva, code.virtual_size)?;
    let mut pending = vec![image.entry];
    let mut graph = Graph::new();
    let mut occupied = BTreeSet::new();
    let mut bound = BTreeSet::new();
    while let Some(pc) = pending.pop() {
        if graph.contains_key(&pc) {
            continue;
        }
        need(
            graph.len() < 128 && pc < finish,
            "input: instruction/resource bounds",
        )?;
        let at = image.location(pc, 1, CODE)?;
        let bytes = range(image.bytes, at, (finish - pc) as usize)?;
        let mut decoder = Decoder::with_ip(32, bytes, u64::from(pc), DecoderOptions::NONE);
        let ins = decoder.decode();
        need(!ins.is_invalid(), "input: malformed instruction")?;
        let b = range(bytes, 0, ins.len())?;
        let next = pc
            .checked_add(ins.len() as u32)
            .ok_or("input: PC overflow")?;
        let op = match b {
            [0x83, 0xec, 8] => Op::Allocate,
            [0x8d, 4, 0x24] => Op::Buffer,
            [0x6a, n] => Op::Push(*n as i8 as i32 as u32),
            [0x50] => Op::PushEax,
            [0x68, _, _, _, _] => {
                let site = pc + 1;
                let rva = *image.pointers.get(&site).ok_or("input: name relocation")?;
                need(
                    u32_at(b, 1)?.checked_sub(image.base) == Some(rva),
                    "input: name provenance",
                )?;
                image.immutable(rva, 20)?;
                let raw = image.location(rva, 20, DATA)?;
                need(
                    range(image.bytes, raw, 20)? == b"W\0\x32\0L\0_\0I\0N\0P\0U\0T\0\0\0",
                    "input: literal name",
                )?;
                bound.insert(site);
                Op::Name
            }
            [0xff, 0x15, _, _, _, _] => {
                need(
                    image.pointers.get(&(pc + 2)) == Some(&image.iat)
                        && u32_at(b, 2)?.checked_sub(image.base) == Some(image.iat),
                    "input: call provenance",
                )?;
                bound.insert(pc + 2);
                Op::Acquire
            }
            [0x3d, _, _, _, _] => Op::Compare(0, 32, u32_at(b, 1)?),
            [0x83, 0xfa, n] => Op::Compare(2, 32, *n as i8 as i32 as u32),
            [0x8b, 0x4c, 0x24, 4] => Op::Argument(1, 4),
            [0x0f, 0xb7, 0x01] => Op::ReadWord(0, 1, 0),
            [0x0f, 0xb7, 0x51, 2] => Op::ReadWord(2, 1, 2),
            [0x8d, 0x04, 0x4a] => Op::Lea(0, 2, 1, 2, 0),
            [0x8d, 0x04, 0x45, _, _, _, _] => Op::Scaled(0, 0, 2, u32_at(b, 3)?),
            [0x8b, 0xc8] => Op::Move(1, 0),
            [0x8b, 0xc2] => Op::Move(0, 2),
            [0xb8, _, _, _, _] => Op::Mov(0, u32_at(b, 1)?),
            [0x85, 0xc9] => Op::Test(1),
            [0x85, 0xc0] => Op::Test(0),
            [0x83, 0xf9, n] => Op::Compare(1, 32, *n as i8 as i32 as u32),
            [0x66, 0x83, 0xf8, n] => Op::Compare(0, 16, u32::from(*n as i8 as i16 as u16)),
            [0x8b, 0x14, 0x24] => Op::Load(2, 0),
            [0x8b, 0x74, 0x24, n] => Op::Load(3, *n),
            [0x56] => Op::Save,
            [0x5e] => Op::Restore,
            [0x83, 0xc4, 8] => Op::Cleanup,
            [0xc3] => Op::Ret,
            [0x8d, 0x42, n] => Op::Lea(0, 2, 2, 0, *n as i8 as i32 as u32),
            [0x8d, 0x46, n] => Op::Lea(0, 3, 3, 0, *n as i8 as i32 as u32),
            [0x8d, 0x14, 0x92] => Op::Lea(2, 2, 2, 4, 0),
            [0x8d, 0x52, n] => Op::Lea(2, 2, 2, 0, *n as i8 as i32 as u32),
            [0x8d, 0x14, 0x50] => Op::Lea(2, 0, 2, 2, 0),
            [0x0f, 0xb7, 0xd2] => Op::ZeroExtend(2, 2),
            [0x0f, 0xb7, 0xc6] => Op::ZeroExtend(0, 3),
            [0x83, 0xea, n] => Op::Arithmetic(2, *n as i8 as i32 as u32, true),
            [0x83, 0xf8, n] => Op::Compare(0, 32, *n as i8 as i32 as u32),
            [0x8b, 0x54, 0x24, 2] => Op::Load(2, 2),
            [0x8b, 0x0c, 0x24] => Op::Load(1, 0),
            [0x8d, 0x41, n] => Op::Lea(0, 1, 1, 0, *n as i8 as i32 as u32),
            [0x0f, 0xb7, 0xc1] => Op::ZeroExtend(0, 1),
            [0x0f, 0xb7, 0xc2] => Op::ZeroExtend(0, 2),
            [0x8d, 0x0c, 0x80] => Op::Lea(1, 0, 0, 4, 0),
            [0x8d, 0x04, 0x48] => Op::Lea(0, 0, 1, 2, 0),
            [0x05, _, _, _, _] => Op::Arithmetic(0, u32_at(b, 1)?, false),
            [0x83, 0xe8, n] => Op::Arithmetic(0, *n as i8 as i32 as u32, true),
            [0x83, 0xc2, n] => Op::Arithmetic(2, *n as i8 as i32 as u32, false),
            [0x83, 0xc1, n] => Op::Arithmetic(1, *n as i8 as i32 as u32, false),
            [0x0f, 0xaf, 0xd2] => Op::Binary(2, 2, true),
            [0x0f, 0xaf, 0xc9] => Op::Binary(1, 1, true),
            [0x8b, 0x4c, 0x24, 2] => Op::Load(1, 2),
            [0x0f, 0xb7, 0xc9] => Op::ZeroExtend(1, 1),
            [0x03, 0xd1] => Op::Binary(2, 1, false),
            [0x8d, 0x44, 0x24, 4] => Op::BufferAt(4),
            [0x8b, 0x54, 0x24, 4] => Op::Argument(2, 4),
            [0x83, 0x7c, 0x24, 8, n] => Op::CompareArgument(8, *n as i8 as i32 as u32),
            [0x0f, 0xb7, 0x0a] => Op::ReadWord(1, 2, 0),
            [0x0f, 0xb7, 0x52, 2] => Op::ReadWord(2, 2, 2),
            [0x83, 0xe9, n] => Op::Arithmetic(1, *n as i8 as i32 as u32, true),
            [0x8d, 0x0c, 0x89] => Op::Lea(1, 1, 1, 4, 0),
            [0x8d, 0x49, n] => Op::Lea(1, 1, 1, 0, *n as i8 as i32 as u32),
            [0x8d, 0x0c, 0x48] => Op::Lea(1, 0, 1, 2, 0),
            [0x8b, 0xc1] => Op::Move(0, 1),
            [0xe8, _, _, _, _] => {
                let t =
                    u32::try_from(ins.near_branch_target()).map_err(|_| "input: call overflow")?;
                need(t >= code.rva && t < finish, "input: call bounds")?;
                Op::Call(t)
            }
            [opcode @ (0x75..=0x77), _] => {
                let target = u32::try_from(ins.near_branch_target())
                    .map_err(|_| "input: branch overflow")?;
                need(
                    target > pc && target < finish,
                    "input: unproved cycle/target",
                )?;
                Op::Branch(
                    match opcode {
                        0x75 => Condition::Ne,
                        0x76 => Condition::Be,
                        _ => Condition::A,
                    },
                    target,
                )
            }
            _ => return Err(format!("input: unsupported instruction at {pc:x}")),
        };
        for byte in pc..next {
            need(occupied.insert(byte), "input: overlapping instructions")?;
        }
        if let Op::Branch(_, target) | Op::Call(target) = op {
            pending.push(target);
        }
        if !matches!(op, Op::Ret) {
            pending.push(next);
        }
        graph.insert(pc, (op, next));
    }
    need(
        (code.rva..finish).all(|pc| {
            occupied.contains(&pc)
                || image
                    .location(pc, 1, CODE)
                    .ok()
                    .and_then(|at| image.bytes.get(at))
                    == Some(&0xcc)
        }),
        "input: unaccounted code bytes",
    )?;
    need(
        bound == image.pointers.keys().copied().collect(),
        "input: unbound relocation",
    )?;
    validate_calls(&graph, image.entry)?;
    Ok(graph)
}
fn validate_calls(graph: &Graph, entry: u32) -> Result<(), String> {
    let mut pending = vec![(entry, vec![entry], Vec::<u32>::new())];
    let mut steps = 0;
    while let Some((pc, mut targets, mut returns)) = pending.pop() {
        steps += 1;
        need(steps <= 4096, "input: call graph budget")?;
        let &(op, next) = graph.get(&pc).ok_or("input: missing control target")?;
        match op {
            Op::Call(t) => {
                need(
                    targets.len() <= 4 && !targets.contains(&t),
                    "input: call cycle/depth",
                )?;
                targets.push(t);
                returns.push(next);
                pending.push((t, targets, returns));
            }
            Op::Ret => {
                if let Some(t) = returns.pop() {
                    targets.pop();
                    pending.push((t, targets, returns));
                }
            }
            Op::Branch(_, t) => {
                pending.push((t, targets.clone(), returns.clone()));
                pending.push((next, targets, returns));
            }
            _ => pending.push((next, targets, returns)),
        }
    }
    Ok(())
}
pub(super) fn translate(image: &Candidate<'_>) -> Result<String, String> {
    let graph = decode(image)?;
    Ok(prove(graph, image.entry)?.emit())
}
impl Proven {
    fn emit(self) -> String {
        let mut s = String::from("// SUB552 native input subset. Genuine procfs; stable initial ASCII-key environment;\n// valid stack/no fault; strict UTF8 target <=64 UTF16 units. Host failures exit203.\n#![allow(dead_code,unused_variables,unused_assignments)]\nmod acquisition {\n");
        s.push_str(include_str!("input/acquisition.rs"));
        s.push_str("}\nstruct Machine { r:[u32;4], saved:u32, stack:Vec<u32>, bytes:[u8;8], cf:bool,zf:bool }\n");
        // Direct Rust functions for the acyclic graph. No runtime opcode/PC decoder.
        for (&pc, &(op, next)) in &self.graph {
            writeln!(s, "fn b{pc}(s:&mut Machine)->u32 {{").unwrap();
            match op {
                Op::Allocate=>s.push_str("s.stack.extend([0,0]);\n"),
                Op::Buffer|Op::BufferAt(_)=>s.push_str("s.r[0]=0;\n"),
                Op::Push(n)=>writeln!(s,"s.stack.push({n});").unwrap(),
                Op::PushEax=>s.push_str("s.stack.push(s.r[0]);\n"),
                Op::Name=>s.push_str("s.stack.push(0);\n"),
                Op::Cleanup=>s.push_str("s.stack.truncate(s.stack.len()-2);\n"),
                Op::Call(t)=>writeln!(s,"s.stack.push(0);s.r[0]=b{t}(s);s.stack.pop();").unwrap(),
                Op::Argument(d,o)=>writeln!(s,"s.r[{d}]=s.stack[s.stack.len()-1-{}];",o/4).unwrap(),
                Op::CompareArgument(o,v)=>writeln!(s,"let v=s.stack[s.stack.len()-1-{}];s.cf=v<{v};s.zf=v=={v};",o/4).unwrap(),
                Op::ReadWord(d,_,_)=>{let o=self.loads[&pc];writeln!(s,"s.r[{d}]=u16::from_le_bytes(s.bytes[{o}..{}].try_into().unwrap()) as u32;",o+2).unwrap();},
                Op::Acquire => s.push_str("s.stack.truncate(s.stack.len()-3);let a=match acquisition::acquire(){Ok(v)=>v.project(),Err(_)=>return 203};s.r[0]=a.returned;s.r[1]=0;s.r[2]=0;for (i,v) in a.bytes.into_iter().enumerate(){if let Some(v)=v{s.bytes[i]=v;}}\n"),
                Op::Move(d,v) => writeln!(s,"s.r[{d}]=s.r[{v}];").unwrap(),
                Op::Mov(r,v) => writeln!(s,"s.r[{r}]={v};").unwrap(),
                Op::Test(r) => writeln!(s,"s.cf=false;s.zf=s.r[{r}]==0;").unwrap(),
                Op::Compare(r,width,v) => {
                    let mask=if width==16{65535}else{u32::MAX};
                    writeln!(s,"let v=s.r[{r}] & {mask};s.cf=v<{v};s.zf=v=={v};").unwrap();
                },
                Op::Load(d,_) => {
                    let offset=self.loads[&pc];
                    writeln!(s,"s.r[{d}]=u32::from_le_bytes(s.bytes[{offset}..{}].try_into().unwrap());",offset+4).unwrap();
                }
                Op::Save => s.push_str("s.saved=s.r[3];s.stack.push(s.r[3]);\n"),
                Op::Restore => s.push_str("s.r[3]=s.saved;s.stack.pop();\n"),
                Op::Ret => {s.push_str("s.r[0]}\n");continue;}
                Op::Lea(d,a,b,k,c) => writeln!(s,"s.r[{d}]=s.r[{a}].wrapping_add(s.r[{b}].wrapping_mul({k})).wrapping_add({c});").unwrap(),
                Op::Scaled(d,v,k,c) => writeln!(s,"s.r[{d}]=s.r[{v}].wrapping_mul({k}).wrapping_add({c});").unwrap(),
                Op::ZeroExtend(d,v) => writeln!(s,"s.r[{d}]=s.r[{v}] & 65535;").unwrap(),
                Op::Arithmetic(r,v,subtract) => {
                    let method=if subtract{"overflowing_sub"}else{"overflowing_add"};
                    writeln!(s,"let (v,c)=s.r[{r}].{method}({v});s.r[{r}]=v;s.cf=c;s.zf=v==0;").unwrap();
                },
                Op::Binary(d,v,multiply)=>{
                    let method=if multiply {"wrapping_mul"} else {"wrapping_add"};
                    writeln!(s,"s.r[{d}]=s.r[{d}].{method}(s.r[{v}]);").unwrap();
                },
                Op::Branch(c,t) => {
                    let condition=match c {Condition::Ne=>"!s.zf",Condition::Be=>"s.cf||s.zf",Condition::A=>"!s.cf&&!s.zf"};
                    writeln!(s,"if {condition} {{ b{t}(s) }} else {{ b{next}(s) }} }}").unwrap();continue;
                }
            }
            writeln!(s, "b{next}(s)}}").unwrap();
        }
        writeln!(s,"fn main(){{let mut s=Machine{{r:[0;4],saved:0,stack:vec![0],bytes:[0;8],cf:false,zf:false}};std::process::exit(b{}(&mut s) as i32);}}",self.entry).unwrap();
        s
    }
}
#[cfg(test)]
mod tests;
