//! Private bounded environment-input admission. No observed host input participates.
use super::*;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
const MAX_ACTIVATIONS: usize = 4;
mod proof;
use proof::{prove, Proven};
#[derive(Clone, Copy, Debug)]
enum Op {
    Allocate,
    AllocateN(u8),
    PushReg(usize),
    PopReg(usize),
    Anchor,
    Leave,
    Address(usize, bool, i32),
    StackRead(usize, bool, i32, u8),
    StackCompare(bool, i32, u32),
    CleanupN(u8),
    CompareRegs(usize, usize),
    Multiply(usize, usize, u32),
    Select(Condition, usize, usize),
    Jump(u32),
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
    Eq,
    B,
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
                    target >= code.rva && target < finish,
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
            _ => normalize(&ins, b)
                .map_err(|e| format!("input: unsupported instruction at {pc:x}: {e}"))?,
        };
        for byte in pc..next {
            need(occupied.insert(byte), "input: overlapping instructions")?;
        }
        if let Op::Branch(_, target) | Op::Call(target) | Op::Jump(target) = op {
            pending.push(target);
        }
        if !matches!(op, Op::Ret | Op::Jump(_)) {
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
// Operand normalization is bounded by encodings and width, not artifact identity.
// Register numbering is internal; ESP is only an owned stack coordinate.
fn reg(r: Register) -> Result<usize, String> {
    match r {
        Register::EAX => Ok(0),
        Register::ECX => Ok(1),
        Register::EDX => Ok(2),
        Register::ESI => Ok(3),
        Register::EDI => Ok(4),
        Register::EBP => Ok(5),
        _ => Err("unsupported register/width".into()),
    }
}
fn normalize(i: &Instruction, b: &[u8]) -> Result<Op, String> {
    // No prefixes: the old exact 66 comparison remains separately admitted.
    need(
        !b.is_empty()
            && !matches!(
                b[0],
                0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3
            ),
        "prefix",
    )?;
    let rr = || -> Result<(usize, usize), String> {
        need(
            i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Register,
            "register operands",
        )?;
        Ok((reg(i.op0_register())?, reg(i.op1_register())?))
    };
    let mem = || -> Result<(Register, i32), String> {
        need(
            i.memory_index() == Register::None
                && i.memory_segment()
                    == if i.memory_base() == Register::EBP || i.memory_base() == Register::ESP {
                        Register::SS
                    } else {
                        Register::DS
                    },
            "address form",
        )?;
        Ok((i.memory_base(), i.memory_displacement64() as u32 as i32))
    };
    let imm = || -> Result<u32, String> {
        match i.op1_kind() {
            OpKind::Immediate8to32 => Ok(i.immediate8to32() as u32),
            OpKind::Immediate32 => Ok(i.immediate32()),
            _ => Err("immediate width".into()),
        }
    };
    match i.mnemonic() {
        Mnemonic::Push if b.len() == 1 => Ok(Op::PushReg(reg(i.op0_register())?)),
        Mnemonic::Pop if b.len() == 1 => Ok(Op::PopReg(reg(i.op0_register())?)),
        Mnemonic::Leave if b == [0xc9] => Ok(Op::Leave),
        Mnemonic::Mov if b == [0x8b, 0xec] => Ok(Op::Anchor),
        Mnemonic::Mov if i.op1_kind() == OpKind::Memory => {
            let (base, off) = mem()?;
            need(
                matches!(base, Register::ESP | Register::EBP),
                "stack source",
            )?;
            Ok(Op::StackRead(
                reg(i.op0_register())?,
                base == Register::EBP,
                off,
                4,
            ))
        }
        Mnemonic::Mov if i.op1_kind() == OpKind::Immediate32 => {
            Ok(Op::Mov(reg(i.op0_register())?, imm()?))
        }
        Mnemonic::Mov => {
            let (d, r) = rr()?;
            Ok(Op::Move(d, r))
        }
        Mnemonic::Movzx if i.op1_kind() == OpKind::Memory => {
            need(b.starts_with(&[0x0f, 0xb7]), "WORD width")?;
            let (base, off) = mem()?;
            let d = reg(i.op0_register())?;
            if matches!(base, Register::ESP | Register::EBP) {
                Ok(Op::StackRead(d, base == Register::EBP, off, 2))
            } else {
                need((0..=8).contains(&off), "borrow displacement")?;
                Ok(Op::ReadWord(d, reg(base)?, off as u8))
            }
        }
        Mnemonic::Lea => {
            let d = reg(i.op0_register())?;
            let base = i.memory_base();
            let index = i.memory_index();
            let off = i.memory_displacement64() as u32;
            if matches!(base, Register::ESP | Register::EBP) {
                need(index == Register::None, "stack address index")?;
                Ok(Op::Address(d, base == Register::EBP, off as i32))
            } else if base == Register::None {
                Ok(Op::Scaled(d, reg(index)?, i.memory_index_scale(), off))
            } else {
                let a = reg(base)?;
                let (v, k) = if index == Register::None {
                    (a, 0)
                } else {
                    (reg(index)?, i.memory_index_scale())
                };
                Ok(Op::Lea(d, a, v, k, off))
            }
        }
        Mnemonic::Add | Mnemonic::Sub if i.op0_register() == Register::ESP => {
            let n = imm()?;
            need(n > 0 && n <= 12 && n % 4 == 0, "stack amount")?;
            Ok(if i.mnemonic() == Mnemonic::Add {
                Op::CleanupN(n as u8)
            } else {
                Op::AllocateN(n as u8)
            })
        }
        Mnemonic::Add if i.op1_kind() == OpKind::Register => {
            let (d, r) = rr()?;
            Ok(Op::Binary(d, r, false))
        }
        Mnemonic::Add | Mnemonic::Sub => Ok(Op::Arithmetic(
            reg(i.op0_register())?,
            imm()?,
            i.mnemonic() == Mnemonic::Sub,
        )),
        Mnemonic::Cmp if i.op0_kind() == OpKind::Memory => {
            let (base, off) = mem()?;
            need(
                matches!(base, Register::ESP | Register::EBP),
                "stack compare",
            )?;
            Ok(Op::StackCompare(base == Register::EBP, off, imm()?))
        }
        Mnemonic::Cmp if i.op1_kind() == OpKind::Register => {
            let (d, r) = rr()?;
            Ok(Op::CompareRegs(d, r))
        }
        Mnemonic::Cmp => Ok(Op::Compare(reg(i.op0_register())?, 32, imm()?)),
        Mnemonic::Test => {
            let (d, r) = rr()?;
            need(d == r, "TEST form")?;
            Ok(Op::Test(d))
        }
        Mnemonic::Imul if i.op_count() == 3 => {
            need(
                i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Register,
                "multiply operands",
            )?;
            let n = match i.op2_kind() {
                OpKind::Immediate8to32 => i.immediate8to32() as u32,
                OpKind::Immediate32 => i.immediate32(),
                _ => return Err("multiply width".into()),
            };
            Ok(Op::Multiply(
                reg(i.op0_register())?,
                reg(i.op1_register())?,
                n,
            ))
        }
        Mnemonic::Cmove | Mnemonic::Cmovbe => {
            let (d, r) = rr()?;
            Ok(Op::Select(
                if i.mnemonic() == Mnemonic::Cmove {
                    Condition::Eq
                } else {
                    Condition::Be
                },
                d,
                r,
            ))
        }
        Mnemonic::Je | Mnemonic::Jb | Mnemonic::Jmp if i.op0_kind() == OpKind::NearBranch32 => {
            let t = u32::try_from(i.near_branch_target()).map_err(|_| "target overflow")?;
            Ok(match i.mnemonic() {
                Mnemonic::Je => Op::Branch(Condition::Eq, t),
                Mnemonic::Jb => Op::Branch(Condition::B, t),
                _ => Op::Jump(t),
            })
        }
        _ => Err("operand policy".into()),
    }
}
fn validate_calls(graph: &Graph, entry: u32) -> Result<(), String> {
    use super::control::{Edge, Error};
    super::control::validate(entry, MAX_ACTIVATIONS, 4096, |pc| {
        graph.get(&pc).map(|&(op, next)| match op {
            Op::Call(target) => Edge::Call { target, next },
            Op::Ret => Edge::Return,
            Op::Branch(_, target) => Edge::Branch(target, next),
            Op::Jump(target) => Edge::Next(target),
            _ => Edge::Next(next),
        })
    })
    .map_err(|e| {
        match e {
            Error::Cycle => "input: control cycle",
            Error::Budget => "input: call graph budget",
            Error::MissingTarget => "input: missing control target",
            Error::RecursionOrDepth => "input: call cycle/depth",
        }
        .into()
    })
}
pub(super) fn translate(image: &Candidate<'_>) -> Result<String, String> {
    let graph = decode(image)?;
    Ok(prove(graph, image.entry)?.emit())
}
fn condition(c: Condition) -> &'static str {
    match c {
        Condition::Ne => "!s.zf",
        Condition::Eq => "s.zf",
        Condition::B => "s.cf",
        Condition::Be => "s.cf||s.zf",
        Condition::A => "!s.cf&&!s.zf",
    }
}
impl Proven {
    fn emit(self) -> String {
        let mut s = String::from("// Bounded native input composition subset. Genuine procfs; stable initial ASCII-key environment;\n// valid stack/no fault; strict UTF8 target <=64 UTF16 units. Host failures exit203.\n#![allow(dead_code,unused_variables,unused_assignments)]\nmod acquisition {\n");
        s.push_str(include_str!("input/acquisition.rs"));
        s.push_str(
            "}\nstruct Machine { r:[u32;6], stack:Vec<u32>, bytes:[u8;12], cf:bool,zf:bool }\n",
        );
        writeln!(s, "const MAX_ACTIVATIONS:usize={MAX_ACTIVATIONS};").unwrap();
        s.push_str("mod activation {\n");
        s.push_str(include_str!("activation.rs"));
        s.push_str("\n}\n");
        s.push_str(include_str!("input/continuation.txt"));
        // Each compiled block returns an explicit guest control effect.
        for (&pc, &(op, next)) in &self.graph {
            writeln!(s, "fn b{pc}(s:&mut Machine)->Flow {{").unwrap();
            match op {
                Op::AllocateN(n)=>writeln!(s,"s.stack.extend([0;{}]);",n/4).unwrap(),
                Op::PushReg(r)=>writeln!(s,"s.stack.push(s.r[{r}]);").unwrap(),
                Op::PopReg(r)=>writeln!(s,"s.r[{r}]=s.stack.pop().unwrap();").unwrap(),
                Op::Anchor=>s.push_str("s.r[5]=s.stack.len() as u32;\n"),
                Op::Leave=>s.push_str("s.stack.truncate(s.r[5] as usize);s.r[5]=s.stack.pop().unwrap();\n"),
                Op::Address(d,_,_)=>writeln!(s,"s.r[{d}]={};",self.addresses[&pc]).unwrap(),
                Op::StackRead(d,frame,off,width)=>{
                    match self.stack_reads[&pc] {
                        Some(o)=>{let ty=if width==2{"u16"}else{"u32"};writeln!(s,"s.r[{d}]={ty}::from_le_bytes(s.bytes[{o}..{}].try_into().unwrap()) as u32;",o+width).unwrap();},
                        None=>{let base=if frame{"s.r[5] as i64"}else{"s.stack.len() as i64"};writeln!(s,"s.r[{d}]=s.stack[({base}-1-({off}i64/4)) as usize];").unwrap();}
                    }
                },
                Op::StackCompare(frame,off,k)=>{let base=if frame{"s.r[5] as i64"}else{"s.stack.len() as i64"};writeln!(s,"let v=s.stack[({base}-1-({off}i64/4)) as usize];s.cf=v<{k};s.zf=v=={k};").unwrap();},
                Op::CleanupN(n)=>writeln!(s,"s.stack.truncate(s.stack.len()-{});",n/4).unwrap(),
                Op::CompareRegs(a,b)=>writeln!(s,"s.cf=s.r[{a}]<s.r[{b}];s.zf=s.r[{a}]==s.r[{b}];").unwrap(),
                Op::Multiply(d,r,k)=>writeln!(s,"s.r[{d}]=s.r[{r}].wrapping_mul({k});").unwrap(),
                Op::Select(c,d,r)=>writeln!(s,"if {} {{s.r[{d}]=s.r[{r}];}}",condition(c)).unwrap(),
                Op::Jump(t)=>{writeln!(s,"Flow::Next({t})}}").unwrap();continue;},
                Op::Allocate=>s.push_str("s.stack.extend([0,0]);\n"),
                Op::Buffer|Op::BufferAt(_)=>writeln!(s,"s.r[0]={};",self.addresses[&pc]).unwrap(),
                Op::Push(n)=>writeln!(s,"s.stack.push({n});").unwrap(),
                Op::PushEax=>s.push_str("s.stack.push(s.r[0]);\n"),
                Op::Name=>s.push_str("s.stack.push(0);\n"),
                Op::Cleanup=>s.push_str("s.stack.truncate(s.stack.len()-2);\n"),
                Op::Call(t)=>{writeln!(s,"Flow::Call{{target:{t},next:{next}}}}}").unwrap();continue;},
                Op::Argument(d,o)=>writeln!(s,"s.r[{d}]=s.stack[s.stack.len()-1-{}];",o/4).unwrap(),
                Op::CompareArgument(o,v)=>writeln!(s,"let v=s.stack[s.stack.len()-1-{}];s.cf=v<{v};s.zf=v=={v};",o/4).unwrap(),
                Op::ReadWord(d,r,o)=>writeln!(s,"let o=s.r[{r}] as usize+{o};s.r[{d}]=u16::from_le_bytes(s.bytes[o..o+2].try_into().unwrap()) as u32;").unwrap(),
                Op::Acquire => s.push_str(&"s.stack.truncate(s.stack.len()-3);let a=match acquisition::acquire(){Ok(v)=>v.project_capacity(CAPACITY).unwrap(),Err(_)=>return Flow::Terminal(203)};s.r[0]=a.returned;s.r[1]=0;s.r[2]=0;for (i,v) in a.bytes.into_iter().enumerate(){if let Some(v)=v{s.bytes[i]=v;}}\n".replace("CAPACITY",&self.capacity.to_string())),
                Op::Move(d,v) => writeln!(s,"s.r[{d}]=s.r[{v}];").unwrap(),
                Op::Mov(r,v) => writeln!(s,"s.r[{r}]={v};").unwrap(),
                Op::Test(r) => writeln!(s,"s.cf=false;s.zf=s.r[{r}]==0;").unwrap(),
                Op::Compare(r,width,v) => {
                    let mask=if width==16{65535}else{u32::MAX};
                    writeln!(s,"let v=s.r[{r}] & {mask};s.cf=v<{v};s.zf=v=={v};").unwrap();
                },
                Op::Load(d,_) => {
                    if self.stack_reads.get(&pc)==Some(&None) {
                        let Op::Load(_,o)=op else{unreachable!()};
                        writeln!(s,"s.r[{d}]=s.stack[s.stack.len()-1-{}];",o/4).unwrap();
                    } else {
                    let offset=self.loads[&pc];
                    writeln!(s,"s.r[{d}]=u32::from_le_bytes(s.bytes[{offset}..{}].try_into().unwrap());",offset+4).unwrap();
                    }
                }
                Op::Save => s.push_str("s.stack.push(s.r[3]);\n"),
                Op::Restore => s.push_str("s.r[3]=s.stack.pop().unwrap();\n"),
                Op::Ret => {s.push_str("Flow::Return}\n");continue;}
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
                    let condition=condition(c);
                    writeln!(s,"Flow::Next(if {condition} {{ {t} }} else {{ {next} }}) }}").unwrap();continue;
                }
            }
            writeln!(s, "Flow::Next({next})}}").unwrap();
        }
        s.push_str("fn block(pc:u32,s:&mut Machine)->Flow {match pc {\n");
        for pc in self.graph.keys() {
            writeln!(s, "{pc}=>b{pc}(s),").unwrap();
        }
        s.push_str("_=>Flow::Terminal(203),}}\n");
        writeln!(s,"fn main(){{let mut s=Machine{{r:[0;6],stack:vec![0],bytes:[0;12],cf:false,zf:false}};std::process::exit(execute({},&mut s) as i32);}}",self.entry).unwrap();
        s
    }
}
#[cfg(test)]
mod tests;
