//! Operand-normalized cyclic graph. Structural closure is NOT execution eligibility.
use iced_x86::{Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reg {
    pub index: u8,
    pub width: u8,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub base: Option<u8>,
    pub index: Option<u8>,
    pub scale: u32,
    pub displacement: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    Reg(Reg),
    Immediate(u32),
    Memory(Address, u8),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binary {
    Move,
    Add,
    Sub,
    Xor,
    And,
    Sbb,
    Compare,
    Test,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    Equal,
    NotEqual,
    Below,
    Above,
    BelowEqual,
    AboveEqual,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Binary(Binary, Operand, Operand),
    Address(Reg, Address),
    Increment(Reg),
    Decrement(Reg),
    Negate(Reg),
    Push(Operand),
    Pop(Reg),
    Leave,
    // Target binding and stdcall effects remain separate proof obligations.
    Call(Operand),
    Nop,
    Return,
    Jump(u32),
    Branch(Condition, u32),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub length: u32,
    pub operation: Operation,
    pub successors: Vec<u32>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Graph {
    pub entry: u32,
    pub nodes: BTreeMap<u32, Node>,
    pub cyclic_components: Vec<Vec<u32>>,
}
fn reg(r: Register) -> Result<Reg, String> {
    use Register::*;
    let (index, width) = match r {
        EAX => (0, 32),
        ECX => (1, 32),
        EDX => (2, 32),
        EBX => (3, 32),
        ESP => (4, 32),
        EBP => (5, 32),
        ESI => (6, 32),
        EDI => (7, 32),
        AL => (0, 8),
        CL => (1, 8),
        DL => (2, 8),
        BL => (3, 8),
        _ => return Err("stream: register width/alias outside policy".into()),
    };
    Ok(Reg { index, width })
}
fn address(i: &Instruction) -> Result<Address, String> {
    let base = if i.memory_base() == Register::None {
        None
    } else {
        let r = reg(i.memory_base())?;
        if r.width != 32 {
            return Err("stream: address width".into());
        }
        Some(r.index)
    };
    let index = if i.memory_index() == Register::None {
        None
    } else {
        let r = reg(i.memory_index())?;
        if r.width != 32 {
            return Err("stream: index width".into());
        }
        Some(r.index)
    };
    Ok(Address {
        base,
        index,
        scale: i.memory_index_scale(),
        displacement: i.memory_displacement32(),
    })
}
fn operand(i: &Instruction, n: u32) -> Result<Operand, String> {
    Ok(match i.op_kind(n) {
        OpKind::Register => Operand::Reg(reg(i.op_register(n))?),
        OpKind::Immediate8 => Operand::Immediate(u32::from(i.immediate8())),
        OpKind::Immediate32 => Operand::Immediate(i.immediate32()),
        OpKind::Immediate8to32 => Operand::Immediate(i.immediate8to32() as u32),
        OpKind::Memory => Operand::Memory(
            address(i)?,
            match i.memory_size() {
                MemorySize::UInt8 => 8,
                MemorySize::UInt32 => 32,
                MemorySize::DwordOffset if i.mnemonic() == Mnemonic::Call => 32,
                _ => return Err("stream: memory width".into()),
            },
        ),
        _ => return Err("stream: operand kind".into()),
    })
}
fn width(o: &Operand) -> Option<u8> {
    match o {
        Operand::Reg(r) => Some(r.width),
        Operand::Memory(_, w) => Some(*w),
        _ => None,
    }
}
fn writable(o: &Operand) -> bool {
    matches!(o, Operand::Reg(_) | Operand::Memory(_, _))
}
fn normalized(i: &Instruction, b: &[u8]) -> Result<Operation, String> {
    use Mnemonic::*;
    // NOP's memory-looking spelling does not access memory. Accept the defined
    // unprefixed 0F1F /0 forms, 66 90 and two exact compiler alignment forms;
    // do not erase arbitrary prefixes.
    if i.mnemonic() == Nop
        && (b == [0x90]
            || b == [0x66, 0x90]
            || b.starts_with(&[0x0f, 0x1f])
            || b == [0x66, 0x66, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0]
            || b == [0x66, 0x0f, 0x1f, 0x44, 0, 0])
    {
        return Ok(Operation::Nop);
    }
    if matches!(
        b[0],
        0xf0 | 0xf2 | 0xf3 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67
    ) {
        return Err("stream: instruction prefix outside policy".into());
    }
    Ok(match i.mnemonic() {
        Mov | Add | Sub | Xor | And | Sbb | Cmp | Test => {
            if i.op_count() != 2 {
                return Err("stream: binary arity".into());
            }
            let a = operand(i, 0)?;
            let b = operand(i, 1)?;
            if !writable(&a)
                || (width(&b).is_some() && width(&a) != width(&b))
                || (matches!(a, Operand::Memory(..)) && matches!(b, Operand::Memory(..)))
            {
                return Err("stream: binary operand widths".into());
            }
            let op = match i.mnemonic() {
                Mov => Binary::Move,
                Add => Binary::Add,
                Sub => Binary::Sub,
                Xor => Binary::Xor,
                And => Binary::And,
                Sbb => Binary::Sbb,
                Cmp => Binary::Compare,
                _ => Binary::Test,
            };
            Operation::Binary(op, a, b)
        }
        Lea if i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Memory => {
            let r = reg(i.op0_register())?;
            if r.width != 32 {
                return Err("stream: lea width".into());
            }
            Operation::Address(r, address(i)?)
        }
        Inc | Dec | Neg if i.op0_kind() == OpKind::Register => {
            let r = reg(i.op0_register())?;
            if r.width != 32 {
                return Err("stream: inc width".into());
            }
            match i.mnemonic() {
                Inc => Operation::Increment(r),
                Dec => Operation::Decrement(r),
                _ => Operation::Negate(r),
            }
        }
        Push => {
            let a = operand(i, 0)?;
            if width(&a).is_some_and(|w| w != 32) {
                return Err("stream: push form".into());
            }
            Operation::Push(a)
        }
        Pop if i.op0_kind() == OpKind::Register => {
            let r = reg(i.op0_register())?;
            if r.width != 32 || r.index == 4 {
                return Err("stream: pop form".into());
            }
            Operation::Pop(r)
        }
        Leave if b == [0xc9] => Operation::Leave,
        Ret if b == [0xc3] => Operation::Return,
        Call => {
            let a = operand(i, 0)?;
            if !matches!(
                &a,
                Operand::Reg(Reg { width: 32, .. })
                    | Operand::Memory(
                        Address {
                            base: None,
                            index: None,
                            ..
                        },
                        32
                    )
            ) {
                return Err("stream: unbound call form".into());
            }
            Operation::Call(a)
        }
        Jmp | Je | Jne | Jb | Ja | Jbe | Jae if i.op0_kind() == OpKind::NearBranch32 => {
            let t = i.near_branch32();
            if i.mnemonic() == Jmp {
                Operation::Jump(t)
            } else {
                Operation::Branch(
                    match i.mnemonic() {
                        Je => Condition::Equal,
                        Jne => Condition::NotEqual,
                        Jb => Condition::Below,
                        Ja => Condition::Above,
                        Jbe => Condition::BelowEqual,
                        _ => Condition::AboveEqual,
                    },
                    t,
                )
            }
        }
        _ => {
            return Err(format!(
                "stream: unsupported instruction {:?}",
                i.mnemonic()
            ))
        }
    })
}
pub fn decode(code: &[u8], origin: u32, entry: u32) -> Result<Graph, String> {
    if code.is_empty() || code.len() > 4096 {
        return Err("stream: code resource limit".into());
    }
    let end = origin
        .checked_add(code.len() as u32)
        .ok_or("stream: code overflow")?;
    let mut pending = vec![entry];
    let mut nodes = BTreeMap::new();
    let mut occupied = BTreeSet::new();
    while let Some(pc) = pending.pop() {
        if nodes.contains_key(&pc) {
            continue;
        }
        if pc < origin || pc >= end || nodes.len() >= 1024 {
            return Err("stream: target/resource bounds".into());
        }
        let bytes = &code[(pc - origin) as usize..];
        let ins = Decoder::with_ip(32, bytes, u64::from(pc), DecoderOptions::NONE).decode();
        if ins.is_invalid() {
            return Err("stream: malformed/truncated instruction".into());
        }
        let length = ins.len() as u32;
        let next = pc
            .checked_add(length)
            .ok_or("stream: instruction overflow")?;
        for p in pc..next {
            if !occupied.insert(p) {
                return Err("stream: overlapping instruction boundary".into());
            }
        }
        let operation =
            normalized(&ins, &bytes[..length as usize]).map_err(|e| format!("{pc:08x}: {e}"))?;
        let mut successors = match operation {
            Operation::Return => vec![],
            Operation::Jump(t) => vec![t],
            Operation::Branch(_, t) => vec![t, next],
            _ => vec![next],
        };
        successors.sort();
        successors.dedup();
        pending.extend(successors.iter().copied());
        nodes.insert(
            pc,
            Node {
                length,
                operation,
                successors,
            },
        );
    }
    // Unreached bytes may only be architectural NOP padding or compiler INT3
    // padding. Decode padding boundaries too: never skip arbitrary hidden code.
    let mut pc = origin;
    while pc < end {
        if occupied.contains(&pc) {
            pc += 1;
            continue;
        }
        let at = (pc - origin) as usize;
        if code[at] == 0xcc {
            pc += 1;
            continue;
        }
        let ins = Decoder::with_ip(32, &code[at..], u64::from(pc), DecoderOptions::NONE).decode();
        if ins.is_invalid()
            || (pc..pc + ins.len() as u32).any(|p| occupied.contains(&p))
            || normalized(&ins, &code[at..at + ins.len()])? != Operation::Nop
        {
            return Err("stream: non-padding unreachable bytes".into());
        }
        pc += ins.len() as u32;
    }
    let cyclic_components = components(&nodes);
    Ok(Graph {
        entry,
        nodes,
        cyclic_components,
    })
}
fn components(nodes: &BTreeMap<u32, Node>) -> Vec<Vec<u32>> {
    // Iterative Kosaraju: bounded graph analysis, no Rust recursion on guest CFG.
    let mut seen = BTreeSet::new();
    let mut finish = vec![];
    for &start in nodes.keys() {
        let mut stack = vec![(start, false)];
        while let Some((p, done)) = stack.pop() {
            if done {
                finish.push(p);
                continue;
            }
            if !seen.insert(p) {
                continue;
            }
            stack.push((p, true));
            for &q in &nodes[&p].successors {
                if !seen.contains(&q) {
                    stack.push((q, false));
                }
            }
        }
    }
    let mut reverse: BTreeMap<u32, Vec<u32>> = nodes.keys().map(|&p| (p, vec![])).collect();
    for (&p, n) in nodes {
        for q in &n.successors {
            reverse.get_mut(q).expect("closed graph").push(p);
        }
    }
    seen.clear();
    let mut cycles = vec![];
    for start in finish.into_iter().rev() {
        if seen.contains(&start) {
            continue;
        }
        let mut component = vec![];
        let mut stack = vec![start];
        while let Some(p) = stack.pop() {
            if seen.insert(p) {
                component.push(p);
                stack.extend(&reverse[&p]);
            }
        }
        component.sort();
        if component.len() > 1 || nodes[&start].successors.contains(&start) {
            cycles.push(component);
        }
    }
    cycles.sort();
    cycles
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backedges_are_represented_not_unrolled_or_claimed_terminating() {
        let g = decode(
            &[0x33, 0xc0, 0x40, 0x3c, 3, 0x72, 0xfb, 0xc3],
            0x1000,
            0x1000,
        )
        .unwrap();
        assert_eq!(g.nodes.len(), 5);
        assert_eq!(g.cyclic_components, vec![vec![0x1002, 0x1003, 0x1005]]);
        let infinite = decode(&[0xeb, 0xfe], 0, 0).unwrap();
        assert_eq!(infinite.cyclic_components, vec![vec![0]]);
        // This is structural acceptance, never a termination or emission certificate.
    }
    #[test]
    fn indexed_byte_forms_and_register_permutations() {
        let a = decode(
            &[0x8a, 0x54, 0x05, 0xfc, 0x88, 0x54, 0x05, 0xfc, 0xc3],
            0,
            0,
        )
        .unwrap();
        assert_eq!(
            a.nodes[&0].operation,
            Operation::Binary(
                Binary::Move,
                Operand::Reg(Reg { index: 2, width: 8 }),
                Operand::Memory(
                    Address {
                        base: Some(5),
                        index: Some(0),
                        scale: 1,
                        displacement: 0xffff_fffc
                    },
                    8
                )
            )
        );
        let b = decode(&[0x8a, 0x4c, 0x1c, 4, 0xc3], 0, 0).unwrap();
        assert_eq!(
            b.nodes[&0].operation,
            Operation::Binary(
                Binary::Move,
                Operand::Reg(Reg { index: 1, width: 8 }),
                Operand::Memory(
                    Address {
                        base: Some(4),
                        index: Some(3),
                        scale: 1,
                        displacement: 4
                    },
                    8
                )
            )
        );
    }
    #[test]
    fn targets_prefixes_truncation_and_unknown_code_reject() {
        for b in [
            &[0xeb, 0xff][..],
            &[0xeb, 2],
            &[0x0f],
            &[0x66, 0x40, 0xc3],
            &[0xf3, 0x90, 0xc3],
            &[0x64, 0x8b, 0x00, 0xc3],
            &[0xc3, 0x40],
            &[0xeb, 1, 0xb8, 0, 0, 0, 0, 0xc3],
            &[0xff, 0xe0],
            &[0xe8, 0, 0, 0, 0, 0xc3],
        ] {
            assert!(decode(b, 0, 0).is_err(), "{b:02x?}");
        }
    }
    #[test]
    fn nop_memory_spelling_has_no_load_effect_and_calls_stay_unbound() {
        let g = decode(
            &[0x0f, 0x1f, 0x40, 0, 0x66, 0x90, 0xff, 0xd3, 0xc3, 0xcc],
            0,
            0,
        )
        .unwrap();
        assert_eq!(g.nodes[&0].operation, Operation::Nop);
        assert_eq!(g.nodes[&4].operation, Operation::Nop);
        assert_eq!(
            g.nodes[&6].operation,
            Operation::Call(Operand::Reg(Reg {
                index: 3,
                width: 32
            }))
        );
    }
    #[test]
    fn deterministic_closed_graph_and_extent_limit() {
        let code = [0x74, 2, 0xeb, 0xfc, 0xc3];
        let a = decode(&code, 16, 16).unwrap();
        assert_eq!(a, decode(&code, 16, 16).unwrap());
        assert_eq!(a.cyclic_components, vec![vec![16, 18]]);
        assert!(decode(&code, u32::MAX - 2, u32::MAX - 2).is_err());
        assert!(decode(&[0x90; 4097], 0, 0).is_err());
    }
    #[test]
    fn scalar_forms_and_alignment_nops_have_exact_operands() {
        let b = [
            0xf7, 0xda, 0x1b, 0xd2, 0x83, 0xe2, 11, 0x49, 0xff, 0x74, 0x24, 4, 0xc3,
        ];
        let g = decode(&b, 0, 0).unwrap();
        assert_eq!(
            g.nodes[&0].operation,
            Operation::Negate(Reg {
                index: 2,
                width: 32
            })
        );
        assert_eq!(
            g.nodes[&7].operation,
            Operation::Decrement(Reg {
                index: 1,
                width: 32
            })
        );
        assert!(matches!(
            g.nodes[&8].operation,
            Operation::Push(Operand::Memory(_, 32))
        ));
        for nop in [
            &[0x66, 0x0f, 0x1f, 0x44, 0, 0][..],
            &[0x66, 0x66, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0],
        ] {
            let mut bytes = nop.to_vec();
            bytes.push(0xc3);
            assert_eq!(
                decode(&bytes, 0, 0).unwrap().nodes[&0].operation,
                Operation::Nop
            );
            bytes.insert(0, 0xf3);
            assert!(decode(&bytes, 0, 0).is_err());
        }
    }
}
