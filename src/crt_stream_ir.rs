//! Shared structural IR for bounded original CRT instruction graphs.
//! Decoding is not admission. Ownership, call effects, flags and cyclic proofs
//! must be supplied by the consuming compiler before native emission.
use super::graph::{self, Binary, Operand, Operation, Reg};
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Target {
    Direct(u32),
    Import(u32),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignedCondition {
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Sign,
    NotSign,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Ordinary(Operation),
    Call(Target),
    ArithmeticShift {
        dst: Reg,
        count: u8,
    },
    Multiply {
        dst: Reg,
        source: Operand,
        factor: u32,
    },
    IncrementMemory(Operand),
    StoreString {
        width: u8,
    },
    CopyString {
        width: u8,
    },
    Locked {
        operation: Binary,
        destination: Operand,
        source: Operand,
    },
    SignedBranch {
        condition: SignedCondition,
        target: u32,
    },
    ConditionalMove {
        condition: graph::Condition,
        dst: Reg,
        source: Operand,
    },
    SignExtend {
        dst: Reg,
        source: Operand,
    },
}
#[derive(Clone, Debug)]
pub(crate) struct Node {
    pub length: u32,
    pub op: Op,
    pub successors: Vec<u32>,
}
#[derive(Clone, Debug)]
pub(crate) struct Graph {
    pub origin: u32,
    pub end: u32,
    pub nodes: BTreeMap<u32, Node>,
}
fn full(r: Register) -> Result<Reg, String> {
    let index = match r {
        Register::EAX => 0,
        Register::ECX => 1,
        Register::EDX => 2,
        Register::EBX => 3,
        Register::ESP => 4,
        Register::EBP => 5,
        Register::ESI => 6,
        Register::EDI => 7,
        _ => return Err("CRT IR: full register required".into()),
    };
    Ok(Reg {
        index,
        width: 32,
        shift: 0,
    })
}
/// Reuse the operand policy by mechanically substituting only the opcode in
/// an iced Instruction. The original bytes still select and validate the form.
fn operand_from_move(i: &Instruction, n: u32) -> Result<Operand, String> {
    if i.op_kind(n) == OpKind::Register {
        return Ok(Operand::Reg(full(i.op_register(n))?));
    }
    if i.op_kind(n) != OpKind::Memory {
        return Err("CRT IR: operand form".into());
    }
    let mut copy = *i;
    copy.set_code(Code::Mov_r32_rm32);
    copy.set_op0_kind(OpKind::Register);
    copy.set_op0_register(Register::EAX);
    copy.set_op1_kind(OpKind::Memory);
    let Operation::Binary(Binary::Move, _, source) = graph::normalized(&copy, &[0x8b])? else {
        return Err("CRT IR: normalized memory operand".into());
    };
    Ok(source)
}
fn extended(i: &Instruction, raw: &[u8]) -> Result<Op, String> {
    if i.has_rep_prefix() || i.has_repne_prefix() {
        return Err("CRT IR: repeated instruction outside domain".into());
    }
    if i.has_lock_prefix() {
        if raw.first() != Some(&0xf0)
            || !matches!(i.mnemonic(), Mnemonic::Or | Mnemonic::And)
            || i.op0_kind() != OpKind::Memory
            || i.op1_kind() != OpKind::Register
            || i.memory_size() != iced_x86::MemorySize::UInt32
            || i.segment_prefix() != Register::None
        {
            return Err("CRT IR: locked effect form".into());
        }
        let destination = operand_from_move(i, 0)?;
        let source = Operand::Reg(full(i.op1_register())?);
        return Ok(Op::Locked {
            operation: if i.mnemonic() == Mnemonic::Or {
                Binary::Or
            } else {
                Binary::And
            },
            destination,
            source,
        });
    }
    if raw
        .first()
        .is_some_and(|b| matches!(b, 0x66 | 0x67 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65))
        && i.mnemonic() != Mnemonic::Nop
    {
        return Err("CRT IR: instruction prefix".into());
    }
    Ok(match i.mnemonic() {
        Mnemonic::Call => {
            if i.code() == Code::Call_rel32_32 && raw.len() == 5 && raw[0] == 0xe8 {
                Op::Call(Target::Direct(i.near_branch32()))
            } else if i.code() == Code::Call_rm32
                && raw.len() == 6
                && raw[..2] == [0xff, 0x15]
                && i.memory_displacement32().is_multiple_of(4)
            {
                Op::Call(Target::Import(i.memory_displacement32()))
            } else {
                return Err("CRT IR: unbound call form".into());
            }
        }
        Mnemonic::Sar if i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Immediate8 => {
            Op::ArithmeticShift {
                dst: full(i.op0_register())?,
                count: i.immediate8() & 31,
            }
        }
        Mnemonic::Imul
            if i.op_count() == 3
                && i.op0_kind() == OpKind::Register
                && matches!(i.op2_kind(), OpKind::Immediate8to32 | OpKind::Immediate32) =>
        {
            Op::Multiply {
                dst: full(i.op0_register())?,
                source: operand_from_move(i, 1)?,
                factor: i.immediate(2) as u32,
            }
        }
        Mnemonic::Inc
            if i.op0_kind() == OpKind::Memory
                && i.memory_size() == iced_x86::MemorySize::UInt32 =>
        {
            Op::IncrementMemory(operand_from_move(i, 0)?)
        }
        Mnemonic::Stosd if raw == [0xab] => Op::StoreString { width: 32 },
        Mnemonic::Movsd if raw == [0xa5] => Op::CopyString { width: 32 },
        Mnemonic::Jl
        | Mnemonic::Jle
        | Mnemonic::Jg
        | Mnemonic::Jge
        | Mnemonic::Js
        | Mnemonic::Jns
            if i.op0_kind() == OpKind::NearBranch32 =>
        {
            Op::SignedBranch {
                condition: match i.mnemonic() {
                    Mnemonic::Jl => SignedCondition::Less,
                    Mnemonic::Jle => SignedCondition::LessEqual,
                    Mnemonic::Jg => SignedCondition::Greater,
                    Mnemonic::Jge => SignedCondition::GreaterEqual,
                    Mnemonic::Js => SignedCondition::Sign,
                    _ => SignedCondition::NotSign,
                },
                target: i.near_branch32(),
            }
        }
        Mnemonic::Cmovne if i.op0_kind() == OpKind::Register => Op::ConditionalMove {
            condition: graph::Condition::NotEqual,
            dst: full(i.op0_register())?,
            source: operand_from_move(i, 1)?,
        },
        Mnemonic::Movsx
            if i.op0_kind() == OpKind::Register
                && i.op1_kind() == OpKind::Memory
                && matches!(
                    i.memory_size(),
                    iced_x86::MemorySize::UInt8 | iced_x86::MemorySize::Int8
                ) =>
        {
            let mut copy = *i;
            copy.set_code(Code::Movzx_r32_rm8);
            let Operation::ZeroExtend(dst, source) = graph::normalized(&copy, &[0x0f, 0xb6])?
            else {
                return Err("CRT IR: signed byte source".into());
            };
            Op::SignExtend { dst, source }
        }
        _ => Op::Ordinary(graph::normalized(i, raw)?),
    })
}
impl Graph {
    pub fn decode(code: &[u8], origin: u32) -> Result<Self, String> {
        let end = origin
            .checked_add(u32::try_from(code.len()).map_err(|_| "CRT IR: code size")?)
            .ok_or("CRT IR: code overflow")?;
        if origin == 0 || code.is_empty() || code.len() > 16384 {
            return Err("CRT IR: code budget".into());
        }
        let mut d = Decoder::with_ip(32, code, origin as u64, DecoderOptions::NONE);
        let mut nodes = BTreeMap::new();
        while d.can_decode() {
            let i = d.decode();
            if i.is_invalid() || nodes.len() >= 2048 {
                return Err("CRT IR: malformed/node budget".into());
            }
            let pc = i.ip32();
            let at = (pc - origin) as usize;
            let raw = &code[at..at + i.len()];
            let op = extended(&i, raw)?;
            let successors = match &op {
                Op::Ordinary(Operation::Return) => vec![],
                Op::Ordinary(Operation::Jump(t)) => vec![*t],
                Op::Ordinary(Operation::Branch(_, t)) | Op::SignedBranch { target: t, .. } => {
                    vec![i.next_ip32(), *t]
                }
                _ => vec![i.next_ip32()],
            };
            nodes.insert(
                pc,
                Node {
                    length: i.len() as u32,
                    op,
                    successors,
                },
            );
        }
        if nodes
            .values()
            .flat_map(|n| &n.successors)
            .any(|t| !nodes.contains_key(t))
        {
            return Err("CRT IR: branch/fallthrough outside instruction boundaries".into());
        }
        let mut reached = BTreeSet::new();
        let mut todo = vec![origin];
        while let Some(pc) = todo.pop() {
            if reached.insert(pc) {
                todo.extend(nodes[&pc].successors.iter().copied());
            }
        }
        if reached.len() != nodes.len() {
            return Err("CRT IR: hidden unreachable instructions".into());
        }
        Ok(Self { origin, end, nodes })
    }
    pub fn calls(&self) -> BTreeSet<Target> {
        self.nodes
            .values()
            .filter_map(|n| {
                if let Op::Call(t) = n.op {
                    Some(t)
                } else {
                    None
                }
            })
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extensions_preserve_operands_and_closed_edges() {
        let c = [
            0xc1, 0xf8, 6, 0x6b, 0xc8, 56, 0xff, 0x43, 8, 0xab, 0xf0, 0x09, 0x06, 0x85, 0xff, 0x7e,
            2, 0x33, 0xc0, 0xc3,
        ];
        let g = Graph::decode(&c, 0x1000).unwrap();
        assert!(matches!(
            g.nodes[&0x1000].op,
            Op::ArithmeticShift { count: 6, .. }
        ));
        assert!(matches!(
            g.nodes[&0x1003].op,
            Op::Multiply { factor: 56, .. }
        ));
        assert!(matches!(
            g.nodes[&0x100a].op,
            Op::Locked {
                operation: Binary::Or,
                ..
            }
        ));
    }
    #[test]
    fn malformed_control_and_unsupported_prefix_reject() {
        for c in [
            &[0xeb, 0xff][..],
            &[0x66, 0xab, 0xc3],
            &[0xf3, 0xab, 0xc3],
            &[0xf0, 0x89, 0x06, 0xc3],
            &[0xff, 0xd0, 0xc3],
            &[0xc3, 0x90],
        ] {
            assert!(Graph::decode(c, 0x1000).is_err(), "{c:?}");
        }
    }
}
