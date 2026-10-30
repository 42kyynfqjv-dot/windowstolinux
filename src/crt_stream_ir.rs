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
    Exchange {
        address: graph::Address,
        register: Reg,
    },
    Call(Target),
    IndirectCall(Operand),
    SignedMove {
        condition: SignedCondition,
        dst: Reg,
        source: Operand,
    },
    ReturnPop(u16),
    FsRead(Reg),
    FsWrite(Reg),
    FsPush,
    SignDividend,
    CpuId,
    ReadXcr,
    XmmZero(u8),
    XmmStoreLow64 {
        source: u8,
        address: graph::Address,
    },
    RotateRightCl(Reg),
    AddCarry {
        destination: Operand,
        source: Operand,
    },
    DivideUnsigned(Operand),
    /// Structural source binding only. Module ownership and table immutability
    /// remain proof obligations before execution admission.
    TableJump {
        index: Reg,
        address: u32,
        targets: Vec<u32>,
    },
    ArithmeticShift {
        dst: Reg,
        count: u8,
    },
    MultiplyValue {
        dst: Reg,
        source: Operand,
    },
    Multiply {
        dst: Reg,
        source: Operand,
        factor: u32,
    },
    IncrementMemory(Operand),
    DecrementMemory(Operand),
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
fn xmm(r: Register) -> Result<u8, String> {
    if !(Register::XMM0..=Register::XMM7).contains(&r) {
        return Err("CRT IR: legacy XMM register".into());
    }
    Ok((r as u32 - Register::XMM0 as u32) as u8)
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
#[derive(Clone, Copy, Debug)]
pub(crate) struct JumpTable<'a> {
    pub address: u32,
    pub bytes: &'a [u8],
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct ByteTable<'a> {
    pub address: u32,
    pub bytes: &'a [u8],
}
fn extended(i: &Instruction, raw: &[u8], tables: &[JumpTable<'_>]) -> Result<Op, String> {
    if i.has_rep_prefix() || i.has_repne_prefix() {
        return Err("CRT IR: repeated instruction outside domain".into());
    }
    if i.segment_prefix() == Register::FS && raw.first() == Some(&0x64) {
        if i.memory_base() != Register::None
            || i.memory_index() != Register::None
            || i.memory_displacement32() != 0
            || i.has_lock_prefix()
        {
            return Err("CRT IR: FS head-only effect".into());
        }
        return Ok(match i.code() {
            Code::Mov_r32_rm32 if raw.len() == 7 => Op::FsRead(full(i.op0_register())?),
            Code::Mov_EAX_moffs32 if raw.len() == 6 => Op::FsRead(full(Register::EAX)?),
            Code::Mov_rm32_r32 if raw.len() == 7 => Op::FsWrite(full(i.op1_register())?),
            Code::Mov_moffs32_EAX if raw.len() == 6 => Op::FsWrite(full(Register::EAX)?),
            Code::Push_rm32 if raw == [0x64, 0xff, 0x35, 0, 0, 0, 0] => Op::FsPush,
            _ => return Err("CRT IR: FS head effect form".into()),
        });
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
    if raw == [0x0f, 0xa2] && i.code() == Code::Cpuid {
        return Ok(Op::CpuId);
    }
    if raw == [0x0f, 0x01, 0xd0] && i.code() == Code::Xgetbv {
        return Ok(Op::ReadXcr);
    }
    // Only legacy, non-faulting SSE/SSE2 forms under an explicit enabled-SSE
    // execution premise. No general SIMD or floating-point contract follows.
    if i.code() == Code::Xorps_xmm_xmmm128
        && i.op0_kind() == OpKind::Register
        && i.op1_kind() == OpKind::Register
        && i.op0_register() == i.op1_register()
        && raw.len() == 3
        && raw[..2] == [0x0f, 0x57]
    {
        return Ok(Op::XmmZero(xmm(i.op0_register())?));
    }
    if i.code() == Code::Movlpd_m64_xmm
        && raw.starts_with(&[0x66, 0x0f, 0x13])
        && i.segment_prefix() == Register::None
        && i.op0_kind() == OpKind::Memory
        && i.op1_kind() == OpKind::Register
    {
        let Operand::Memory(address, _) = operand_from_move(i, 0)? else {
            return Err("CRT IR: MOVLPD memory".into());
        };
        return Ok(Op::XmmStoreLow64 {
            source: xmm(i.op1_register())?,
            address,
        });
    }
    // Exact word-memory compare used by STARTUPINFO.cbReserved2. Keep the
    // operand override local to this form; it grants no 16-bit register state.
    if i.code() == Code::Cmp_rm16_imm8
        && raw.starts_with(&[0x66, 0x83])
        && i.op0_kind() == OpKind::Memory
        && !i.has_lock_prefix()
        && i.segment_prefix() == Register::None
    {
        let Operand::Memory(address, _) = operand_from_move(i, 0)? else {
            return Err("CRT word compare address".into());
        };
        return Ok(Op::Ordinary(Operation::Binary(
            Binary::Compare,
            Operand::Memory(address, 16),
            Operand::Immediate(i.immediate8to16() as u16 as u32),
        )));
    }
    // Word stores preserve flags and upper source bits. Only a memory
    // destination is admitted here; this does not add partial register writes.
    if i.code() == Code::Mov_rm16_r16
        && raw.starts_with(&[0x66, 0x89])
        && i.op0_kind() == OpKind::Memory
        && !i.has_lock_prefix()
        && i.segment_prefix() == Register::None
    {
        let index = match i.op1_register() {
            Register::AX => 0,
            Register::CX => 1,
            Register::DX => 2,
            Register::BX => 3,
            Register::SP => 4,
            Register::BP => 5,
            Register::SI => 6,
            Register::DI => 7,
            _ => return Err("CRT word store source".into()),
        };
        let Operand::Memory(address, _) = operand_from_move(i, 0)? else {
            return Err("CRT word store destination".into());
        };
        return Ok(Op::Ordinary(Operation::Binary(
            Binary::Move,
            Operand::Memory(address, 16),
            Operand::Reg(Reg {
                index,
                width: 16,
                shift: 0,
            }),
        )));
    }
    // Word TEST/CMP forms used by bounded UTF-16 traversal. Decode only;
    // live initialized read authority remains an execution obligation.
    if matches!(
        i.code(),
        Code::Test_rm16_r16 | Code::Cmp_r16_rm16 | Code::Cmp_rm16_r16
    ) && raw.first() == Some(&0x66)
        && !i.has_lock_prefix()
        && i.segment_prefix() == Register::None
    {
        let word_reg = |r| -> Result<Operand, String> {
            let index = match r {
                Register::AX => 0,
                Register::CX => 1,
                Register::DX => 2,
                Register::BX => 3,
                Register::SP => 4,
                Register::BP => 5,
                Register::SI => 6,
                Register::DI => 7,
                _ => return Err("CRT word register".into()),
            };
            Ok(Operand::Reg(Reg {
                index,
                width: 16,
                shift: 0,
            }))
        };
        let operand = |n| -> Result<Operand, String> {
            if i.op_kind(n) == OpKind::Register {
                return word_reg(i.op_register(n));
            }
            let Operand::Memory(a, _) = operand_from_move(i, n)? else {
                return Err("CRT word operand".into());
            };
            Ok(Operand::Memory(a, 16))
        };
        return Ok(Op::Ordinary(Operation::Binary(
            if i.code() == Code::Test_rm16_r16 {
                Binary::Test
            } else {
                Binary::Compare
            },
            operand(0)?,
            operand(1)?,
        )));
    }
    if raw
        .first()
        .is_some_and(|b| matches!(b, 0x66 | 0x67 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65))
        && i.mnemonic() != Mnemonic::Nop
    {
        return Err("CRT IR: instruction prefix".into());
    }
    Ok(match i.mnemonic() {
        Mnemonic::Ror if i.code() == Code::Ror_rm32_CL && i.op0_kind() == OpKind::Register => {
            let dst = full(i.op0_register())?;
            if dst.index == 4 {
                return Err("CRT rotate stack register".into());
            }
            Op::RotateRightCl(dst)
        }
        Mnemonic::Xchg
            if i.code() == Code::Xchg_rm32_r32
                && i.op0_kind() == OpKind::Memory
                && i.op1_kind() == OpKind::Register =>
        {
            let Operand::Memory(address, 32) = operand_from_move(i, 0)? else {
                return Err("CRT XCHG word address".into());
            };
            let register = full(i.op1_register())?;
            if register.index == 4 {
                return Err("CRT XCHG stack register".into());
            }
            Op::Exchange { address, register }
        }

        Mnemonic::Inc if i.code() == Code::Inc_rm8 && i.op0_kind() == OpKind::Register => {
            let mut copy = *i;
            copy.set_code(Code::Setne_rm8);
            let Operation::Set(_, dst) = graph::normalized(&copy, &[0x0f, 0x95])? else {
                return Err("CRT IR: INC byte register".into());
            };
            Op::Ordinary(Operation::Increment(dst))
        }
        Mnemonic::Sete if i.code() == Code::Sete_rm8 && i.op0_kind() == OpKind::Register => {
            let mut copy = *i;
            copy.set_code(Code::Setne_rm8);
            let Operation::Set(_, dst) = graph::normalized(&copy, &[0x0f, 0x95])? else {
                return Err("CRT IR: SETE byte register".into());
            };
            Op::Ordinary(Operation::Set(graph::Condition::Equal, dst))
        }
        Mnemonic::Ret if i.code() == Code::Retnd_imm16 && raw.len() == 3 && raw[0] == 0xc2 => {
            let bytes = i.immediate16();
            if bytes > 256 || !bytes.is_multiple_of(4) {
                return Err("CRT IR: bounded word RET cleanup".into());
            }
            Op::ReturnPop(bytes)
        }
        Mnemonic::Cdq if raw == [0x99] => Op::SignDividend,
        Mnemonic::Adc => {
            let mut copy = *i;
            copy.set_code(match i.code() {
                Code::Adc_rm32_r32 => Code::Add_rm32_r32,
                Code::Adc_r32_rm32 => Code::Add_r32_rm32,
                Code::Adc_EAX_imm32 => Code::Add_EAX_imm32,
                Code::Adc_rm32_imm32 => Code::Add_rm32_imm32,
                Code::Adc_rm32_imm8 => Code::Add_rm32_imm8,
                _ => return Err("CRT IR: ADC32 form".into()),
            });
            let Operation::Binary(Binary::Add, destination, source) =
                graph::normalized(&copy, &[0x01])?
            else {
                return Err("CRT IR: ADC operands".into());
            };
            Op::AddCarry {
                destination,
                source,
            }
        }
        Mnemonic::Div if i.code() == Code::Div_rm32 && i.op_count() == 1 => {
            Op::DivideUnsigned(operand_from_move(i, 0)?)
        }
        Mnemonic::Jmp if i.code() == Code::Jmp_rm32 => {
            if raw.len() != 7
                || raw[..2] != [0xff, 0x24]
                || i.memory_base() != Register::None
                || i.memory_index_scale() != 4
                || i.op0_kind() != OpKind::Memory
            {
                return Err("CRT IR: bounded indexed JMP form".into());
            }
            let index = full(i.memory_index())?;
            let address = i.memory_displacement32();
            let table = tables
                .iter()
                .find(|t| t.address == address)
                .ok_or("CRT IR: indirect JMP lacks source table")?;
            let targets = table
                .bytes
                .as_chunks::<4>()
                .0
                .iter()
                .map(|b| u32::from_le_bytes(*b))
                .collect();
            Op::TableJump {
                index,
                address,
                targets,
            }
        }
        Mnemonic::Call => {
            if i.code() == Code::Call_rel32_32 && raw.len() == 5 && raw[0] == 0xe8 {
                Op::Call(Target::Direct(i.near_branch32()))
            } else if i.code() == Code::Call_rm32
                && raw.len() == 6
                && raw[..2] == [0xff, 0x15]
                && i.memory_displacement32().is_multiple_of(4)
            {
                Op::Call(Target::Import(i.memory_displacement32()))
            } else if i.code() == Code::Call_rm32 {
                Op::IndirectCall(operand_from_move(i, 0)?)
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
        Mnemonic::Imul if i.code() == Code::Imul_r32_rm32 => Op::MultiplyValue {
            dst: full(i.op0_register())?,
            source: operand_from_move(i, 1)?,
        },
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
        Mnemonic::Dec
            if i.op0_kind() == OpKind::Memory
                && i.memory_size() == iced_x86::MemorySize::UInt32 =>
        {
            Op::DecrementMemory(operand_from_move(i, 0)?)
        }
        Mnemonic::Movzx if i.code() == Code::Movzx_r32_rm16 && i.op1_kind() == OpKind::Memory => {
            let Operand::Memory(a, _) = operand_from_move(i, 1)? else {
                return Err("CRT IR: word zero extension source".into());
            };
            Op::Ordinary(Operation::ZeroExtend(
                full(i.op0_register())?,
                Operand::Memory(a, 16),
            ))
        }
        Mnemonic::Movsx if i.code() == Code::Movsx_r32_rm16 && i.op1_kind() == OpKind::Memory => {
            let Operand::Memory(a, _) = operand_from_move(i, 1)? else {
                return Err("CRT IR: word sign extension source".into());
            };
            Op::SignExtend {
                dst: full(i.op0_register())?,
                source: Operand::Memory(a, 16),
            }
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
        Mnemonic::Cmovl | Mnemonic::Cmovg
            if matches!(i.code(), Code::Cmovl_r32_rm32 | Code::Cmovg_r32_rm32) =>
        {
            Op::SignedMove {
                condition: if i.mnemonic() == Mnemonic::Cmovl {
                    SignedCondition::Less
                } else {
                    SignedCondition::Greater
                },
                dst: full(i.op0_register())?,
                source: operand_from_move(i, 1)?,
            }
        }
        Mnemonic::Cmovne if i.op0_kind() == OpKind::Register => Op::ConditionalMove {
            condition: graph::Condition::NotEqual,
            dst: full(i.op0_register())?,
            source: operand_from_move(i, 1)?,
        },
        Mnemonic::Movsx if i.code() == Code::Movsx_r32_rm8 && i.op1_kind() == OpKind::Register => {
            let mut copy = *i;
            copy.set_code(Code::Movzx_r32_rm8);
            let Operation::ZeroExtend(dst, source) = graph::normalized(&copy, &[0x0f, 0xb6])?
            else {
                return Err("CRT IR: signed byte register source".into());
            };
            Op::SignExtend { dst, source }
        }
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
/// Structural normalization of an instruction decoded from the supplied bytes.
/// This does not admit control effects or close any external-call contract.
pub(crate) fn normalize(i: &Instruction, raw: &[u8]) -> Result<Op, String> {
    extended(i, raw, &[])
}
impl Graph {
    /// Structural lowering of one exactly bounded original instruction. This
    /// supplies no reachability, ownership or call-effect proof.
    #[allow(dead_code)] // Shared bounded-path compiler; not all standalone slices use it.
    pub(crate) fn decode_instruction(raw: &[u8], origin: u32) -> Result<Node, String> {
        if origin == 0
            || raw.is_empty()
            || raw.len() > 15
            || origin.checked_add(raw.len() as u32).is_none()
        {
            return Err("CRT IR: instruction cut extent".into());
        }
        let mut decoder = Decoder::with_ip(32, raw, u64::from(origin), DecoderOptions::NONE);
        let i = decoder.decode();
        if i.is_invalid() || i.len() != raw.len() {
            return Err("CRT IR: instruction cut boundary".into());
        }
        let op = extended(&i, raw, &[])?;
        let successors = match &op {
            Op::Ordinary(Operation::Return) | Op::ReturnPop(_) => vec![],
            Op::Ordinary(Operation::Jump(t)) => vec![*t],
            Op::Ordinary(Operation::Branch(_, t)) | Op::SignedBranch { target: t, .. } => {
                vec![i.next_ip32(), *t]
            }
            _ => vec![i.next_ip32()],
        };
        Ok(Node {
            length: i.len() as u32,
            op,
            successors,
        })
    }
    /// Explicit straight-line component cut. This is not whole-function admission.
    #[allow(dead_code)]
    pub fn decode_linear_fragment(code: &[u8], origin: u32) -> Result<Self, String> {
        let end = origin
            .checked_add(u32::try_from(code.len()).map_err(|_| "CRT fragment extent")?)
            .ok_or("CRT fragment overflow")?;
        if origin == 0 || code.is_empty() || code.len() > 1024 {
            return Err("CRT fragment bounds".into());
        }
        let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
        let mut nodes = BTreeMap::new();
        while decoder.can_decode() {
            let i = decoder.decode();
            if i.is_invalid() {
                return Err("CRT fragment instruction".into());
            }
            let pc = i.ip() as u32;
            let at = (pc - origin) as usize;
            let node = Self::decode_instruction(&code[at..at + i.len()], pc)?;
            if node.successors != [pc + node.length]
                || matches!(
                    node.op,
                    Op::Call(_)
                        | Op::CpuId
                        | Op::ReadXcr
                        | Op::IndirectCall(_)
                        | Op::FsRead(_)
                        | Op::FsWrite(_)
                        | Op::FsPush
                        | Op::Ordinary(Operation::Jump(_))
                )
            {
                return Err("CRT fragment control/effect boundary".into());
            }
            if nodes.len() >= 128 {
                return Err("CRT fragment instruction budget".into());
            }
            nodes.insert(pc, node);
        }
        Ok(Self { origin, end, nodes })
    }
    pub fn decode(code: &[u8], origin: u32) -> Result<Self, String> {
        Self::decode_with_tables(code, origin, &[])
    }
    /// Bind an original indexed branch to exact source words. Embedded table
    /// bytes are excluded from instruction decoding, never treated as code.
    /// This proves bounds/control closure, not module permissions or no-write.
    pub fn decode_with_tables(
        code: &[u8],
        origin: u32,
        tables: &[JumpTable<'_>],
    ) -> Result<Self, String> {
        Self::decode_with_table_maps(code, origin, tables, &[])
    }
    pub fn decode_with_table_maps(
        code: &[u8],
        origin: u32,
        tables: &[JumpTable<'_>],
        maps: &[ByteTable<'_>],
    ) -> Result<Self, String> {
        Self::decode_complete(code, origin, tables, maps, &[])
    }
    /// Inventory exact original external tail edges, without granting emission.
    /// A later proof must eliminate or independently bind every such edge.
    pub fn decode_with_exits(code: &[u8], origin: u32, exits: &[u32]) -> Result<Self, String> {
        Self::decode_complete(code, origin, &[], &[], exits)
    }
    fn decode_complete(
        code: &[u8],
        origin: u32,
        tables: &[JumpTable<'_>],
        maps: &[ByteTable<'_>],
        exits: &[u32],
    ) -> Result<Self, String> {
        let end = origin
            .checked_add(u32::try_from(code.len()).map_err(|_| "CRT IR: code size")?)
            .ok_or("CRT IR: code overflow")?;
        if origin == 0
            || code.is_empty()
            || code.len() > 16384
            || tables.len() > 8
            || maps.len() > 8
        {
            return Err("CRT IR: code/table budget".into());
        }
        if exits.len() > 16
            || exits.iter().any(|&t| t == 0 || (origin..end).contains(&t))
            || exits.iter().copied().collect::<BTreeSet<_>>().len() != exits.len()
        {
            return Err("CRT IR: external edge inventory".into());
        }
        let mut used_exits = BTreeSet::new();
        let mut data_ranges = Vec::new();
        for table in tables {
            if table.address == 0
                || !table.address.is_multiple_of(4)
                || table.bytes.is_empty()
                || !table.bytes.len().is_multiple_of(4)
                || table.bytes.len() > 1024
            {
                return Err("CRT IR: jump table full-word bound".into());
            }
            let table_end = table
                .address
                .checked_add(table.bytes.len() as u32)
                .ok_or("CRT IR: jump table overflow")?;
            if data_ranges
                .iter()
                .any(|&(a, b)| table.address < b && a < table_end)
            {
                return Err("CRT IR: overlapping jump tables".into());
            }
            if table.address < end
                && origin < table_end
                && (table.address < origin
                    || table_end > end
                    || code[(table.address - origin) as usize..(table_end - origin) as usize]
                        != *table.bytes)
            {
                return Err("CRT IR: embedded table source mismatch".into());
            }
            data_ranges.push((table.address, table_end));
        }
        for table in maps {
            if table.address == 0 || table.bytes.is_empty() || table.bytes.len() > 256 {
                return Err("CRT IR: class table bound".into());
            }
            let table_end = table
                .address
                .checked_add(table.bytes.len() as u32)
                .ok_or("CRT IR: class table overflow")?;
            if data_ranges
                .iter()
                .any(|&(a, b)| table.address < b && a < table_end)
            {
                return Err("CRT IR: overlapping class table".into());
            }
            if table.address < end
                && origin < table_end
                && (table.address < origin
                    || table_end > end
                    || code[(table.address - origin) as usize..(table_end - origin) as usize]
                        != *table.bytes)
            {
                return Err("CRT IR: embedded class table mismatch".into());
            }
            data_ranges.push((table.address, table_end));
        }
        let mut used_maps = BTreeSet::new();
        let mut nodes = BTreeMap::new();
        let mut offset = 0usize;
        while offset < code.len() {
            let pc = origin + offset as u32;
            if let Some(&(_, data_end)) = data_ranges.iter().find(|&&(a, _)| a == pc) {
                offset = (data_end - origin) as usize;
                continue;
            }
            let mut d = Decoder::with_ip(32, &code[offset..], u64::from(pc), DecoderOptions::NONE);
            let i = d.decode();
            if i.is_invalid()
                || nodes.len() >= 2048
                || data_ranges
                    .iter()
                    .any(|&(a, b)| pc < b && a < i.next_ip32())
            {
                return Err("CRT IR: malformed/instruction-data overlap/node budget".into());
            }
            let raw = &code[offset..offset + i.len()];
            let op = extended(&i, raw, tables)?;
            let successors = match &op {
                Op::Ordinary(Operation::Return) | Op::ReturnPop(_) => vec![],
                Op::Ordinary(Operation::Jump(t)) => vec![*t],
                Op::Ordinary(Operation::Branch(_, t)) | Op::SignedBranch { target: t, .. } => {
                    vec![i.next_ip32(), *t]
                }
                Op::TableJump { targets, .. } => targets.clone(),
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
            offset += i.len();
        }
        for node in nodes.values() {
            for target in &node.successors {
                if !nodes.contains_key(target) {
                    if matches!(node.op,Op::Ordinary(Operation::Jump(t)) if t==*target)
                        && exits.contains(target)
                    {
                        used_exits.insert(*target);
                    } else {
                        return Err(
                            "CRT IR: branch/fallthrough outside instruction boundaries".into()
                        );
                    }
                }
            }
        }
        if used_exits.len() != exits.len() {
            return Err("CRT IR: unused external edge inventory".into());
        }
        let used: BTreeSet<_> = nodes
            .values()
            .filter_map(|n| {
                if let Op::TableJump { address, .. } = n.op {
                    Some(address)
                } else {
                    None
                }
            })
            .collect();
        if used.len() != tables.len() {
            return Err("CRT IR: unused source table".into());
        }
        for (&pc, node) in &nodes {
            if let Op::TableJump { index, targets, .. } = &node.op {
                let (&previous_pc, previous) = nodes
                    .range(..pc)
                    .next_back()
                    .ok_or("CRT IR: missing table guard")?;
                let (guard_end, bound) =
                    if let Op::Ordinary(Operation::ZeroExtend(dst, Operand::Memory(a, 8))) =
                        &previous.op
                    {
                        if dst != index
                            || a.base != Some(index.index)
                            || a.index.is_some()
                            || a.scale != 1
                            || previous_pc + previous.length != pc
                        {
                            return Err("CRT IR: table class map form".into());
                        }
                        let map = maps
                            .iter()
                            .find(|m| m.address == a.displacement)
                            .ok_or("CRT IR: class map lacks original bytes")?;
                        if map.bytes.iter().any(|&v| usize::from(v) >= targets.len()) {
                            return Err("CRT IR: class map exceeds target table".into());
                        }
                        used_maps.insert(map.address);
                        if nodes
                            .iter()
                            .any(|(&from, n)| n.successors.contains(&pc) && from != previous_pc)
                            || origin == pc
                        {
                            return Err("CRT IR: alternate entry bypasses class map".into());
                        }
                        (previous_pc, map.bytes.len() as u32 - 1)
                    } else {
                        (pc, targets.len() as u32 - 1)
                    };
                let (&branch_pc, branch) = nodes
                    .range(..guard_end)
                    .next_back()
                    .ok_or("CRT IR: missing table range branch")?;
                let (&compare_pc, compare) = nodes
                    .range(..branch_pc)
                    .next_back()
                    .ok_or("CRT IR: missing table compare")?;
                if branch_pc + branch.length != guard_end
                    || compare_pc + compare.length != branch_pc
                    || !matches!(branch.op,Op::Ordinary(Operation::Branch(graph::Condition::Above,t)) if t!=guard_end)
                    || compare.op
                        != Op::Ordinary(Operation::Binary(
                            Binary::Compare,
                            Operand::Reg(*index),
                            Operand::Immediate(bound),
                        ))
                    || nodes.iter().any(|(&from, n)| {
                        n.successors.contains(&guard_end) && from != branch_pc
                            || n.successors.contains(&branch_pc) && from != compare_pc
                    })
                    || origin == branch_pc
                    || origin == guard_end
                {
                    return Err("CRT IR: indexed JMP lacks dominating unsigned bound".into());
                }
            }
        }
        if used_maps.len() != maps.len() {
            return Err("CRT IR: unused class table".into());
        }
        let mut reached = BTreeSet::new();
        let mut todo = vec![origin];
        while let Some(pc) = todo.pop() {
            if used_exits.contains(&pc) {
                continue;
            }
            if !nodes.contains_key(&pc) {
                return Err("CRT IR: entry is table data".into());
            }
            if reached.insert(pc) {
                todo.extend(nodes[&pc].successors.iter().copied());
            }
        }
        if reached.len() != nodes.len() {
            return Err("CRT IR: hidden unreachable instructions".into());
        }
        if nodes
            .values()
            .any(|node| matches!(node.op, Op::IndirectCall(_)))
        {
            return Err("CRT IR: unbound call form".into());
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

#[cfg(test)]
mod linear_fragment_tests {
    #[test]
    fn explicit_cut_does_not_relax_complete_graph_or_accept_control_effects() {
        use super::Graph;
        let code = [0x55, 0x8b, 0xec, 0x83, 0xec, 0x1c];
        assert!(Graph::decode(&code, 0x1000).is_err());
        let graph = Graph::decode_linear_fragment(&code, 0x1000).unwrap();
        assert_eq!(graph.end, 0x1006);
        assert_eq!(graph.nodes.len(), 3);
        for code in [
            &[0xc3][..],
            &[0xeb, 0][..],
            &[0xe8, 0, 0, 0, 0][..],
            &[0x64, 0xa1, 0, 0, 0, 0][..],
            &[0x0f][..],
        ] {
            assert!(
                Graph::decode_linear_fragment(code, 0x1000).is_err(),
                "accepted {code:x?}"
            );
        }
        assert!(Graph::decode_linear_fragment(&[0x90], u32::MAX).is_err());
        assert!(Graph::decode_linear_fragment(&[0x90; 129], 0x1000).is_err());
    }
}
