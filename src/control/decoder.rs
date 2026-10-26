//! Strict production policy over iced decoding; library validity alone is insufficient.
use super::{Condition, Instruction, Op};
use iced_x86::{Code, Decoder, DecoderOptions, OpKind, Register};

pub(super) fn decode_instruction(bytes: &[u8], at: usize) -> Result<Instruction, String> {
    let tail = bytes.get(at..).ok_or("offset outside executable bytes")?;
    let opcode = *tail.first().ok_or("control flow leaves executable bytes")?;
    // A whitelist on the FIRST byte rejects every legacy prefix, including those
    // iced normalizes away. Code alone would accept segment/REP-prefixed forms.
    let (code, size) = match opcode {
        0xb8 => (Code::Mov_r32_imm32, 5),
        0x05 => (Code::Add_EAX_imm32, 5),
        0x3d => (Code::Cmp_EAX_imm32, 5),
        0x31 if tail.get(1) == Some(&0xc0) => (Code::Xor_rm32_r32, 2),
        0x68 => (Code::Pushd_imm32, 5),
        0x8b if tail.get(..4) == Some(&[0x8b, 0x44, 0x24, 4]) => (Code::Mov_r32_rm32, 4),
        0x8d if tail.get(..4) == Some(&[0x8d, 0x64, 0x24, 4]) => (Code::Lea_r32_m, 4),
        0xe8 => (Code::Call_rel32_32, 5),
        0xc3 => (Code::Retnd, 1),
        0x72 => (Code::Jb_rel8_32, 2),
        0x73 => (Code::Jae_rel8_32, 2),
        0x74 => (Code::Je_rel8_32, 2),
        0x75 => (Code::Jne_rel8_32, 2),
        0x7c => (Code::Jl_rel8_32, 2),
        0x7d => (Code::Jge_rel8_32, 2),
        _ => return Err("encoding outside exact subset".into()),
    };
    let ip = u32::try_from(at).map_err(|_| "offset exceeds 32-bit decoder domain")?;
    let mut decoder = Decoder::with_ip(32, tail, u64::from(ip), DecoderOptions::NONE);
    let decoded = decoder.decode();
    if decoded.is_invalid() {
        return Err(format!(
            "invalid or truncated instruction: {:?}",
            decoder.last_error()
        ));
    }
    if decoded.code() != code || decoded.len() != size {
        return Err("decoder form/length disagrees with subset".into());
    }
    let next = at.checked_add(size).ok_or("instruction offset overflow")?;
    let eax = |operand| {
        decoded.op_kind(operand) == OpKind::Register
            && decoded.op_register(operand) == Register::EAX
    };
    let op = match code {
        Code::Mov_r32_imm32 | Code::Add_EAX_imm32 | Code::Cmp_EAX_imm32 => {
            if decoded.op_count() != 2 || !eax(0) || decoded.op1_kind() != OpKind::Immediate32 {
                return Err("unsupported immediate operands".into());
            }
            match code {
                Code::Mov_r32_imm32 => Op::Mov(decoded.immediate32()),
                Code::Add_EAX_imm32 => Op::Add(decoded.immediate32()),
                _ => Op::Compare(decoded.immediate32()),
            }
        }
        Code::Xor_rm32_r32 => {
            if decoded.op_count() != 2 || !eax(0) || !eax(1) {
                return Err("unsupported XOR operands".into());
            }
            Op::Xor
        }
        Code::Pushd_imm32 => {
            if decoded.op_count() != 1 || decoded.op0_kind() != OpKind::Immediate32 {
                return Err("unsupported PUSH operand".into());
            }
            Op::PushData(decoded.immediate32())
        }
        Code::Mov_r32_rm32 | Code::Lea_r32_m => {
            let destination = if code == Code::Mov_r32_rm32 {
                Register::EAX
            } else {
                Register::ESP
            };
            if decoded.op_count() != 2
                || decoded.op0_kind() != OpKind::Register
                || decoded.op0_register() != destination
                || decoded.op1_kind() != OpKind::Memory
                || decoded.memory_base() != Register::ESP
                || decoded.memory_index() != Register::None
                || decoded.memory_index_scale() != 1
                || decoded.memory_displ_size() != 1
                || decoded.memory_displacement64() != 4
                || decoded.memory_segment() != Register::SS
            {
                return Err("unsupported stack address operands".into());
            }
            if code == Code::Mov_r32_rm32 {
                Op::LoadArgument
            } else {
                Op::DropData
            }
        }
        Code::Call_rel32_32 => {
            let displacement = i32::from_le_bytes(tail[1..5].try_into().unwrap());
            if displacement < 0 {
                return Err("backward calls are unsupported".into());
            }
            let target = next
                .checked_add(displacement as usize)
                .ok_or("call overflow")?;
            if decoded.op_count() != 1
                || decoded.op0_kind() != OpKind::NearBranch32
                || usize::try_from(decoded.near_branch_target()).ok() != Some(target)
            {
                return Err("call target/operand disagrees with subset".into());
            }
            Op::Call { target }
        }
        Code::Retnd => {
            if decoded.op_count() != 0 {
                return Err("unsupported RET operands".into());
            }
            Op::Ret
        }
        _ => {
            let displacement = tail[1] as i8; // Successful exact two-byte decode above.
            if displacement < 0 {
                return Err("backward branches are unsupported".into());
            }
            let target = next
                .checked_add(displacement as usize)
                .ok_or("branch overflow")?;
            if decoded.op_count() != 1
                || decoded.op0_kind() != OpKind::NearBranch32
                || usize::try_from(decoded.near_branch_target()).ok() != Some(target)
            {
                return Err("branch target/operand disagrees with subset".into());
            }
            let (condition, when) = match code {
                Code::Jb_rel8_32 => (Condition::Carry, true),
                Code::Jae_rel8_32 => (Condition::Carry, false),
                Code::Je_rel8_32 => (Condition::Zero, true),
                Code::Jne_rel8_32 => (Condition::Zero, false),
                Code::Jl_rel8_32 => (Condition::SignedLess, true),
                Code::Jge_rel8_32 => (Condition::SignedLess, false),
                _ => unreachable!(),
            };
            Op::Branch {
                condition,
                when,
                target,
            }
        }
    };
    Ok(Instruction { op, next })
}
