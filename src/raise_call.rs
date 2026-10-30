//! Original RaiseException call-site evidence, not a Windows context capture.
//!
//! The enclosing image proof must bind the IAT cell to the documented import.
//! These expressions describe guest state before/at the CALL; Windows may build
//! its exception CONTEXT inside the API and dispatcher. Argument rules follow
//! https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-raiseexception.
//! No equality between
//! those distinct states, no return, and no exception delivery is inferred here.
use super::frame_proof::{GuestRegister, ProvenFrame};
use iced_x86::{Code, Decoder, DecoderOptions, OpKind, Register};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArgumentRole {
    ExceptionCode,
    ExceptionFlags,
    ArgumentCount,
    NullArgumentArray,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ArgumentCell {
    pub role: ArgumentRole,
    /// Relative to the original guest function entry ESP, not the API CONTEXT.
    pub offset: i32,
    pub value: u32,
}
pub(crate) struct RaiseCallProof {
    pc: u32,
    next_pc: u32,
    iat: u32,
    arguments: [ArgumentCell; 4],
    registers: [GuestRegister; 8],
    known_register_bits: [(u32, u32); 8],
    known_flags: (u32, u32),
    caller_sp: i32,
    callee_sp: i32,
    normal_return_sp: i32,
}
impl RaiseCallProof {
    pub fn call_pc(&self) -> u32 {
        self.pc
    }
    pub fn next_pc(&self) -> u32 {
        self.next_pc
    }
    pub fn iat(&self) -> u32 {
        self.iat
    }
    pub fn event_code(&self) -> u32 {
        self.arguments[0].value
    }
    pub fn arguments(&self) -> &[ArgumentCell; 4] {
        &self.arguments
    }
    /// State before the CALL. StackOffset expressions use function entry ESP.
    pub fn registers(&self) -> &[GuestRegister; 8] {
        &self.registers
    }
    /// Static known bits; symbolic addresses and incoming identities retain
    /// zero knowledge masks, not numeric zero values.
    pub fn known_register_bits(&self) -> &[(u32, u32); 8] {
        &self.known_register_bits
    }
    pub fn known_flags(&self) -> (u32, u32) {
        self.known_flags
    }
    pub fn caller_sp_offset(&self) -> i32 {
        self.caller_sp
    }
    /// The original CALL pushes only its protected continuation word.
    pub fn callee_sp_offset(&self) -> i32 {
        self.callee_sp
    }
    /// Conditional stdcall result if normal return is independently justified.
    /// This getter is not authority to resume execution after RaiseException.
    pub fn normal_return_sp_offset(&self) -> i32 {
        self.normal_return_sp
    }
    pub fn temporary_bytes(&self) -> u32 {
        4
    }
    /// Complete caller frame plus this CALL's return slot, relative to entry.
    pub fn call_stack_extent(&self) -> u32 {
        self.callee_sp.unsigned_abs()
    }
}

pub(crate) fn prove_call(
    frame: &ProvenFrame,
    code: &[u8],
    origin: u32,
    iat: u32,
    event_code: u32,
) -> Result<RaiseCallProof, String> {
    if origin == 0
        || origin != frame.end()
        || code.len() != 6
        || code[..2] != [0xff, 0x15]
        || iat == 0
        || !iat.is_multiple_of(4)
        || iat.checked_add(4).is_none()
    {
        return Err("raise call: original boundary/form/IAT extent".into());
    }
    let next_pc = origin
        .checked_add(6)
        .ok_or("raise call: code range overflow")?;
    if origin < iat + 4 && iat < next_pc {
        return Err("raise call: IAT aliases original instructions".into());
    }
    let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.code() != Code::Call_rm32
        || instruction.op0_kind() != OpKind::Memory
        || instruction.memory_base() != Register::None
        || instruction.memory_index() != Register::None
        || instruction.memory_displacement32() != iat
        || instruction.next_ip32() != next_pc
        || decoder.can_decode()
    {
        return Err("raise call: exact bound original indirect call".into());
    }
    // Microsoft's API reserves bit28 and documents clearing it before message
    // display. Exclude that domain conservatively; this is not a claim that
    // every delivered exception record has its code bit cleared.
    if event_code & 0x1000_0000 != 0 || frame.pending_arguments() != [event_code, 0, 0, 0] {
        return Err("raise call: unproved code/continuability/count/buffer arguments".into());
    }
    let caller_sp = frame
        .ebp_offset()
        .checked_add(frame.esp_offset())
        .ok_or("raise call: caller stack offset")?;
    let callee_sp = caller_sp
        .checked_sub(4)
        .ok_or("raise call: protected return extent")?;
    let normal_return_sp = caller_sp
        .checked_add(16)
        .ok_or("raise call: conditional return stack extent")?;
    if caller_sp >= 0
        || callee_sp < -4100
        || normal_return_sp > 0
        || caller_sp % 4 != 0
        || frame.final_registers()[4] != GuestRegister::StackOffset(caller_sp)
    {
        return Err("raise call: original stack expression/extent".into());
    }
    let roles = [
        ArgumentRole::ExceptionCode,
        ArgumentRole::ExceptionFlags,
        ArgumentRole::ArgumentCount,
        ArgumentRole::NullArgumentArray,
    ];
    let arguments = std::array::from_fn(|i| ArgumentCell {
        role: roles[i],
        offset: caller_sp + i as i32 * 4,
        value: frame.pending_arguments()[i],
    });
    Ok(RaiseCallProof {
        pc: origin,
        next_pc,
        iat,
        arguments,
        registers: *frame.final_registers(),
        known_register_bits: frame.final_registers().map(GuestRegister::known_bits),
        known_flags: frame.known_flags(),
        caller_sp,
        callee_sp,
        normal_return_sp,
    })
}
