//! Instruction-derived Main initialization and bounded original fill-helper proof.
//! Feature words are initialized but unknown. The fill byte is symbolic and
//! destination low bits are exhaustively partitioned, not sampled addresses.
use super::frame_proof::ProvenFrame;
use super::graph::{self, Address, Binary, Operand, Operation};
use iced_x86::{
    Code, Decoder, DecoderOptions, Instruction, MemorySize, Mnemonic, OpKind, Register,
};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct FillHelper<'a> {
    pub code: &'a [u8],
    pub origin: u32,
    pub feature_words: [u32; 2],
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum V {
    Unknown,
    Number(u32),
    Pointer(i32),
    Stack,
    Saved(usize),
    Byte,
    Splat,
}
fn is_xmm(r: Register) -> bool {
    (Register::XMM0 as u32..=Register::XMM7 as u32).contains(&(r as u32))
}
fn memory_width(i: &Instruction) -> Result<usize, String> {
    match i.memory_size() {
        MemorySize::UInt8 => Ok(1),
        MemorySize::UInt32 => Ok(4),
        MemorySize::UInt128 | MemorySize::Packed128_UInt32 | MemorySize::Packed128_Float32 => {
            Ok(16)
        }
        _ => Err(format!(
            "fill: unsupported memory width {:?} {:?}",
            i.memory_size(),
            i.code()
        )),
    }
}
fn reg(r: Register) -> Result<usize, String> {
    match r {
        Register::EAX => Ok(0),
        Register::ECX => Ok(1),
        Register::EDX => Ok(2),
        Register::EBX => Ok(3),
        Register::ESP => Ok(4),
        Register::EBP => Ok(5),
        Register::ESI => Ok(6),
        Register::EDI => Ok(7),
        _ => Err("fill: register width".into()),
    }
}
fn number(v: V) -> Result<u32, String> {
    if let V::Number(n) = v {
        Ok(n)
    } else {
        Err("fill: unknown or typed scalar".into())
    }
}
struct FillState {
    regs: [V; 8],
    xmm: [Option<[V; 4]>; 8],
    written: Vec<bool>,
    count: u32,
    alignment: i32,
    features: [bool; 2],
    zero: Option<bool>,
    carry: Option<bool>,
}
impl FillState {
    fn new(count: u32, alignment: i32, features: [bool; 2]) -> Self {
        let mut regs = std::array::from_fn(|i| {
            if [3, 5, 6, 7].contains(&i) {
                V::Saved(i)
            } else {
                V::Unknown
            }
        });
        regs[4] = V::Stack;
        Self {
            regs,
            xmm: std::array::from_fn(|_| None),
            written: vec![false; count as usize],
            count,
            alignment,
            features,
            zero: None,
            carry: None,
        }
    }
    fn read_reg(&self, r: Register) -> Result<V, String> {
        if r == Register::AL {
            return match self.regs[0] {
                V::Byte | V::Splat => Ok(V::Byte),
                V::Number(n) => Ok(V::Number(n & 255)),
                _ => Err("fill: unknown AL".into()),
            };
        }
        Ok(self.regs[reg(r)?].clone())
    }
    fn address(&self, i: &Instruction) -> Result<V, String> {
        let displacement = i.memory_displacement32() as i32;
        let mut value = if i.memory_base() == Register::None {
            V::Number(0)
        } else {
            self.read_reg(i.memory_base())?
        };
        if i.memory_index() != Register::None {
            let n = number(self.read_reg(i.memory_index())?)?;
            let scaled = n
                .checked_mul(i.memory_index_scale())
                .ok_or("fill: index wrap")?;
            value = Self::add(value, V::Number(scaled))?;
        }
        match value {
            V::Pointer(n) => Ok(V::Pointer(
                n.checked_add(displacement)
                    .ok_or("fill: pointer offset overflow")?,
            )),
            V::Stack if displacement == 0 => Ok(V::Stack),
            V::Number(n) => Ok(V::Number(n.wrapping_add(displacement as u32))),
            V::Saved(_) if displacement == 0 => Ok(value),
            _ => Err("fill: address provenance".into()),
        }
    }
    fn operand(&self, i: &Instruction, n: u32) -> Result<V, String> {
        match i.op_kind(n) {
            OpKind::Register => self.read_reg(i.op_register(n)),
            OpKind::Immediate8 => Ok(V::Number(u32::from(i.immediate8()))),
            OpKind::Immediate8to32 => Ok(V::Number(i.immediate8to32() as u32)),
            OpKind::Immediate32 => Ok(V::Number(i.immediate32())),
            OpKind::Memory
                if i.memory_base() == Register::ESP && i.memory_index() == Register::None =>
            {
                if self.regs[4] != V::Stack {
                    return Err("fill: changed stack pointer".into());
                }
                match (i.memory_displacement32(), memory_width(i)?) {
                    (4, 4) => Ok(V::Pointer(0)),
                    (8, 1) => Ok(V::Byte),
                    (12, 4) => Ok(V::Number(self.count)),
                    _ => Err("fill: protected or unbound argument".into()),
                }
            }
            _ => Err("fill: unsupported read".into()),
        }
    }
    fn write(&mut self, i: &Instruction, value: V) -> Result<(), String> {
        match i.op0_kind() {
            OpKind::Register => {
                let r = reg(i.op0_register())?;
                if r == 4 {
                    return Err("fill: ESP write".into());
                }
                self.regs[r] = value;
                Ok(())
            }
            OpKind::Memory => {
                let width = memory_width(i)?;
                if !matches!((width, &value), (1, V::Byte) | (4, V::Splat)) {
                    return Err("fill: store is not original fill byte".into());
                }
                self.store(self.address(i)?, width, false)
            }
            _ => Err("fill: unsupported destination".into()),
        }
    }
    fn store(&mut self, address: V, width: usize, aligned: bool) -> Result<(), String> {
        let V::Pointer(at) = address else {
            return Err("fill: unowned write".into());
        };
        if at < 0 || (aligned && (at + self.alignment) % 16 != 0) {
            return Err("fill: range/alignment".into());
        }
        let end = (at as usize)
            .checked_add(width)
            .ok_or("fill: store overflow")?;
        let bytes = self
            .written
            .get_mut(at as usize..end)
            .ok_or("fill: write outside requested range")?;
        bytes.fill(true);
        Ok(())
    }
    fn add(a: V, b: V) -> Result<V, String> {
        match (a, b) {
            (V::Number(a), V::Number(b)) => Ok(V::Number(a.wrapping_add(b))),
            (V::Pointer(a), V::Number(b)) | (V::Number(b), V::Pointer(a)) => Ok(V::Pointer(
                a.checked_add(b as i32)
                    .ok_or("fill: pointer add overflow")?,
            )),
            _ => Err("fill: unsupported arithmetic provenance".into()),
        }
    }
    fn arithmetic(&mut self, i: &Instruction) -> Result<(), String> {
        let a = self.operand(i, 0)?;
        let b = self.operand(i, 1)?;
        let result = match i.mnemonic() {
            Mnemonic::Add => Self::add(a.clone(), b.clone())?,
            Mnemonic::Sub | Mnemonic::Cmp => match (a.clone(), b.clone()) {
                (V::Number(a), V::Number(b)) => V::Number(a.wrapping_sub(b)),
                (V::Pointer(a), V::Pointer(b)) => V::Number(a.wrapping_sub(b) as u32),
                (V::Pointer(a), V::Number(b)) => V::Pointer(
                    a.checked_sub(b as i32)
                        .ok_or("fill: pointer sub overflow")?,
                ),
                _ => return Err("fill: unsupported subtraction".into()),
            },
            Mnemonic::And | Mnemonic::Test => match (a.clone(), b.clone()) {
                (V::Number(a), V::Number(b)) => V::Number(a & b),
                (V::Pointer(a), V::Number(0xfffffff0)) if i.mnemonic() == Mnemonic::And => {
                    V::Pointer(
                        (a.checked_add(self.alignment)
                            .ok_or("fill: alignment overflow")?
                            & !15)
                            - self.alignment,
                    )
                }
                _ => return Err("fill: unsupported mask".into()),
            },
            _ => return Err("fill: arithmetic instruction".into()),
        };
        self.zero = if let V::Number(n) = result {
            Some(n == 0)
        } else {
            None
        };
        self.carry = match (i.mnemonic(), a, b) {
            (Mnemonic::Sub | Mnemonic::Cmp, V::Number(a), V::Number(b)) => Some(a < b),
            (Mnemonic::Sub | Mnemonic::Cmp, V::Pointer(a), V::Pointer(b)) => Some(a < b),
            (Mnemonic::Add, V::Number(a), V::Number(b)) => Some(a.overflowing_add(b).1),
            (Mnemonic::And | Mnemonic::Test, _, _) => Some(false),
            _ => None,
        };
        if !matches!(i.mnemonic(), Mnemonic::Cmp | Mnemonic::Test) {
            self.write(i, result)?;
        }
        Ok(())
    }
}

/// All low-address-bit and feature-bit classes are proved. Other bits of the
/// feature words are irrelevant only because original BT consumes exactly bit 1.
/// Destination arithmetic is symbolic relative to a nonwrapping owned range.
/// The entry contract is valid writable storage, DF clear and flat ES, with
/// initialized feature words and original instruction availability. This is a
/// memory/return/nonvolatile effect certificate: callers must forget volatile
/// GPR, status-flag and XMM facts, not expose a fabricated complete CPU snapshot.
pub(crate) fn prove_fill(helper: &FillHelper<'_>, count: u32) -> Result<(), String> {
    if count > 16384
        || helper.code.is_empty()
        || helper.code.len() > 2048
        || helper
            .origin
            .checked_add(helper.code.len() as u32)
            .is_none()
        || helper.feature_words[0] == helper.feature_words[1]
        || helper
            .feature_words
            .iter()
            .any(|n| *n == 0 || n % 4 != 0 || n.checked_add(4).is_none())
    {
        return Err("fill: extent/binding budget".into());
    }
    let mut decoder = Decoder::with_ip(
        32,
        helper.code,
        u64::from(helper.origin),
        DecoderOptions::NONE,
    );
    let mut instructions = BTreeMap::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        if i.is_invalid() || instructions.len() >= 256 {
            return Err("fill: malformed instruction/budget".into());
        }
        instructions.insert(i.ip32(), i);
    }
    for alignment in 0..16 {
        for feature in 0..4 {
            let mut state = FillState::new(count, alignment, [feature & 1 != 0, feature & 2 != 0]);
            let mut pc = helper.origin;
            let mut steps = 0u32;
            loop {
                steps += 1;
                if steps > 100_000 {
                    return Err("fill: proof budget exhausted".into());
                }
                let i = instructions
                    .get(&pc)
                    .ok_or("fill: branch outside original boundaries")?;
                if i.has_lock_prefix()
                    || i.has_repne_prefix()
                    || i.segment_prefix() != Register::None
                {
                    return Err("fill: unsupported prefix".into());
                }
                let at = (pc - helper.origin) as usize;
                let raw = &helper.code[at..at + i.len()];
                let required_prefix: Option<&[u8]> = match i.code() {
                    Code::Stosb_m8_AL => Some(&[0xf3, 0xaa]),
                    Code::Movd_xmm_rm32 => Some(&[0x66, 0x0f, 0x6e]),
                    Code::Pshufd_xmm_xmmm128_imm8 => Some(&[0x66, 0x0f, 0x70]),
                    Code::Movdqa_xmmm128_xmm => Some(&[0x66, 0x0f, 0x7f]),
                    Code::Movdqu_xmmm128_xmm => Some(&[0xf3, 0x0f, 0x7f]),
                    _ => None,
                };
                if let Some(prefix) = required_prefix {
                    if !raw.starts_with(prefix) {
                        return Err("fill: exact prefix/form policy".into());
                    }
                } else if matches!(
                    raw[0],
                    0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3
                ) {
                    return Err("fill: unsupported instruction prefix".into());
                }
                if i.has_rep_prefix()
                    && !matches!(i.code(), Code::Stosb_m8_AL | Code::Movdqu_xmmm128_xmm)
                {
                    return Err("fill: unsupported repetition".into());
                }
                let mut next = i.next_ip32();
                match i.mnemonic() {
                    Mnemonic::Mov => {
                        let v = state.operand(i, 1)?;
                        state.write(i, v)?;
                    }
                    Mnemonic::Movzx
                        if i.op0_register() == Register::EAX && memory_width(i)? == 1 =>
                    {
                        state.regs[0] = state.operand(i, 1)?;
                    }
                    Mnemonic::Imul if i.op_count() == 3 => {
                        if state.operand(i, 1)? != V::Byte
                            || number(state.operand(i, 2)?)? != 0x01010101
                        {
                            return Err("fill: unproved multiplication".into());
                        }
                        state.regs[reg(i.op0_register())?] = V::Splat;
                        state.zero = None;
                        state.carry = None;
                    }
                    Mnemonic::Add
                    | Mnemonic::Sub
                    | Mnemonic::And
                    | Mnemonic::Cmp
                    | Mnemonic::Test => state.arithmetic(i)?,
                    Mnemonic::Inc => {
                        let r = reg(i.op0_register())?;
                        state.regs[r] = FillState::add(state.regs[r].clone(), V::Number(1))?;
                        state.zero = if let V::Number(n) = state.regs[r] {
                            Some(n == 0)
                        } else {
                            None
                        };
                    }
                    Mnemonic::Lea => {
                        let value = state.address(i)?;
                        let r = reg(i.op0_register())?;
                        if r == 4 && value != V::Stack {
                            return Err("fill: stack LEA".into());
                        }
                        state.regs[r] = value;
                    }
                    Mnemonic::Nop => {}
                    Mnemonic::Bt => {
                        if i.op0_kind() != OpKind::Memory
                            || i.memory_base() != Register::None
                            || i.memory_index() != Register::None
                            || memory_width(i)? != 4
                            || i.op1_kind() != OpKind::Immediate8
                            || i.immediate8() != 1
                        {
                            return Err("fill: feature read form".into());
                        }
                        let index = helper
                            .feature_words
                            .iter()
                            .position(|&a| a == i.memory_displacement32())
                            .ok_or("fill: unbound feature read")?;
                        state.carry = Some(state.features[index]);
                        state.zero = None;
                    }
                    Mnemonic::Movd
                        if i.op0_kind() == OpKind::Register && is_xmm(i.op0_register()) =>
                    {
                        let x = (i.op0_register() as usize) - (Register::XMM0 as usize);
                        if x >= 8 {
                            return Err("fill: vector register".into());
                        }
                        state.xmm[x] = Some([
                            state.operand(i, 1)?,
                            V::Number(0),
                            V::Number(0),
                            V::Number(0),
                        ]);
                    }
                    Mnemonic::Pshufd => {
                        if !is_xmm(i.op0_register())
                            || !is_xmm(i.op1_register())
                            || i.op2_kind() != OpKind::Immediate8
                        {
                            return Err("fill: shuffle form".into());
                        }
                        let dst = (i.op0_register() as usize) - (Register::XMM0 as usize);
                        let src = (i.op1_register() as usize) - (Register::XMM0 as usize);
                        if dst >= 8 || src >= 8 {
                            return Err("fill: vector register".into());
                        }
                        let value = state.xmm[src].clone().ok_or("fill: unknown vector")?;
                        let mask = i.immediate8();
                        state.xmm[dst] = Some(std::array::from_fn(|n| {
                            value[usize::from((mask >> (2 * n)) & 3)].clone()
                        }));
                    }
                    Mnemonic::Movups | Mnemonic::Movdqa | Mnemonic::Movdqu => {
                        if i.op0_kind() != OpKind::Memory
                            || !is_xmm(i.op1_register())
                            || memory_width(i)? != 16
                        {
                            return Err("fill: vector store form".into());
                        }
                        let x = (i.op1_register() as usize) - (Register::XMM0 as usize);
                        if x >= 8 || state.xmm[x] != Some([V::Splat, V::Splat, V::Splat, V::Splat])
                        {
                            return Err("fill: vector contains unknown/nonfill bits".into());
                        }
                        state.store(state.address(i)?, 16, i.mnemonic() == Mnemonic::Movdqa)?;
                    }
                    Mnemonic::Stosb => {
                        if !i.has_rep_prefix() || state.read_reg(Register::AL)? != V::Byte {
                            return Err("fill: STOS contract".into());
                        }
                        let n = number(state.regs[1].clone())?;
                        state.store(state.regs[7].clone(), n as usize, false)?;
                        state.regs[7] = FillState::add(state.regs[7].clone(), V::Number(n))?;
                        state.regs[1] = V::Number(0);
                    }
                    Mnemonic::Je
                    | Mnemonic::Jne
                    | Mnemonic::Jb
                    | Mnemonic::Jae
                    | Mnemonic::Jbe
                    | Mnemonic::Ja => {
                        let take = match i.mnemonic() {
                            Mnemonic::Je => state.zero,
                            Mnemonic::Jne => state.zero.map(|b| !b),
                            Mnemonic::Jb => state.carry,
                            Mnemonic::Jae => state.carry.map(|b| !b),
                            Mnemonic::Jbe => state.carry.zip(state.zero).map(|(c, z)| c || z),
                            _ => state.carry.zip(state.zero).map(|(c, z)| !c && !z),
                        }
                        .ok_or("fill: unknown branch flags")?;
                        if !instructions.contains_key(&i.near_branch32()) {
                            return Err("fill: branch target".into());
                        }
                        if take {
                            next = i.near_branch32();
                        }
                    }
                    Mnemonic::Jmp if i.op0_kind() == OpKind::NearBranch32 => {
                        next = i.near_branch32()
                    }
                    Mnemonic::Ret if i.code() == Code::Retnd => {
                        if state.regs[0] != V::Pointer(0)
                            || state.regs[4] != V::Stack
                            || [3, 5, 6, 7].iter().any(|&r| state.regs[r] != V::Saved(r))
                            || state.written.iter().any(|b| !*b)
                        {
                            return Err("fill: incomplete footprint/ABI return".into());
                        }
                        break;
                    }
                    _ => {
                        return Err(format!(
                            "fill: unproved original instruction {:?} at {pc:#x}",
                            i.code()
                        ))
                    }
                }
                // The symbolic destination is any nonwrapping owned interval.
                // Keep every intermediate pointer within that interval, including
                // one-past, so a representative low-bit class cannot hide wrap.
                if state
                    .regs
                    .iter()
                    .any(|v| matches!(v,V::Pointer(n) if *n<0 || i64::from(*n)>i64::from(count)))
                {
                    return Err("fill: intermediate pointer leaves proved interval".into());
                }
                pc = next;
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
enum MainValue {
    Unknown,
    Scalar(u32),
    Stack(i32),
    Module,
}
#[derive(Debug)]
pub(crate) struct ProvenInitialization {
    body: String,
    end: u32,
    try_level: i32,
    fill_range: (i32, u32),
    module_slot: i32,
    temporary_bytes: u32,
}
impl ProvenInitialization {
    pub fn body(&self) -> &str {
        &self.body
    }
    pub fn end(&self) -> u32 {
        self.end
    }
    pub fn try_level(&self) -> i32 {
        self.try_level
    }
    pub fn fill_range(&self) -> (i32, u32) {
        self.fill_range
    }
    pub fn module_slot(&self) -> i32 {
        self.module_slot
    }
    pub fn temporary_bytes(&self) -> u32 {
        self.temporary_bytes
    }
}
fn main_address(address: &Address, regs: &[MainValue; 8]) -> Result<i32, String> {
    if address.index.is_some() {
        return Err("initializer: indexed address".into());
    }
    let Some(base) = address.base else {
        return Err("initializer: absolute memory access".into());
    };
    let MainValue::Stack(base) = regs[base as usize] else {
        return Err("initializer: unowned address".into());
    };
    base.checked_add(address.displacement as i32)
        .ok_or("initializer: address overflow".into())
}
fn main_operand(operand: &Operand, regs: &[MainValue; 8]) -> Result<MainValue, String> {
    match operand {
        Operand::Immediate(n) => Ok(MainValue::Scalar(*n)),
        Operand::Reg(r) if r.width == 32 && r.shift == 0 => Ok(regs[r.index as usize].clone()),
        _ => Err("initializer: unsupported source".into()),
    }
}
pub(crate) fn prove_initializer(
    frame: &ProvenFrame,
    code: &[u8],
    origin: u32,
    helper: &FillHelper<'_>,
    module_iat: u32,
) -> Result<ProvenInitialization, String> {
    if origin != frame.end()
        || code.is_empty()
        || code.len() > 512
        || module_iat == 0
        || !module_iat.is_multiple_of(4)
    {
        return Err("initializer: discontinuous extent/binding".into());
    }
    let end = origin
        .checked_add(code.len() as u32)
        .ok_or("initializer: extent overflow")?;
    let mut regs = std::array::from_fn(|_| MainValue::Unknown);
    regs[4] = MainValue::Stack(frame.esp_offset());
    regs[5] = MainValue::Stack(0);
    let initial_sp = frame.esp_offset();
    let mut sp = initial_sp;
    let mut minimum_sp = initial_sp;
    let mut args = BTreeMap::new();
    let mut body = String::new();
    let mut fill_range = None;
    let mut module_slot = None;
    let mut level = None;
    let mut module_called = false;
    let mut initialized_words = BTreeSet::new();
    let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
    while decoder.can_decode() {
        let i = decoder.decode();
        if i.is_invalid() {
            return Err("initializer: malformed instruction".into());
        }
        let at = (i.ip32() - origin) as usize;
        let operation = if i.code() == Code::Call_rel32_32 && code[at] == 0xe8 {
            Operation::Call(Operand::Immediate(i.near_branch32()))
        } else {
            graph::normalized(&i, &code[at..at + i.len()])?
        };
        match operation {
            Operation::Push(value) => {
                let value = main_operand(&value, &regs)?;
                if matches!(value, MainValue::Unknown) {
                    return Err("initializer: unknown pushed argument".into());
                }
                sp = sp.checked_sub(4).ok_or("initializer: stack underflow")?;
                if sp < initial_sp - 64 || args.insert(sp, value).is_some() {
                    return Err("initializer: argument ownership/budget".into());
                }
                regs[4] = MainValue::Stack(sp);
            }
            Operation::Address(dst, address)
                if dst.width == 32 && dst.shift == 0 && dst.index != 4 && dst.index != 5 =>
            {
                regs[dst.index as usize] = MainValue::Stack(main_address(&address, &regs)?);
            }
            Operation::Binary(Binary::Add, Operand::Reg(r), Operand::Immediate(n))
                if r.index == 4 && r.width == 32 && n % 4 == 0 =>
            {
                let next = sp
                    .checked_add(i32::try_from(n).map_err(|_| "initializer: cleanup size")?)
                    .ok_or("initializer: cleanup overflow")?;
                if next > initial_sp || (sp..next).step_by(4).any(|at| !args.contains_key(&at)) {
                    return Err("initializer: cleanup consumes protected word".into());
                }
                args.retain(|&offset, _| offset >= next);
                sp = next;
                regs[4] = MainValue::Stack(sp);
            }
            Operation::Binary(Binary::Move, Operand::Reg(r), src)
                if r.width == 32 && r.shift == 0 && r.index != 4 && r.index != 5 =>
            {
                regs[r.index as usize] = main_operand(&src, &regs)?
            }
            Operation::Binary(Binary::Move, Operand::Memory(address, 32), src) => {
                let offset = main_address(&address, &regs)?;
                let value = main_operand(&src, &regs)?;
                if offset == frame.try_level_offset() {
                    let MainValue::Scalar(value) = value else {
                        return Err("initializer: unknown TryLevel".into());
                    };
                    if level.replace(value as i32).is_some() {
                        return Err("initializer: multiple activation stores".into());
                    }
                    body.push_str(&format!("memory.write_try_level({}i32)?;\n", value as i32));
                } else {
                    if !frame.ordinary_words().contains(&offset) {
                        return Err("initializer: protected destination".into());
                    }
                    if !initialized_words.insert(offset) {
                        return Err("initializer: overlapping initialization effects".into());
                    }
                    match value {
                        MainValue::Scalar(n) => {
                            if frame
                                .scalar_words()
                                .get(&offset)
                                .is_some_and(|&prior| prior != n)
                            {
                                return Err("initializer: changes an earlier scalar proof".into());
                            }
                            body.push_str(&format!("memory.write_u32({offset},{n}u32)?;\n"))
                        }
                        MainValue::Module => {
                            if frame.scalar_words().contains_key(&offset) {
                                return Err(
                                    "initializer: replaces an earlier scalar with a module".into(),
                                );
                            }
                            if module_slot.replace(offset).is_some() {
                                return Err("initializer: repeated module store".into());
                            }
                            body.push_str(&format!("memory.write_module({offset},module)?;\n"));
                        }
                        _ => return Err("initializer: unknown/unsupported stored value".into()),
                    }
                }
            }
            Operation::Call(Operand::Immediate(target)) if target == helper.origin => {
                minimum_sp = minimum_sp.min(
                    sp.checked_sub(4)
                        .ok_or("initializer: return slot overflow")?,
                );
                if fill_range.is_some() {
                    return Err("initializer: duplicate fill call".into());
                }
                let Some(MainValue::Stack(destination)) = args.get(&sp) else {
                    return Err("initializer: fill destination provenance".into());
                };
                let Some(MainValue::Scalar(byte)) = args.get(&(sp + 4)) else {
                    return Err("initializer: fill byte".into());
                };
                let Some(MainValue::Scalar(count)) = args.get(&(sp + 8)) else {
                    return Err("initializer: fill count".into());
                };
                let destination = *destination;
                let count = *count;
                let byte = *byte as u8;
                if count == 0 || count > 16384 {
                    return Err("initializer: fill range budget".into());
                }
                let limit = i64::from(destination) + i64::from(count);
                let mut filled_words = BTreeSet::new();
                for at in i64::from(destination)..limit {
                    let at = i32::try_from(at).map_err(|_| "initializer: fill overflow")?;
                    let word = at.div_euclid(4) * 4;
                    if !frame.ordinary_words().contains(&word) {
                        return Err("initializer: fill touches protected/unallocated bytes".into());
                    }
                    if initialized_words.contains(&word)
                        || frame.scalar_words().get(&word).is_some_and(|prior| {
                            prior.to_le_bytes()[at.rem_euclid(4) as usize] != byte
                        })
                    {
                        return Err("initializer: fill aliases an earlier value proof".into());
                    }
                    filled_words.insert(word);
                }
                initialized_words.extend(filled_words);
                prove_fill(helper, count)?;
                body.push_str(&format!("memory.fill({destination},{count},{byte})?;\n"));
                fill_range = Some((destination, count));
                regs[0] = MainValue::Stack(destination);
                regs[1] = MainValue::Unknown;
                regs[2] = MainValue::Unknown;
            }
            Operation::Call(Operand::Memory(address, 32))
                if address.base.is_none()
                    && address.index.is_none()
                    && address.displacement == module_iat =>
            {
                minimum_sp = minimum_sp.min(
                    sp.checked_sub(4)
                        .ok_or("initializer: return slot overflow")?,
                );
                if module_called || !matches!(args.get(&sp), Some(MainValue::Scalar(0))) {
                    return Err("initializer: module API domain".into());
                }
                args.remove(&sp);
                sp += 4;
                regs[4] = MainValue::Stack(sp);
                regs[0] = MainValue::Module;
                regs[1] = MainValue::Unknown;
                regs[2] = MainValue::Unknown;
                module_called = true;
            }
            _ => {
                return Err(format!(
                    "initializer: unproved original effect {:?}",
                    i.code()
                ))
            }
        }
    }
    if sp != initial_sp || !args.is_empty() || !module_called {
        return Err("initializer: unbalanced arguments or missing module call".into());
    }
    body = format!(
        "memory.preflight_call_stack({})?;\n{body}Ok(())\n",
        initial_sp - minimum_sp
    );
    Ok(ProvenInitialization {
        body,
        end,
        try_level: level.ok_or("initializer: missing TryLevel")?,
        fill_range: fill_range.ok_or("initializer: missing fill")?,
        module_slot: module_slot.ok_or("initializer: missing module result")?,
        temporary_bytes: u32::try_from(initial_sp - minimum_sp)
            .map_err(|_| "initializer: temporary stack extent")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scalar_fill() -> Vec<u8> {
        // Independently authored cdecl fill: symbolic AL, counted byte stores.
        vec![
            0x8b, 0x4c, 0x24, 0x0c, 0x0f, 0xb6, 0x44, 0x24, 8, 0x8b, 0xd7, 0x8b, 0x7c, 0x24, 4,
            0x85, 0xc9, 0x74, 8, 0x88, 7, 0x47, 0x83, 0xe9, 1, 0x75, 0xf8, 0x8b, 0x44, 0x24, 4,
            0x8b, 0xfa, 0xc3,
        ]
    }
    fn helper(code: &[u8]) -> FillHelper<'_> {
        FillHelper {
            code,
            origin: 0x4000,
            feature_words: [0x8000, 0x8004],
        }
    }
    fn frame() -> ProvenFrame {
        frame_with_stores(&[])
    }
    fn frame_with_stores(stores: &[u8]) -> ProvenFrame {
        // Separate compact prolog; no captured original stack/register inputs.
        let mut code = vec![
            0x55, 0x8b, 0xec, 0x6a, 0xfe, 0x68, 0, 0x50, 0, 0, 0x68, 0, 0x60, 0, 0, 0x64, 0xa1, 0,
            0, 0, 0, 0x50, 0x83, 0xec, 0x20, 0x53, 0x56, 0x57, 0xa1, 0, 0x70, 0, 0, 0x31, 0x45,
            0xf8, 0x33, 0xc5, 0x50, 0x8d, 0x45, 0xf0, 0x64, 0xa3, 0, 0, 0, 0,
        ];
        code.extend(stores);
        super::super::frame_proof::prove_frame(
            &code,
            0x1000,
            0x7000,
            &std::collections::BTreeSet::from([0x5000]),
            &std::collections::BTreeSet::from([0x6000]),
        )
        .unwrap()
    }
    fn initializer(origin: u32, count: u8) -> Vec<u8> {
        let mut code = vec![
            0x6a, count, 0x68, 0x78, 0x56, 0x34, 0x12, 0x8d, 0x45, 0xe0, 0x50, 0xe8,
        ];
        code.extend(0x4000u32.wrapping_sub(origin + 16).to_le_bytes());
        code.extend([
            0x83, 0xc4, 0x0c, 0x6a, 0, 0xff, 0x15, 0, 0x90, 0, 0, 0x89, 0x45, 0xdc, 0xc7, 0x45,
            0xfc, 0, 0, 0, 0,
        ]);
        code
    }
    #[test]
    fn independent_fill_all_alignments_and_symbolic_bytes() {
        let code = scalar_fill();
        for count in [0, 1, 3, 4, 7, 15, 16, 17, 31, 32, 33, 127, 128, 716] {
            prove_fill(&helper(&code), count).unwrap();
        }
        // All 256 possible low bytes are symbolic in the certificate, not 256
        // observed executions. Native byte stores are checked separately.
    }
    #[test]
    fn independent_fill_rejects_wrong_footprints_registers_flags_and_prefixes() {
        let code = scalar_fill();
        for (offset, value) in [(20, 0x06), (21, 0x46), (23, 0xe8), (26, 0xf7), (32, 0xf8)] {
            let mut mutation = code.clone();
            mutation[offset] = value;
            assert!(
                prove_fill(&helper(&mutation), 17).is_err(),
                "mutation {offset}"
            );
        }
        let mut prefix = vec![0x67];
        prefix.extend(&code);
        assert!(prove_fill(&helper(&prefix), 17).is_err());
        let mut unknown = code.clone();
        unknown[16] = 0xd2;
        assert!(prove_fill(&helper(&unknown), 17).is_err());
        assert!(prove_fill(&helper(&code), 16385).is_err());
        let no_progress = [0xeb, 0xfe];
        assert!(prove_fill(&helper(&no_progress), 1)
            .unwrap_err()
            .contains("budget"));
    }
    #[test]
    fn unknown_feature_selects_independent_rep_and_vector_paths() {
        // Different instruction layout and XMM register from the retained CRT.
        // Feature=1 uses REP, feature=0 a full unaligned vector write. Both must
        // establish the same footprint for every destination alignment.
        let code = vec![
            0x8b, 0x4c, 0x24, 0x0c, 0x0f, 0xb6, 0x44, 0x24, 8, 0x8b, 0xd7, 0x8b, 0x7c, 0x24, 4,
            0x69, 0xc0, 1, 1, 1, 1, 0x0f, 0xba, 0x25, 0, 0x80, 0, 0, 1, 0x73, 4, 0xf3, 0xaa, 0xeb,
            13, 0x66, 0x0f, 0x6e, 0xc8, 0x66, 0x0f, 0x70, 0xc9, 0, 0xf3, 0x0f, 0x7f, 0x0f, 0x8b,
            0x44, 0x24, 4, 0x8b, 0xfa, 0xc3,
        ];
        prove_fill(&helper(&code), 16).unwrap();
        assert!(prove_fill(&helper(&code), 15).is_err());
        assert!(prove_fill(&helper(&code), 17).is_err());
        let mut zero_lane = code.clone();
        zero_lane[43] = 0x55;
        assert!(prove_fill(&helper(&zero_lane), 16).is_err());
        let mut aligned = code.clone();
        aligned[44] = 0x66;
        assert!(prove_fill(&helper(&aligned), 16).is_err());
        let mut feature_bit = code.clone();
        feature_bit[28] = 2;
        assert!(prove_fill(&helper(&feature_bit), 16).is_err());
        let mut wrong_abi = code.clone();
        wrong_abi[52] = 0xc0;
        assert!(prove_fill(&helper(&wrong_abi), 16).is_err());
    }
    #[test]
    fn original_instruction_arguments_bind_fill_module_and_activation() {
        let frame = frame();
        let fill = scalar_fill();
        let code = initializer(frame.end(), 8);
        let proof = prove_initializer(&frame, &code, frame.end(), &helper(&fill), 0x9000).unwrap();
        assert_eq!(proof.fill_range(), (-32, 8));
        assert_eq!(proof.module_slot(), -36);
        assert_eq!(proof.try_level(), 0);
        assert_eq!(proof.temporary_bytes(), 16);
        assert!(proof.body().contains("memory.fill(-32,8,120)?"));
        assert!(prove_initializer(&frame, &code, frame.end() + 1, &helper(&fill), 0x9000).is_err());
        let mut protected = code.clone();
        protected[9] = 0xfc;
        assert!(
            prove_initializer(&frame, &protected, frame.end(), &helper(&fill), 0x9000).is_err()
        );
        let oversized = initializer(frame.end(), 20);
        assert!(
            prove_initializer(&frame, &oversized, frame.end(), &helper(&fill), 0x9000).is_err()
        );
        let mut named_module = code.clone();
        named_module[20] = 1;
        assert!(
            prove_initializer(&frame, &named_module, frame.end(), &helper(&fill), 0x9000).is_err()
        );
        let mut cleanup = code.clone();
        cleanup[18] = 16;
        assert!(prove_initializer(&frame, &cleanup, frame.end(), &helper(&fill), 0x9000).is_err());
        assert!(prove_initializer(&frame, &code, frame.end(), &helper(&fill), 0x9004).is_err());
    }
    #[test]
    fn initializer_does_not_invalidate_prior_scalar_or_later_result_proofs() {
        let fill = scalar_fill();
        let frame = frame_with_stores(&[0xc7, 0x45, 0xe0, 1, 0, 0, 0]);
        let code = initializer(frame.end(), 8);
        assert!(
            prove_initializer(&frame, &code, frame.end(), &helper(&fill), 0x9000)
                .unwrap_err()
                .contains("earlier value")
        );
        let frame = frame_with_stores(&[0xc7, 0x45, 0xd8, 1, 0, 0, 0]);
        let mut code = initializer(frame.end(), 8);
        code.extend([0xc7, 0x45, 0xd8, 2, 0, 0, 0]);
        assert!(
            prove_initializer(&frame, &code, frame.end(), &helper(&fill), 0x9000)
                .unwrap_err()
                .contains("earlier scalar")
        );
        let frame = frame_with_stores(&[]);
        let mut code = initializer(frame.end(), 8);
        let at = code
            .windows(3)
            .position(|b| b == [0x89, 0x45, 0xdc])
            .unwrap();
        code[at + 2] = 0xe0;
        assert!(
            prove_initializer(&frame, &code, frame.end(), &helper(&fill), 0x9000)
                .unwrap_err()
                .contains("overlapping")
        );
        let mut code = initializer(frame.end(), 8);
        code.extend([0xc7, 0x45, 0xdc, 0, 0, 0, 0]);
        assert!(
            prove_initializer(&frame, &code, frame.end(), &helper(&fill), 0x9000)
                .unwrap_err()
                .contains("overlapping")
        );
    }
    #[test]
    fn emitted_initializer_executes_owned_range_and_typed_module_effect() {
        let frame = frame();
        let fill = scalar_fill();
        let code = initializer(frame.end(), 8);
        let proof = prove_initializer(&frame, &code, frame.end(), &helper(&fill), 0x9000).unwrap();
        let source = format!(
            r#"#![allow(dead_code)]
{}
{}
fn prefix<P:Clone>(entry_sp:u32,cookie:u32,saved:[Option<u32>;8],predecessor:P)->Result<FrameImage<P>,&'static str>{{{}}}
fn run<P>(memory:&mut FrameMemory<P>,module:GuestModule)->Result<(),&'static str>{{{}}}
fn main(){{
 let mut image=prefix(0x10000,0xabcdef12,[None;8],"incoming root").unwrap();
 let mut memory=FrameMemory::new(&mut image,3,&{:?}).unwrap();
 run(&mut memory,GuestModule{{owner:3,base:0x400000}}).unwrap();
 assert_eq!(memory.read_u32(-32).unwrap(),0x78787878);
 assert_eq!(memory.read_u32(-28).unwrap(),0x78787878);
 assert!(memory.read_u32(-24).is_err());
 assert_eq!(memory.read_module(-36).unwrap(),0x400000);
 assert_eq!(memory.image.try_level,0);
 assert!(matches!(memory.image.words.get(&-20),Some(FrameWord::Borrowed("incoming root"))));
}}
"#,
            super::super::frame_proof::EMITTED_TYPES,
            super::super::frame_memory::EMITTED_TYPES,
            frame.initializer_body(),
            proof.body(),
            frame.ordinary_words().iter().copied().collect::<Vec<_>>()
        );
        let directory =
            std::env::temp_dir().join(format!("w2l-frame-initializer-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("main.rs");
        std::fs::write(&path, source).unwrap();
        let output = directory.join(if cfg!(windows) { "main.exe" } else { "main" });
        let result = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(&path)
            .arg("-o")
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(std::process::Command::new(output)
            .status()
            .unwrap()
            .success());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
