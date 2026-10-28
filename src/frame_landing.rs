//! Original selected-handler landing, owned context stores and nonlocal Restore.
//! This proves an instruction fragment, not delivery of a Windows exception or
//! whole-program startup. Layout authority must come from the original prolog.
use super::graph::{self, Address, Binary, Operand, Operation, Reg};
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, OpKind};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct Layout<'a> {
    pub ordinary_words: &'a BTreeSet<i32>,
    /// Protected word offset -> original pointed-to stack offset, relative EBP.
    pub stack_words: &'a BTreeMap<i32, i32>,
    pub stack_offset: i32,
    pub try_level_offset: i32,
}

pub(crate) struct ProvenLanding {
    /// These three bodies share a lexical scope and the same live FrameMemory.
    /// Run all of them inside the selected-frame restoration lease. No supplied
    /// saved-register values or post-hoc cleanup receipt can replace execution.
    pub prepare_source: String,
    pub restore_source: String,
    pub observation_source: String,
    pub context_offset: i32,
    pub target: u32,
    pub end: u32,
    /// Maximum original argument/return scratch depth below recovered ESP.
    /// The enclosing address map must preflight it against bound image regions
    /// and other still-live frames; numeric non-wrap checks alone are not enough.
    temporary_bytes: u32,
    /// Original post-transfer stores: restored register index -> frame offset.
    pub observations: BTreeMap<u8, i32>,
    pub final_words: BTreeMap<i32, InitializedWord>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InitializedWord {
    Scalar,
    Stack,
    Continuation,
}
impl ProvenLanding {
    pub fn temporary_bytes(&self) -> u32 {
        self.temporary_bytes
    }
}

#[derive(Clone)]
enum Value {
    Unknown,
    Scalar(String),
    Stack(i32, String),
    Address(i32),
    Continuation(u32),
}

struct State<'a> {
    layout: Layout<'a>,
    registers: [Value; 8],
    written: BTreeMap<i32, Value>,
    source: String,
    serial: usize,
}

fn full(reg: Reg) -> bool {
    reg.width == 32 && reg.shift == 0 && reg.index < 8
}

impl State<'_> {
    fn ordinary(&self, offset: i32) -> Result<(), String> {
        if offset < self.layout.stack_offset
            || offset >= 0
            || offset % 4 != 0
            || !self.layout.ordinary_words.contains(&offset)
        {
            return Err("landing: ordinary full-word ownership".into());
        }
        Ok(())
    }
    fn address(&self, address: &Address) -> Result<i32, String> {
        if address.index.is_some() {
            return Err("landing: indexed address outside proof".into());
        }
        let base = match address.base.and_then(|r| self.registers.get(r as usize)) {
            Some(Value::Address(offset) | Value::Stack(offset, _)) => *offset,
            _ => return Err("landing: frame pointer provenance".into()),
        };
        base.checked_add(address.displacement as i32)
            .ok_or_else(|| "landing: frame address overflow".into())
    }
    fn snapshot(&mut self, expression: String) -> String {
        let name = format!("landing_v{}", self.serial);
        self.serial += 1;
        self.source
            .push_str(&format!("let {name}:u32={expression};\n"));
        name
    }
    fn read(&mut self, operand: &Operand) -> Result<Value, String> {
        match operand {
            Operand::Immediate(value) => Ok(Value::Scalar(format!("{value}u32"))),
            Operand::Reg(reg) if full(*reg) => match &self.registers[reg.index as usize] {
                Value::Unknown => Err("landing: unknown register".into()),
                value => Ok(value.clone()),
            },
            Operand::Memory(address, 32) => {
                let offset = self.address(address)?;
                if let Some(&target) = self.layout.stack_words.get(&offset) {
                    let name = self.snapshot(format!("memory.read_stack({offset})?"));
                    self.source.push_str(&format!("if {name}!=frame_address(memory.frame_pointer(),{target})?{{return Err(\"landing saved stack identity\");}}\n"));
                    return Ok(Value::Stack(target, name));
                }
                self.ordinary(offset)?;
                match self.written.get(&offset).cloned() {
                    Some(Value::Scalar(_)) => Ok(Value::Scalar(
                        self.snapshot(format!("memory.read_u32({offset})?")),
                    )),
                    Some(Value::Stack(target, _) | Value::Address(target)) => Ok(Value::Stack(
                        target,
                        self.snapshot(format!("memory.read_stack({offset})?")),
                    )),
                    Some(Value::Continuation(target)) => {
                        let name = self.snapshot(format!("memory.read_continuation({offset})?"));
                        self.source.push_str(&format!("if {name}!={target}u32{{return Err(\"landing continuation identity\");}}\n"));
                        Ok(Value::Continuation(target))
                    }
                    _ => Err("landing: uninitialized or unproved context read".into()),
                }
            }
            _ => Err("landing: unsupported source width/form".into()),
        }
    }
    fn write(&mut self, operand: &Operand, value: Value) -> Result<(), String> {
        match operand {
            Operand::Reg(reg) if full(*reg) && reg.index <= 2 => {
                self.registers[reg.index as usize] = value;
            }
            Operand::Reg(reg) if full(*reg) && reg.index == 4 => {
                let Value::Stack(offset, expression) = &value else {
                    return Err("landing: unproved stack restoration".into());
                };
                if *offset != self.layout.stack_offset {
                    return Err("landing: stack restoration identity".into());
                }
                self.source
                    .push_str(&format!("memory.set_stack_pointer({expression})?;\n"));
                self.registers[4] = value;
            }
            Operand::Memory(address, 32) => {
                let offset = self.address(address)?;
                self.ordinary(offset)?;
                match &value {
                    Value::Scalar(expression) => self
                        .source
                        .push_str(&format!("memory.write_u32({offset},{expression})?;\n")),
                    Value::Stack(_, expression) => self
                        .source
                        .push_str(&format!("memory.write_stack({offset},{expression})?;\n")),
                    Value::Address(target) => self.source.push_str(&format!(
                        "memory.write_stack({offset},frame_address(memory.frame_pointer(),{target})?)?;\n"
                    )),
                    Value::Continuation(target) => self.source.push_str(&format!(
                        "memory.write_continuation({offset},{target})?;\n"
                    )),
                    Value::Unknown => return Err("landing: unknown store".into()),
                }
                self.written.insert(offset, value);
            }
            _ => return Err("landing: protected destination/width".into()),
        }
        Ok(())
    }
}

fn decode(code: &[u8], origin: u32, budget: usize) -> Result<BTreeMap<u32, Instruction>, String> {
    if origin == 0 || code.is_empty() || code.len() > 1024 {
        return Err("landing: code resource bounds".into());
    }
    origin
        .checked_add(code.len() as u32)
        .ok_or("landing: code overflow")?;
    let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
    let mut instructions = BTreeMap::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        if i.is_invalid() || instructions.len() >= budget {
            return Err("landing: malformed instruction/budget".into());
        }
        instructions.insert(i.ip() as u32, i);
    }
    Ok(instructions)
}

fn original_bytes(code: &[u8], origin: u32, instruction: &Instruction) -> Vec<u8> {
    let at = (instruction.ip() as u32 - origin) as usize;
    code[at..at + instruction.len()].to_vec()
}

fn restore(
    state: &mut State<'_>,
    code: &[u8],
    origin: u32,
    context_offset: i32,
    before_call_sp: i32,
) -> Result<u32, String> {
    let instructions = decode(code, origin, 8)?;
    let mut owner = None;
    let mut loaded = BTreeSet::new();
    for instruction in instructions.values() {
        let bytes = original_bytes(code, origin, instruction);
        if instruction.code() == Code::Jmp_rm32 {
            if bytes.first() != Some(&0xff)
                || instruction.op0_kind() != OpKind::Memory
                || instruction.memory_index() != iced_x86::Register::None
                || Some(instruction.memory_base()) != owner
                || instruction.segment_prefix() != iced_x86::Register::None
                || instruction.next_ip() != u64::from(origin) + code.len() as u64
                || loaded != BTreeSet::from([0, 4, 5])
            {
                return Err("landing restore: terminal transfer policy".into());
            }
            let offset = context_offset
                .checked_add(instruction.memory_displacement32() as i32)
                .ok_or("landing restore: target offset overflow")?;
            state.ordinary(offset)?;
            let Some(Value::Continuation(target)) = state.written.get(&offset).cloned() else {
                return Err("landing restore: continuation provenance".into());
            };
            state.source.push_str(&format!("let landing_target=memory.read_continuation({offset})?;if landing_target!={target}u32{{return Err(\"landing restore target\");}}\nlanding_context[8]=Some(landing_target);\n"));
            return Ok(target);
        }
        let Operation::Binary(Binary::Move, Operand::Reg(dst), Operand::Memory(address, 32)) =
            graph::normalized(instruction, &bytes)?
        else {
            return Err("landing restore: unsupported effect".into());
        };
        if !full(dst) {
            return Err("landing restore: partial destination".into());
        }
        if owner.is_none() {
            if !matches!(dst.index, 1 | 2)
                || address.base != Some(4)
                || address.index.is_some()
                || address.displacement != 4
            {
                return Err("landing restore: actual pushed context argument".into());
            }
            // The original PUSH stores this same owned frame capability; CALL
            // places its protected return word below it. No host pointer cast.
            owner = Some(instruction.op0_register());
            state.registers[dst.index as usize] = Value::Address(context_offset);
            continue;
        }
        if Some(instruction.memory_base()) != owner
            || address.index.is_some()
            || !matches!(dst.index, 0 | 4 | 5)
            || !loaded.insert(dst.index)
        {
            return Err("landing restore: field owner/destination".into());
        }
        let value = state.read(&Operand::Memory(address, 32))?;
        match (dst.index, &value) {
            (0, Value::Scalar(expression)) => state
                .source
                .push_str(&format!("landing_context[0]=Some({expression});\n")),
            (4, Value::Stack(offset, expression)) if *offset == before_call_sp => {
                state.source.push_str(&format!("memory.set_stack_pointer({expression})?;landing_context[4]=Some({expression});\n"));
            }
            (5, Value::Stack(0, expression)) => state.source.push_str(&format!("if {expression}!=memory.frame_pointer(){{return Err(\"landing restore frame identity\");}}landing_context[5]=Some({expression});\n")),
            _ => return Err("landing restore: scalar/stack/parent identity".into()),
        }
        state.registers[dst.index as usize] = value;
    }
    Err("landing restore: missing nonlocal transfer".into())
}

/// Code spans the selected landing through the post-restore observation stores.
/// All bytes must decode, but fallthrough after the proven nonlocal CALL is not
/// executed. The bound Restore body must consume the actual pushed capability,
/// restore this frame's original SP/BP, and jump to an in-fragment boundary.
/// Temporary argument/return words use a private typed call adapter; writable,
/// fault-free original stack space remains an explicit enclosing cut premise.
/// Emitted bodies require `memory: &mut FrameMemory<P>` and leave
/// `landing_context: [Option<u32>;10]`; only actually restored fields are Some.
pub(crate) fn prove_landing(
    code: &[u8],
    origin: u32,
    restore_code: &[u8],
    restore_va: u32,
    layout: Layout<'_>,
) -> Result<ProvenLanding, String> {
    let instructions = decode(code, origin, 64)?;
    let end = origin + code.len() as u32;
    let restore_end = restore_va
        .checked_add(restore_code.len() as u32)
        .ok_or("landing: restore extent")?;
    if origin < restore_end && restore_va < end {
        return Err("landing: code region alias".into());
    }
    if layout.ordinary_words.len() > 4096
        || layout.stack_words.is_empty()
        || layout.stack_words.len() > 64
        || layout.stack_offset >= 0
        || layout.stack_offset % 4 != 0
        || layout.try_level_offset >= 0
        || layout.try_level_offset % 4 != 0
        || layout.ordinary_words.contains(&layout.try_level_offset)
        || layout.stack_words.keys().any(|at| {
            layout.ordinary_words.contains(at) || *at == layout.try_level_offset || *at % 4 != 0
        })
    {
        return Err("landing: frame layout authority".into());
    }
    let mut registers = std::array::from_fn(|_| Value::Unknown);
    // The selected landing is entered from exception dispatch. The current
    // thread ESP is not the saved Main ESP until the original MOV establishes
    // it; the owned image's persistent stack field does not prove entry state.
    registers[5] = Value::Address(0);
    let mut state = State {
        source: "let mut landing_context:[Option<u32>;10]=[None;10];\n".into(),
        layout,
        registers,
        written: BTreeMap::new(),
        serial: 0,
    };
    let mut cursor = origin;
    let mut argument = None;
    let mut argument_bytes = 0u32;
    let mut temporary_bytes = 0u32;
    let mut prepared = None;
    let mut restored = None;
    let mut context_offset = None;
    let mut target = None;
    let mut inactive = false;
    let mut selected_sp = false;
    let mut observations = BTreeMap::new();
    let mut visited = BTreeSet::new();
    while cursor != end {
        if !visited.insert(cursor) {
            return Err("landing: cycle outside proof".into());
        }
        let instruction = instructions
            .get(&cursor)
            .ok_or("landing: instruction target")?;
        let bytes = original_bytes(code, origin, instruction);
        if instruction.code() == Code::Call_rel32_32 {
            if bytes.first() != Some(&0xe8)
                || bytes.len() != 5
                || instruction.near_branch32() != restore_va
                || target.is_some()
                || !inactive
                || !selected_sp
            {
                return Err("landing: bound Restore call/phase".into());
            }
            let offset = argument
                .take()
                .ok_or("landing: missing pushed context owner")?;
            let Value::Stack(before_call_sp, _) = state.registers[4] else {
                return Err("landing: call stack provenance".into());
            };
            let call_bytes = argument_bytes
                .checked_add(4)
                .ok_or("landing: protected call stack extent")?;
            temporary_bytes = temporary_bytes.max(call_bytes);
            state.source.push_str(&format!("let landing_call_sp=memory.stack_pointer();frame_address(landing_call_sp,-{argument_bytes})?;frame_address(landing_call_sp,-{call_bytes})?;let _landing_return_va={}u32;\n",instruction.next_ip()));
            prepared = Some(std::mem::take(&mut state.source));
            let destination =
                restore(&mut state, restore_code, restore_va, offset, before_call_sp)?;
            if destination <= instruction.next_ip() as u32
                || !instructions.contains_key(&destination)
            {
                return Err("landing: nonlocal target boundary/order".into());
            }
            restored = Some(std::mem::take(&mut state.source));
            context_offset = Some(offset);
            target = Some(destination);
            argument_bytes = 0;
            cursor = destination;
            continue;
        }
        let operation = graph::normalized(instruction, &bytes)?;
        match operation {
            Operation::Address(reg, address) if full(reg) && reg.index <= 2 => {
                if target.is_some() || argument.is_some() || address.index.is_some() {
                    return Err("landing: address phase/index".into());
                }
                state.registers[reg.index as usize] = if address.base.is_none() {
                    if !instructions.contains_key(&address.displacement) {
                        return Err("landing: code pointer boundary".into());
                    }
                    Value::Continuation(address.displacement)
                } else {
                    let offset = state.address(&address)?;
                    state.ordinary(offset)?;
                    Value::Address(offset)
                };
            }
            Operation::Push(Operand::Reg(reg)) if full(reg) && reg.index <= 2 => {
                if target.is_some() || argument.is_some() {
                    return Err("landing: argument stack shape".into());
                }
                let Value::Address(offset) = state.registers[reg.index as usize] else {
                    return Err("landing: argument ownership".into());
                };
                state.ordinary(offset)?;
                argument = Some(offset);
                argument_bytes = argument_bytes
                    .checked_add(4)
                    .ok_or("landing: argument stack extent")?;
                temporary_bytes = temporary_bytes.max(argument_bytes);
            }
            Operation::Binary(Binary::Move, dst, src) => {
                if argument.is_some() {
                    return Err("landing: effect between argument PUSH and CALL".into());
                }
                if let Operand::Memory(address, 32) = &dst {
                    let offset = state.address(address)?;
                    if offset == state.layout.try_level_offset {
                        if inactive || target.is_some() || src != Operand::Immediate((-2i32) as u32)
                        {
                            return Err("landing: inactive TryLevel transition".into());
                        }
                        state.source.push_str("memory.write_try_level(-2)?;\n");
                        inactive = true;
                        cursor = instruction.next_ip() as u32;
                        continue;
                    }
                    if target.is_some() {
                        let Operand::Reg(reg) = &src else {
                            return Err("landing: restored observation source".into());
                        };
                        if !full(*reg)
                            || !matches!(reg.index, 0 | 4 | 5)
                            || observations.insert(reg.index, offset).is_some()
                            || observations.values().filter(|&&v| v == offset).count() != 1
                        {
                            return Err("landing: distinct restored observations".into());
                        }
                    }
                } else if target.is_some() {
                    return Err("landing: effect after restoration outside observation cut".into());
                }
                let value = state.read(&src)?;
                if let Operand::Reg(reg) = &dst {
                    if reg.index == 4 {
                        if selected_sp || target.is_some() {
                            return Err("landing: repeated selected stack transition".into());
                        }
                        selected_sp = true;
                    }
                }
                state.write(&dst, value)?;
            }
            _ => return Err("landing: unsupported reachable instruction".into()),
        }
        cursor = instruction.next_ip() as u32;
    }
    if observations.keys().copied().collect::<BTreeSet<_>>() != BTreeSet::from([0, 4, 5]) {
        return Err("landing: incomplete original post-transfer observations".into());
    }
    let final_words = state
        .written
        .iter()
        .map(|(&offset, value)| {
            let kind = match value {
                Value::Scalar(_) => InitializedWord::Scalar,
                Value::Stack(..) | Value::Address(_) => InitializedWord::Stack,
                Value::Continuation(_) => InitializedWord::Continuation,
                Value::Unknown => return Err("landing: unknown final initialized word".to_string()),
            };
            Ok((offset, kind))
        })
        .collect::<Result<_, String>>()?;
    Ok(ProvenLanding {
        prepare_source: prepared.ok_or("landing: missing Restore preparation")?,
        restore_source: restored.ok_or("landing: missing Restore execution")?,
        observation_source: state.source,
        context_offset: context_offset.ok_or("landing: missing context capability")?,
        target: target.ok_or("landing: missing target")?,
        end,
        temporary_bytes,
        observations,
        final_words,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    const ORIGIN: u32 = 0x7000;
    const RESTORE: u32 = 0x9000;
    const CONTEXT: i32 = -256;
    const SP: i32 = -352;
    const RESTORE_BYTES: &[u8] = &[
        0x8b, 0x4c, 0x24, 4, 0x8b, 0x81, 176, 0, 0, 0, 0x8b, 0xa1, 196, 0, 0, 0, 0x8b, 0xa9, 180,
        0, 0, 0, 0xff, 0xa1, 184, 0, 0, 0,
    ];
    fn ordinary() -> BTreeSet<i32> {
        (SP..-28).step_by(4).collect()
    }
    fn fixture(eax: u32, context: i32, origin: u32) -> (Vec<u8>, u32) {
        let mut bytes = vec![0x8b, 0x65, 0xe8, 0xc7, 0x85];
        bytes.extend((-316i32).to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.extend([0xc7, 0x45, 0xfc, 0xfe, 0xff, 0xff, 0xff, 0x8d, 0x8d]);
        bytes.extend(context.to_le_bytes());
        bytes.extend([0xc7, 0x81]);
        bytes.extend(176u32.to_le_bytes());
        bytes.extend(eax.to_le_bytes());
        bytes.extend([0x89, 0xa1]);
        bytes.extend(196u32.to_le_bytes());
        bytes.extend([0x89, 0xa9]);
        bytes.extend(180u32.to_le_bytes());
        bytes.extend([0x8d, 0x05]);
        let target_at = bytes.len();
        bytes.extend([0; 4]);
        bytes.extend([0x89, 0x81]);
        bytes.extend(184u32.to_le_bytes());
        bytes.extend([0x51, 0xe8]);
        let next = origin + bytes.len() as u32 + 4;
        bytes.extend(RESTORE.wrapping_sub(next).to_le_bytes());
        // Original nonlocal Restore must skip this global side effect. It is
        // structurally decoded, but cannot enter the emitted reachable path.
        bytes.extend([0x83, 0x0d, 0, 0, 0xa0, 0, 0x40]);
        let target = origin + bytes.len() as u32;
        bytes[target_at..target_at + 4].copy_from_slice(&target.to_le_bytes());
        for (reg, offset) in [(0, -304i32), (4, -308), (5, -312)] {
            bytes.extend([0x89, 0x85 | (reg << 3)]);
            bytes.extend(offset.to_le_bytes());
        }
        (bytes, target)
    }
    fn prove(code: &[u8], restore: &[u8]) -> Result<ProvenLanding, String> {
        prove_landing(
            code,
            ORIGIN,
            restore,
            RESTORE,
            Layout {
                ordinary_words: &ordinary(),
                stack_words: &BTreeMap::from([(-24, SP)]),
                stack_offset: SP,
                try_level_offset: -4,
            },
        )
    }
    fn replace(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
        assert_eq!(from.len(), to.len());
        let mut result = bytes.to_vec();
        let positions: Vec<_> = bytes
            .windows(from.len())
            .enumerate()
            .filter_map(|(i, b)| (b == from).then_some(i))
            .collect();
        assert_eq!(positions.len(), 1, "mutation must bind one original form");
        result[positions[0]..positions[0] + from.len()].copy_from_slice(to);
        result
    }

    #[test]
    fn derives_context_and_target_from_original_stores_and_call() {
        for (eax, context) in [(0, CONTEXT), (255, -264), (u32::MAX, -280)] {
            let (bytes, target) = fixture(eax, context, ORIGIN);
            let p = prove(&bytes, RESTORE_BYTES).unwrap();
            assert_eq!(p.context_offset, context);
            assert_eq!(p.target, target);
            assert_eq!(p.end, ORIGIN + bytes.len() as u32);
            assert_eq!(p.temporary_bytes(), 8);
            assert_eq!(
                p.observations,
                BTreeMap::from([(0, -304), (4, -308), (5, -312)])
            );
            assert!(p.prepare_source.contains(&format!("{eax}u32")));
            assert!(p.restore_source.contains("memory.read_u32"));
            assert!(p.restore_source.contains("memory.read_stack"));
            assert!(!p.restore_source.contains("read_saved"));
            assert!(!p.observation_source.contains("10485760"));
            let again = prove(&bytes, RESTORE_BYTES).unwrap();
            assert_eq!(p.prepare_source, again.prepare_source);
            assert_eq!(p.restore_source, again.restore_source);
            assert_eq!(p.observation_source, again.observation_source);
        }
    }

    #[test]
    fn rejects_swapped_fields_protected_aliases_and_unknown_context() {
        let (bytes, _) = fixture(77, CONTEXT, ORIGIN);
        // Scalar EAX cannot be read as saved ESP, and stack addresses cannot be
        // laundered into scalar EAX merely because all fields are 32-bit words.
        for (from, to) in [
            ([0x8b, 0x81, 176, 0, 0, 0], [0x8b, 0x81, 196, 0, 0, 0]),
            ([0x8b, 0xa1, 196, 0, 0, 0], [0x8b, 0xa1, 176, 0, 0, 0]),
            ([0x8b, 0xa1, 196, 0, 0, 0], [0x8b, 0xa1, 180, 0, 0, 0]),
            ([0x8b, 0xa9, 180, 0, 0, 0], [0x8b, 0xa9, 196, 0, 0, 0]),
            ([0x8b, 0x81, 176, 0, 0, 0], [0x8b, 0x81, 172, 0, 0, 0]),
        ] {
            assert!(prove(&bytes, &replace(RESTORE_BYTES, &from, &to)).is_err());
        }
        for context in [-200, -201, 0, i32::MAX] {
            assert!(prove(&fixture(77, context, ORIGIN).0, RESTORE_BYTES).is_err());
        }
        let protected_observation = replace(
            &bytes,
            &[0x89, 0x85, 0xd0, 0xfe, 0xff, 0xff],
            &[0x89, 0x85, 0xe4, 0xff, 0xff, 0xff],
        );
        assert!(prove(&protected_observation, RESTORE_BYTES).is_err());
        let wrong_saved_sp = replace(&bytes, &[0x8b, 0x65, 0xe8], &[0x8b, 0x65, 0xe4]);
        assert!(prove(&wrong_saved_sp, RESTORE_BYTES).is_err());
        // A stale allocated word below the current frame SP is not live local
        // authority: the original PUSH/CALL may overwrite that region.
        let mut below_sp = ordinary();
        below_sp.insert(SP - 4);
        let stale_context = fixture(77, SP - 4, ORIGIN).0;
        assert!(prove_landing(
            &stale_context,
            ORIGIN,
            RESTORE_BYTES,
            RESTORE,
            Layout {
                ordinary_words: &below_sp,
                stack_words: &BTreeMap::from([(-24, SP)]),
                stack_offset: SP,
                try_level_offset: -4
            }
        )
        .is_err());
    }

    #[test]
    fn rejects_invalid_stack_targets_call_forms_and_extent() {
        let (bytes, target) = fixture(77, CONTEXT, ORIGIN);
        for bad in [target + 1, ORIGIN, target - 7, target + 18, 0] {
            let mut from = vec![0x8d, 5];
            from.extend(target.to_le_bytes());
            let mut to = vec![0x8d, 5];
            to.extend(bad.to_le_bytes());
            assert!(prove(&replace(&bytes, &from, &to), RESTORE_BYTES).is_err());
        }
        assert!(prove(
            &replace(&bytes, &[0x51, 0xe8], &[0x50, 0xe8]),
            RESTORE_BYTES
        )
        .is_err());
        let mut extra_push = bytes.clone();
        let push = bytes.windows(2).position(|v| v == [0x51, 0xe8]).unwrap();
        extra_push.insert(push, 0x51);
        assert!(prove(&extra_push, RESTORE_BYTES).is_err());
        for end in [1, 2, bytes.len() - 1, bytes.len() - 6] {
            assert!(prove(&bytes[..end], RESTORE_BYTES).is_err());
        }
        let mut prefixed = RESTORE_BYTES.to_vec();
        prefixed.insert(0, 0x66);
        assert!(prove(&bytes, &prefixed).is_err());
        let mut trailing = RESTORE_BYTES.to_vec();
        trailing.push(0x90);
        assert!(prove(&bytes, &trailing).is_err());
        assert!(prove(
            &replace(
                &bytes,
                &[0xc7, 0x45, 0xfc, 0xfe, 0xff, 0xff, 0xff],
                &[0xc7, 0x45, 0xfc, 0, 0, 0, 0]
            ),
            RESTORE_BYTES
        )
        .is_err());
        // Current thread ESP is unknown at the selected landing. A persistent
        // owned frame SP is not authority to read that register before the
        // original saved-stack load (even if EAX is later overwritten).
        let mut unknown_entry_sp = vec![0x89, 0xe0]; // MOV EAX,ESP
        unknown_entry_sp.extend(&bytes);
        let result = prove(&unknown_entry_sp, RESTORE_BYTES).err().unwrap();
        assert!(result.contains("unknown register"), "{result}");
    }

    #[test]
    fn emitted_landing_uses_live_owned_context_without_supplied_saved_values() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "w2l-landing-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).unwrap();
        let mut source = format!(
            "#![allow(dead_code)]\n{}\n{}\n",
            super::super::frame_proof::EMITTED_TYPES,
            super::super::frame_memory::EMITTED_TYPES,
        );
        for (index, eax) in [0, 255, u32::MAX].into_iter().enumerate() {
            let (bytes, target) = fixture(eax, CONTEXT, ORIGIN);
            let p = prove(&bytes, RESTORE_BYTES).unwrap();
            source.push_str(&format!(
                "fn run{index}(memory:&mut FrameMemory<()>)->Result<[Option<u32>;10],&'static str>{{{}{}{}Ok(landing_context)}}\n",
                p.prepare_source,p.restore_source,p.observation_source
            ));
            source.push_str(&format!("fn check{index}(){{let ordinary:Vec<i32>=(-352..-28).step_by(4).collect();let mut words=std::collections::BTreeMap::new();for &o in &ordinary{{words.insert(o-4,FrameWord::Unknown);}}words.insert(-28,FrameWord::StackAddress(0x8e9c));words.insert(-8,FrameWord::Scalar(0));let mut image=FrameImage{{words,entry_sp:0x9000,ebp:0x8ffc,esp:0x8e9c,record:0x8fec,scope_va:0x5000,handler_va:0x6000,try_level:0}};let mut memory=FrameMemory::new(&mut image,1,&ordinary).unwrap();let result=run{index}(&mut memory).unwrap();assert_eq!(result,[Some({eax}),None,None,None,Some(0x8e9c),Some(0x8ffc),None,None,Some({target}),None]);assert_eq!(memory.read_u32(-316),Ok(1));assert_eq!(memory.read_u32(-304),Ok({eax}));assert_eq!(memory.read_stack(-308),Ok(0x8e9c));assert_eq!(memory.read_stack(-312),Ok(0x8ffc));assert_eq!(memory.read_u32({}),Ok({eax}));assert_eq!(memory.read_stack({}),Ok(0x8e9c));assert_eq!(memory.read_stack({}),Ok(0x8ffc));assert_eq!(memory.read_continuation({}),Ok({target}));assert_eq!(memory.stack_pointer(),0x8e9c);drop(memory);assert_eq!(image.try_level,-2);}}\n", CONTEXT+176,CONTEXT+196,CONTEXT+180,CONTEXT+184));
        }
        source.push_str("fn main(){check0();check1();check2();}\n");
        let rust = directory.join("native.rs");
        let executable = directory.join("native");
        fs::write(&rust, source).unwrap();
        let compilation = Command::new("rustc")
            .args(["--edition=2021", "-Dwarnings"])
            .arg(&rust)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            compilation.status.success(),
            "{}",
            String::from_utf8_lossy(&compilation.stderr)
        );
        let run = Command::new(&executable).output().unwrap();
        assert!(
            run.status.success(),
            "{}",
            String::from_utf8_lossy(&run.stderr)
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
