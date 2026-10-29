//! Instruction-derived EH4 handler routing after the verified common prefix.
//!
//! This is a caller proof with explicit, still-required callee contracts. It is
//! not a Windows dispatcher implementation or an emission/admission token. In
//! particular, GlobalUnwind's target-preservation footprint must be established
//! by the enclosing original-helper/API composition before this plan may run.
use super::graph::{self, Address, Binary, Condition, Operand, Operation, Reg};
use super::handler_checks::PrefixProof;
use super::selection::{self, FilterLayout, FilterProof, OriginalFilter};
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy)]
pub(crate) struct Bindings {
    pub filter_bridge: u32,
    pub global_unwind: u32,
    pub local_unwind: u32,
    pub guard: u32,
    pub selected_transfer: u32,
    pub cookie: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KnownFlags {
    pub mask: u32,
    pub value: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Entry {
    Search,
    /// The recorded original prefix flag branch is taken. Only explicit unwind
    /// bits in its mask are admitted; delivery/nested-state closure is separate.
    Unwind {
        flags: KnownFlags,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Argument {
    ExceptionRecord,
    Establisher,
    OwnerFrame,
    ScopeTable,
    CookieAddress(u32),
    ScopeLevel(i32),
    CodeTarget(u32),
}

pub(crate) enum Action {
    Filter {
        pc: u32,
        bridge: u32,
        scope: i32,
        target: u32,
        arguments: Vec<Argument>,
        proof: FilterProof,
    },
    /// Required contract: unwind younger registrations only, preserve this
    /// target's words/identity/TryLevel and resume this original wrapper call.
    GlobalUnwind {
        pc: u32,
        target: u32,
        arguments: Vec<Argument>,
        preserved_level: i32,
    },
    /// Required contract: execute the bound original local-unwind body. Its
    /// certificate must establish `after`; this action never supplies cleanup
    /// targets or a precomputed cleanup order to the runtime.
    LocalUnwind {
        pc: u32,
        target: u32,
        arguments: Vec<Argument>,
        before: i32,
        stop: i32,
        after: i32,
    },
    ValidateGuards {
        pc: u32,
        target: u32,
        arguments: Vec<Argument>,
    },
    StoreTryLevel {
        pc: u32,
        before: i32,
        after: i32,
    },
    Transfer {
        pc: u32,
        bridge: u32,
        arguments: Vec<Argument>,
        scope: i32,
        landing: u32,
    },
    ReturnDisposition {
        pc: u32,
        value: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InstructionStep {
    pub pc: u32,
    pub next: Option<u32>,
    /// The original encoding is retained for auditing, not decoded at runtime.
    pub bytes: Vec<u8>,
}

pub(crate) struct DispatchProof {
    #[allow(dead_code)] // Retained for native live-source table binding.
    pub source_table: Vec<u8>,
    pub actions: Vec<Action>,
    pub instructions: Vec<InstructionStep>,
    pub final_level: i32,
    pub temporary_bytes: u32,
    /// Original handler-entry ESP to callee-entry ESP, including this CALL's
    /// protected return word. Callee-local depth is added by the composition.
    pub call_depths: Vec<(u32, u32)>,
    /// Unexecuted external calls remain inventoried. Their exclusion follows
    /// the actual known event/filter operands, never an application identity.
    pub unexecuted_calls: Vec<(u32, Option<u32>)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Unknown,
    Scalar(u32),
    LowByte(u8),
    Handler(i32),
    Table(i32),
    Establisher,
    Owner,
    Record,
    Context,
    Code(u32),
    Saved(u8),
    Return,
}
#[derive(Clone, Copy, Debug)]
struct Flags {
    zero: bool,
    sign: bool,
    overflow: bool,
    carry: bool,
}

#[derive(Clone)]
enum Decoded {
    Normal(Operation),
    Call(u32),
    SignedBranch { greater: bool, target: u32 },
    Trap,
}
struct Node {
    instruction: Instruction,
    bytes: Vec<u8>,
    operation: Decoded,
}
#[derive(Clone)]
struct Row {
    parent: i32,
    filter: u32,
    landing: u32,
}

fn full(reg: Reg) -> Result<usize, String> {
    if reg.width != 32 || reg.shift != 0 || reg.index >= 8 {
        return Err("dispatch: register width".into());
    }
    Ok(reg.index as usize)
}

fn decode(code: &[u8], origin: u32) -> Result<BTreeMap<u32, Node>, String> {
    if origin == 0
        || code.is_empty()
        || code.len() > 1024
        || origin.checked_add(code.len() as u32).is_none()
    {
        return Err("dispatch: instruction extent".into());
    }
    let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
    let mut nodes = BTreeMap::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        if i.is_invalid() || nodes.len() >= 256 {
            return Err("dispatch: instruction boundary/budget".into());
        }
        let at = i.ip32();
        let bytes = code[(at - origin) as usize..(at - origin) as usize + i.len()].to_vec();
        let operation = if i.code() == Code::Call_rel32_32 && bytes.len() == 5 && bytes[0] == 0xe8 {
            Decoded::Call(i.near_branch32())
        } else if (i.mnemonic() == Mnemonic::Js
            && (bytes.first() == Some(&0x78) || bytes.starts_with(&[0x0f, 0x88])))
            || (i.mnemonic() == Mnemonic::Jg
                && (bytes.first() == Some(&0x7f) || bytes.starts_with(&[0x0f, 0x8f])))
        {
            Decoded::SignedBranch {
                greater: i.mnemonic() == Mnemonic::Jg,
                target: i.near_branch32(),
            }
        } else if bytes == [0xcc] {
            Decoded::Trap
        } else {
            Decoded::Normal(graph::normalized(&i, &bytes)?)
        };
        nodes.insert(
            at,
            Node {
                instruction: i,
                bytes,
                operation,
            },
        );
    }
    for node in nodes.values() {
        let target = match &node.operation {
            Decoded::SignedBranch { target, .. } => Some(*target),
            Decoded::Normal(Operation::Branch(_, target) | Operation::Jump(target)) => {
                Some(*target)
            }
            _ => None,
        };
        if target.is_some_and(|t| !nodes.contains_key(&t)) {
            return Err("dispatch: branch outside complete body".into());
        }
        if matches!(
            node.operation,
            Decoded::SignedBranch { .. } | Decoded::Normal(Operation::Branch(..))
        ) && !nodes.contains_key(&node.instruction.next_ip32())
        {
            return Err("dispatch: branch fallthrough outside body".into());
        }
        if !matches!(
            node.operation,
            Decoded::Trap | Decoded::Normal(Operation::Return | Operation::Jump(_))
        ) && !nodes.contains_key(&node.instruction.next_ip32())
        {
            return Err("dispatch: truncated complete body fallthrough".into());
        }
    }
    Ok(nodes)
}

struct State<'a> {
    registers: [Value; 8],
    words: BTreeMap<i32, Value>,
    sp: i32,
    level: i32,
    event: u32,
    event_flags: KnownFlags,
    rows: &'a [Row],
    header: [u32; 4],
    flags: Option<Flags>,
    minimum_sp: i32,
}
impl State<'_> {
    fn reg(&self, r: Reg) -> Result<Value, String> {
        if r.index >= 8 || r.shift != 0 {
            return Err("dispatch: register alias".into());
        }
        let value = self.registers[r.index as usize].clone();
        match (r.width, value) {
            (32, Value::Unknown | Value::LowByte(_)) => {
                Err("dispatch: unknown full register".into())
            }
            (32, v) => Ok(v),
            (8, Value::Scalar(n)) => Ok(Value::Scalar(n & 255)),
            (8, Value::LowByte(n)) => Ok(Value::Scalar(u32::from(n))),
            _ => Err("dispatch: unknown or pointer partial register".into()),
        }
    }
    fn address(&self, a: &Address) -> Result<Value, String> {
        let mut scalar = a.displacement;
        let mut pointer = None;
        for (register, scale) in [(a.base, 1), (a.index, a.scale)] {
            let Some(register) = register else { continue };
            let value = &self.registers[register as usize];
            match value {
                Value::Scalar(n) => scalar = scalar.wrapping_add(n.wrapping_mul(scale)),
                Value::Handler(_) | Value::Table(_) | Value::Establisher | Value::Record
                    if scale == 1 && pointer.is_none() =>
                {
                    pointer = Some(value.clone())
                }
                _ => return Err("dispatch: address ownership/scale".into()),
            }
        }
        let offset = scalar as i32;
        Ok(match pointer {
            None => Value::Scalar(scalar),
            Some(Value::Handler(at)) => Value::Handler(
                at.checked_add(offset)
                    .ok_or("dispatch: handler offset overflow")?,
            ),
            Some(Value::Table(at)) => Value::Table(
                at.checked_add(offset)
                    .ok_or("dispatch: table offset overflow")?,
            ),
            Some(Value::Establisher) if offset == 0 => Value::Establisher,
            Some(Value::Record) if offset == 0 => Value::Record,
            // Object fields are handled by their typed accessors, never by
            // manufacturing a handler-stack offset from an unrelated pointer.
            Some(Value::Establisher | Value::Record) => {
                return Err("dispatch: external pointer arithmetic".into())
            }
            _ => return Err("dispatch: unsupported pointer arithmetic".into()),
        })
    }
    fn memory(&self, a: &Address, width: u8) -> Result<Value, String> {
        // Distinct objects are matched before computing frame-relative offsets;
        // sentinel encodings are never dereferenced or admitted as frame words.
        if a.index.is_none() {
            if let Some(base) = a.base {
                match self.registers[base as usize] {
                    Value::Establisher if width == 32 && a.displacement == 12 => {
                        return Ok(Value::Scalar(self.level as u32))
                    }
                    Value::Record if a.displacement == 0 && width == 32 => {
                        return Ok(Value::Scalar(self.event))
                    }
                    Value::Record if a.displacement == 4 && matches!(width, 8 | 32) => {
                        let observed = if width == 8 { 255 } else { u32::MAX };
                        if self.event_flags.mask & observed != observed {
                            return Err("dispatch: unproved exception flag bits".into());
                        }
                        return Ok(Value::Scalar(self.event_flags.value & observed));
                    }
                    Value::Establisher | Value::Record => {
                        return Err("dispatch: external object field bounds".into())
                    }
                    _ => {}
                }
            }
        }
        match self.address(a)? {
            Value::Handler(offset) if width == 32 && offset % 4 == 0 => self
                .words
                .get(&offset)
                .cloned()
                .ok_or("dispatch: uninitialized handler word".into()),
            Value::Handler(-1) if width == 8 => match self.words.get(&-1) {
                Some(Value::Scalar(n)) => Ok(Value::Scalar(n & 255)),
                _ => Err("dispatch: unknown handler byte".into()),
            },
            Value::Table(offset) if width == 32 && offset >= 0 && offset % 4 == 0 => {
                if offset < 16 {
                    return Ok(Value::Scalar(self.header[offset as usize / 4]));
                }
                let at = (offset as usize - 16) / 12;
                let row = self
                    .rows
                    .get(at)
                    .ok_or("dispatch: full scope field bounds")?;
                Ok(match (offset as usize - 16) % 12 {
                    0 => Value::Scalar(row.parent as u32),
                    4 if row.filter == 0 => Value::Scalar(0),
                    4 => Value::Code(row.filter),
                    8 => Value::Code(row.landing),
                    _ => return Err("dispatch: scope alignment".into()),
                })
            }
            _ => Err("dispatch: unproved external read".into()),
        }
    }
    fn read(&self, o: &Operand) -> Result<Value, String> {
        match o {
            Operand::Immediate(n) => Ok(Value::Scalar(*n)),
            Operand::Reg(r) => self.reg(*r),
            Operand::Memory(a, w) => self.memory(a, *w),
        }
    }
    fn scalar(&self, o: &Operand) -> Result<u32, String> {
        match self.read(o)? {
            Value::Scalar(n) => Ok(n),
            Value::Code(n) => Ok(n),
            _ => Err("dispatch: non-scalar flags operand".into()),
        }
    }
    fn write(&mut self, o: &Operand, value: Value) -> Result<(), String> {
        match o {
            Operand::Reg(r) if r.width == 32 && r.shift == 0 => {
                let index = full(*r)?;
                if index == 4 {
                    let Value::Handler(sp) = value else {
                        return Err("dispatch: stack provenance".into());
                    };
                    if sp > 0 || sp < self.sp {
                        return Err("dispatch: stack lifetime".into());
                    }
                    self.sp = sp;
                }
                self.registers[index] = value;
                Ok(())
            }
            Operand::Reg(r) if r.width == 8 && r.shift == 0 && r.index < 4 => {
                let Value::Scalar(n) = value else {
                    return Err("dispatch: partial pointer store".into());
                };
                self.registers[r.index as usize] = match self.registers[r.index as usize] {
                    Value::Scalar(old) => Value::Scalar((old & !255) | (n & 255)),
                    Value::Unknown | Value::LowByte(_) => Value::LowByte(n as u8),
                    _ => return Err("dispatch: partial pointer destination".into()),
                };
                Ok(())
            }
            Operand::Memory(a, w) => {
                let Value::Handler(offset) = self.address(a)? else {
                    return Err("dispatch: protected object write".into());
                };
                if !matches!((offset, *w), (-1, 8) | (-12, 32) | (-20, 32)) {
                    return Err("dispatch: protected handler write".into());
                }
                if *w == 8 && !matches!(value, Value::Scalar(_)) {
                    return Err("dispatch: pointer byte write".into());
                }
                self.words.insert(offset, value);
                Ok(())
            }
            _ => Err("dispatch: unsupported destination".into()),
        }
    }
    fn push(&mut self, v: Value) -> Result<(), String> {
        if matches!(v, Value::Unknown | Value::Return) {
            return Err("dispatch: unknown/protected argument".into());
        }
        self.sp = self.sp.checked_sub(4).ok_or("dispatch: stack wrap")?;
        if self.sp < -128 || self.words.insert(self.sp, v).is_some() {
            return Err("dispatch: argument stack overlap".into());
        }
        self.registers[4] = Value::Handler(self.sp);
        self.minimum_sp = self.minimum_sp.min(self.sp);
        Ok(())
    }
    fn arguments(&self) -> Result<(Value, Value), String> {
        if self.sp != -48 {
            return Err("dispatch: complete two-argument stack".into());
        }
        Ok((
            self.words
                .get(&self.sp)
                .cloned()
                .ok_or("dispatch: argument missing")?,
            self.words
                .get(&(self.sp + 4))
                .cloned()
                .ok_or("dispatch: argument missing")?,
        ))
    }
    fn cleanup(&mut self, bytes: u32) -> Result<(), String> {
        if bytes == 0 || !bytes.is_multiple_of(4) || bytes > 32 || self.sp + bytes as i32 > -40 {
            return Err("dispatch: cleanup crosses protected slots".into());
        }
        for at in (self.sp..self.sp + bytes as i32).step_by(4) {
            if self.words.remove(&at).is_none() {
                return Err("dispatch: missing cleanup word".into());
            }
        }
        self.sp += bytes as i32;
        self.registers[4] = Value::Handler(self.sp);
        self.flags = None;
        Ok(())
    }
    fn clobber(&mut self) {
        for i in [0, 1, 2] {
            self.registers[i] = Value::Unknown;
        }
        self.flags = None;
    }
}

fn level(rows: &[Row], at: i32) -> Result<(), String> {
    if at != -2 && (at < 0 || at as usize >= rows.len()) {
        Err("dispatch: scope level bounds".into())
    } else {
        Ok(())
    }
}
fn local_after(rows: &[Row], mut at: i32, stop: i32) -> Result<i32, String> {
    level(rows, at)?;
    level(rows, stop)?;
    let mut seen = BTreeSet::new();
    while at != -2 && (stop == -2 || (at as u32) > (stop as u32)) {
        if !seen.insert(at) {
            return Err("dispatch: required local unwind rank".into());
        }
        at = rows[at as usize].parent;
    }
    Ok(at)
}

/// The prefix proof supplies the original handler-local/argument/saved-register
/// cut. Filters are independently decoded by selection::prove_filter, not
/// supplied integer answers. Callee addresses bind required effects only; the
/// enclosing compiler must discharge every Action against original body/API
/// certificates and same-owner read/write footprints before native emission.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_dispatch(
    code: &[u8],
    origin: u32,
    prefix: &PrefixProof,
    bindings: Bindings,
    entry: Entry,
    table_bytes: &[u8],
    initial_level: i32,
    event_code: u32,
    filters: &BTreeMap<u32, OriginalFilter<'_>>,
    filter_layout: &FilterLayout,
    executable_targets: &BTreeSet<u32>,
) -> Result<DispatchProof, String> {
    let nodes = decode(code, origin)?;
    if origin != prefix.end
        || prefix.handler_allocation != 28
        || prefix.owner_pair_offset != -20
        || prefix.handler_pair_offset != -28
        || prefix.calls.len() != 3
        || prefix
            .calls
            .iter()
            .find(|c| c.effect == super::handler_checks::CallEffect::ValidateGuards)
            .is_none_or(|c| c.target != bindings.guard)
    {
        return Err("dispatch: original prefix state boundary".into());
    }
    selection::parse_eh4(table_bytes, executable_targets)?;
    let header = std::array::from_fn(|i| {
        u32::from_le_bytes(table_bytes[i * 4..i * 4 + 4].try_into().unwrap())
    });
    if filter_layout.exception_pointers_offset != -20
        || filter_layout
            .writable_words
            .iter()
            .any(|&offset| offset >= -24 || [header[0] as i32, header[2] as i32].contains(&offset))
    {
        return Err("dispatch: filter writes protected EH4 state".into());
    }
    let rows: Vec<_> = table_bytes[16..]
        .as_chunks::<12>()
        .0
        .iter()
        .map(|r| Row {
            parent: i32::from_le_bytes(r[0..4].try_into().unwrap()),
            filter: u32::from_le_bytes(r[4..8].try_into().unwrap()),
            landing: u32::from_le_bytes(r[8..12].try_into().unwrap()),
        })
        .collect();
    level(&rows, initial_level)?;
    let addresses = [
        bindings.filter_bridge,
        bindings.global_unwind,
        bindings.local_unwind,
        bindings.guard,
        bindings.selected_transfer,
    ];
    if bindings.cookie == 0
        || !bindings.cookie.is_multiple_of(4)
        || addresses.contains(&0)
        || addresses.iter().copied().collect::<BTreeSet<_>>().len() != 5
        || addresses.iter().any(|v| nodes.contains_key(v))
    {
        return Err("dispatch: bound callee identities".into());
    }
    let (mut pc, event_flags) = match entry {
        Entry::Search => {
            prefix.require_search_flags(0)?;
            (
                origin,
                KnownFlags {
                    mask: u32::MAX,
                    value: 0,
                },
            )
        }
        Entry::Unwind { flags } => {
            if flags.value & !flags.mask != 0
                || flags.value & flags.mask & u32::from(prefix.exception_flags_mask) == 0
                || !nodes.contains_key(&prefix.exception_flags_branch)
            {
                return Err("dispatch: original unwind-flags boundary".into());
            }
            (prefix.exception_flags_branch, flags)
        }
    };
    let mut regs = std::array::from_fn(|_| Value::Unknown);
    regs[3] = Value::Establisher;
    regs[4] = Value::Handler(-40);
    regs[5] = Value::Handler(0);
    regs[6] = Value::Owner;
    regs[7] = Value::Scalar(initial_level as u32);
    let mut s = State {
        registers: regs,
        words: BTreeMap::from([
            (-40, Value::Saved(7)),
            (-36, Value::Saved(6)),
            (-32, Value::Saved(3)),
            (-1, Value::Scalar(0)),
            (-12, Value::Scalar(1)),
            (-16, Value::Owner),
            (-8, Value::Table(0)),
            (0, Value::Saved(5)),
            (4, Value::Return),
            (8, Value::Record),
            (12, Value::Establisher),
            (16, Value::Context),
        ]),
        sp: -40,
        level: initial_level,
        event: event_code,
        event_flags,
        rows: &rows,
        header,
        flags: None,
        minimum_sp: -40,
    };
    let mut actions = Vec::new();
    let mut instructions = Vec::new();
    let mut visited = BTreeSet::new();
    let mut calls = BTreeSet::new();
    let mut call_depths = Vec::new();
    loop {
        let key = format!(
            "{pc}:{:?}:{:?}:{}:{}:{:?}",
            s.registers, s.words, s.sp, s.level, s.flags
        );
        if instructions.len() >= 2048 || !visited.insert(key) {
            return Err("dispatch: unproved cycle/resource limit".into());
        }
        let node = nodes
            .get(&pc)
            .ok_or("dispatch: incomplete body successor")?;
        let mut next = Some(node.instruction.next_ip32());
        match &node.operation {
            Decoded::Trap => {
                return Err("dispatch: reachable trap/returned nonlocal transfer".into())
            }
            Decoded::Call(target) => {
                calls.insert(pc);
                call_depths.push((
                    pc,
                    u32::try_from(8 - s.sp).map_err(|_| "dispatch: call stack extent")?,
                ));
                s.minimum_sp = s.minimum_sp.min(s.sp - 4);
                if *target == bindings.filter_bridge {
                    if s.sp != -40 || s.registers[2] != Value::Owner {
                        return Err("dispatch: filter frame/stack arguments".into());
                    }
                    let Value::Code(filter) = s.registers[1] else {
                        return Err("dispatch: unbound filter target".into());
                    };
                    let Value::Scalar(scope) = s.registers[7] else {
                        return Err("dispatch: filter scope provenance".into());
                    };
                    let row = rows
                        .get(scope as usize)
                        .ok_or("dispatch: filter scope bounds")?;
                    if row.filter != filter {
                        return Err("dispatch: filter/table identity".into());
                    }
                    let original = filters
                        .get(&filter)
                        .ok_or("dispatch: original filter body absent")?;
                    if original.origin != filter {
                        return Err("dispatch: filter source binding".into());
                    }
                    let proof =
                        selection::prove_filter(original.bytes, filter, filter_layout, event_code)?;
                    let result = proof.result();
                    actions.push(Action::Filter {
                        pc,
                        bridge: *target,
                        scope: scope as i32,
                        target: filter,
                        arguments: vec![Argument::CodeTarget(filter), Argument::OwnerFrame],
                        proof,
                    });
                    s.clobber();
                    s.registers[0] = Value::Scalar(result as u32);
                } else if *target == bindings.global_unwind {
                    if s.sp != -40
                        || s.registers[1] != Value::Establisher
                        || s.registers[2] != Value::Record
                    {
                        return Err("dispatch: global unwind typed arguments".into());
                    }
                    actions.push(Action::GlobalUnwind {
                        pc,
                        target: *target,
                        arguments: vec![Argument::Establisher, Argument::ExceptionRecord],
                        preserved_level: s.level,
                    });
                    s.clobber();
                } else if *target == bindings.local_unwind {
                    if s.registers[1] != Value::Establisher {
                        return Err("dispatch: local unwind registration".into());
                    }
                    let Value::Scalar(stop) = s.registers[2] else {
                        return Err("dispatch: local unwind stop level".into());
                    };
                    if s.arguments()? != (Value::Owner, Value::Scalar(bindings.cookie)) {
                        return Err("dispatch: local unwind owner/cookie arguments".into());
                    }
                    let after = local_after(&rows, s.level, stop as i32)?;
                    actions.push(Action::LocalUnwind {
                        pc,
                        target: *target,
                        arguments: vec![
                            Argument::Establisher,
                            Argument::ScopeLevel(stop as i32),
                            Argument::OwnerFrame,
                            Argument::CookieAddress(bindings.cookie),
                        ],
                        before: s.level,
                        stop: stop as i32,
                        after,
                    });
                    s.level = after;
                    s.cleanup(8)?;
                    s.clobber();
                } else if *target == bindings.guard {
                    if s.arguments()? != (Value::Table(0), Value::Owner) {
                        return Err("dispatch: guard table/frame arguments".into());
                    }
                    actions.push(Action::ValidateGuards {
                        pc,
                        target: *target,
                        arguments: vec![Argument::ScopeTable, Argument::OwnerFrame],
                    });
                    s.clobber();
                } else if *target == bindings.selected_transfer {
                    if s.sp != -40 || s.registers[2] != Value::Owner {
                        return Err("dispatch: selected transfer frame/stack".into());
                    }
                    let Value::Code(landing) = s.registers[1] else {
                        return Err("dispatch: selected transfer target".into());
                    };
                    let Some(Value::Table(offset)) = s.words.get(&-20) else {
                        return Err("dispatch: selected scope pointer".into());
                    };
                    if *offset < 16 || (*offset - 16) % 12 != 0 {
                        return Err("dispatch: selected scope alignment".into());
                    }
                    let scope = (*offset - 16) / 12;
                    if rows.get(scope as usize).is_none_or(|r| {
                        r.filter == 0 || r.landing != landing || r.parent != s.level
                    }) {
                        return Err("dispatch: selected landing/parent identity".into());
                    }
                    actions.push(Action::Transfer {
                        pc,
                        bridge: *target,
                        arguments: vec![Argument::CodeTarget(landing), Argument::OwnerFrame],
                        scope,
                        landing,
                    });
                    next = None;
                } else {
                    return Err("dispatch: unresolved reachable external call".into());
                }
            }
            Decoded::SignedBranch { greater, target } => {
                let flags = s.flags.ok_or("dispatch: unknown signed flags")?;
                if if *greater {
                    !flags.zero && flags.sign == flags.overflow
                } else {
                    flags.sign
                } {
                    next = Some(*target);
                }
            }
            Decoded::Normal(op) => match op {
                Operation::Binary(Binary::Move, dst, src) => {
                    let value = s.read(src)?;
                    if let Operand::Memory(a, 32) = dst {
                        if a.index.is_none()
                            && a.displacement == 12
                            && a.base
                                .is_some_and(|r| s.registers[r as usize] == Value::Establisher)
                        {
                            let Value::Scalar(after) = value else {
                                return Err("dispatch: non-scalar TryLevel write".into());
                            };
                            level(&rows, after as i32)?;
                            actions.push(Action::StoreTryLevel {
                                pc,
                                before: s.level,
                                after: after as i32,
                            });
                            s.level = after as i32;
                        } else {
                            s.write(dst, value)?;
                        }
                    } else {
                        s.write(dst, value)?;
                    }
                }
                Operation::Address(r, a) => {
                    let value = s.address(a)?;
                    s.write(&Operand::Reg(*r), value)?;
                }
                Operation::Binary(Binary::Compare | Binary::Test, left, right) => {
                    let width = match left {
                        Operand::Reg(r) => r.width,
                        Operand::Memory(_, w) => *w,
                        _ => return Err("dispatch: flags operand width".into()),
                    };
                    let mask = if width == 8 {
                        255
                    } else if width == 32 {
                        u32::MAX
                    } else {
                        return Err("dispatch: flags width".into());
                    };
                    let a = s.scalar(left)? & mask;
                    let b = s.scalar(right)? & mask;
                    let is_compare = matches!(op, Operation::Binary(Binary::Compare, ..));
                    let result = if is_compare {
                        a.wrapping_sub(b) & mask
                    } else {
                        a & b
                    };
                    let sign = 1u32 << (width - 1);
                    s.flags = Some(Flags {
                        zero: result == 0,
                        sign: result & sign != 0,
                        overflow: is_compare && (a ^ b) & (a ^ result) & sign != 0,
                        carry: is_compare && a < b,
                    });
                }
                Operation::Binary(Binary::Add, Operand::Reg(r), Operand::Immediate(n))
                    if full(*r)? == 4 =>
                {
                    s.cleanup(*n)?
                }
                Operation::Branch(condition, target) => {
                    let f = s.flags.ok_or("dispatch: unknown flags")?;
                    if match condition {
                        Condition::Equal => f.zero,
                        Condition::NotEqual => !f.zero,
                        Condition::Below => f.carry,
                        Condition::Above => !f.carry && !f.zero,
                        Condition::BelowEqual => f.carry || f.zero,
                        Condition::AboveEqual => !f.carry,
                    } {
                        next = Some(*target);
                    }
                }
                Operation::Jump(target) => next = Some(*target),
                Operation::Push(operand) => {
                    let value = s.read(operand)?;
                    s.push(value)?;
                }
                Operation::Pop(reg) => {
                    let index = full(*reg)?;
                    if index == 4 || s.sp > 0 {
                        return Err("dispatch: protected stack pop".into());
                    }
                    let value = s.words.remove(&s.sp).ok_or("dispatch: missing pop word")?;
                    if value == Value::Return {
                        return Err("dispatch: protected return pop".into());
                    }
                    s.sp += 4;
                    s.registers[4] = Value::Handler(s.sp);
                    s.registers[index] = value;
                }
                Operation::Return => {
                    if s.sp != 4
                        || s.words.get(&4) != Some(&Value::Return)
                        || [3, 5, 6, 7]
                            .iter()
                            .any(|&r| s.registers[r] != Value::Saved(r as u8))
                    {
                        return Err("dispatch: original return state/stack".into());
                    }
                    let Value::Scalar(value) = s.registers[0] else {
                        return Err("dispatch: unknown disposition".into());
                    };
                    if value > 1 {
                        return Err("dispatch: unsupported raw disposition".into());
                    }
                    actions.push(Action::ReturnDisposition { pc, value });
                    next = None;
                }
                _ => return Err("dispatch: unsupported reachable instruction/effect".into()),
            },
        }
        instructions.push(InstructionStep {
            pc,
            next,
            bytes: node.bytes.clone(),
        });
        if let Some(next) = next {
            pc = next;
        } else {
            break;
        }
    }
    let unexecuted_calls = nodes
        .iter()
        .filter_map(|(&pc, n)| {
            if calls.contains(&pc) {
                None
            } else {
                match n.operation {
                    Decoded::Call(target) => Some((pc, Some(target))),
                    Decoded::Normal(Operation::Call(_)) => Some((pc, None)),
                    _ => None,
                }
            }
        })
        .collect();
    Ok(DispatchProof {
        source_table: table_bytes.to_vec(),
        actions,
        instructions,
        final_level: s.level,
        temporary_bytes: u32::try_from(4 - s.minimum_sp).map_err(|_| "dispatch: stack extent")?,
        call_depths,
        unexecuted_calls,
    })
}

#[cfg(test)]
mod tests {
    use super::super::handler_checks::{CallEffect, CallSite};
    use super::*;
    const START: u32 = 0x2000;
    fn bindings() -> Bindings {
        Bindings {
            filter_bridge: 0x8000,
            global_unwind: 0x8100,
            local_unwind: 0x8200,
            guard: 0x8300,
            selected_transfer: 0x8400,
            cookie: 0xa000,
        }
    }
    struct Asm {
        bytes: Vec<u8>,
        labels: BTreeMap<&'static str, usize>,
        fixups: Vec<(usize, &'static str)>,
    }
    impl Asm {
        fn new() -> Self {
            Self {
                bytes: vec![],
                labels: BTreeMap::new(),
                fixups: vec![],
            }
        }
        fn emit(&mut self, b: &[u8]) {
            self.bytes.extend(b);
        }
        fn label(&mut self, name: &'static str) {
            assert!(self.labels.insert(name, self.bytes.len()).is_none());
        }
        fn branch(&mut self, condition: Option<u8>, name: &'static str) {
            if let Some(c) = condition {
                self.emit(&[0x0f, c]);
            } else {
                self.emit(&[0xe9]);
            }
            self.fixups.push((self.bytes.len(), name));
            self.emit(&[0; 4]);
        }
        fn call(&mut self, target: u32) {
            self.emit(&[0xe8]);
            let next = START + self.bytes.len() as u32 + 4;
            self.bytes.extend(target.wrapping_sub(next).to_le_bytes());
        }
        fn finish(mut self) -> (Vec<u8>, BTreeMap<&'static str, u32>) {
            for (at, name) in self.fixups {
                let relative = self.labels[name] as i32 - (at + 4) as i32;
                self.bytes[at..at + 4].copy_from_slice(&relative.to_le_bytes());
            }
            (
                self.bytes,
                self.labels
                    .into_iter()
                    .map(|(n, o)| (n, START + o as u32))
                    .collect(),
            )
        }
    }
    fn fixture() -> (Vec<u8>, PrefixProof, BTreeMap<&'static str, u32>) {
        let b = bindings();
        let mut a = Asm::new();
        a.emit(&[0x83, 0xff, 0xfe]);
        a.branch(Some(0x84), "return");
        a.label("loop");
        a.emit(&[
            0x8b, 0x4d, 0xf8, 0x8d, 0x47, 2, 0x8d, 4, 0x47, 0x8b, 0x1c, 0x81, 0x8d, 4, 0x81, 0x8b,
            0x48, 4, 0x89, 0x45, 0xec, 0x85, 0xc9,
        ]);
        a.branch(Some(0x84), "parent");
        a.emit(&[0x8b, 0xd6]);
        a.call(b.filter_bridge);
        a.emit(&[0xb1, 1, 0x88, 0x4d, 0xff, 0x85, 0xc0]);
        a.branch(Some(0x88), "resume");
        a.branch(Some(0x8f), "selected");
        a.label("parent");
        a.emit(&[0x8b, 0xfb, 0x83, 0xfb, 0xfe]);
        a.branch(Some(0x85), "loop");
        a.emit(&[0x8a, 0x4d, 0xff, 0x84, 0xc9]);
        a.branch(Some(0x85), "guard");
        a.branch(None, "return");
        a.label("resume");
        a.emit(&[0xc7, 0x45, 0xf4, 0, 0, 0, 0]);
        a.branch(None, "guard");
        a.label("unwind");
        a.emit(&[0x83, 0xff, 0xfe]);
        a.branch(Some(0x84), "return");
        a.emit(&[0x68]);
        a.bytes.extend(b.cookie.to_le_bytes());
        a.emit(&[0x56, 0xba, 0xfe, 0xff, 0xff, 0xff, 0x8b, 0xcb]);
        a.call(b.local_unwind);
        a.branch(None, "guard");
        a.label("selected");
        a.emit(&[0x8b, 0x45, 8, 0x81, 0x38, 0x63, 0x73, 0x6d, 0xe0]);
        a.branch(Some(0x84), "external");
        a.emit(&[0x8b, 0x4d, 12, 0x8b, 0xd0]);
        a.call(b.global_unwind);
        a.emit(&[0x8b, 0x45, 12, 0x39, 0x78, 12]);
        a.branch(Some(0x84), "store");
        a.emit(&[0x68]);
        a.bytes.extend(b.cookie.to_le_bytes());
        a.emit(&[0x56, 0x8b, 0xd7, 0x8b, 0xc8]);
        a.call(b.local_unwind);
        a.emit(&[0x8b, 0x45, 12]);
        a.label("store");
        a.emit(&[0x56, 0xff, 0x75, 0xf8, 0x89, 0x58, 12]);
        a.call(b.guard);
        a.emit(&[0x8b, 0x4d, 0xec, 0x83, 0xc4, 8, 0x8b, 0xd6, 0x8b, 0x49, 8]);
        a.call(b.selected_transfer);
        a.emit(&[0xcc]);
        a.label("guard");
        a.emit(&[0x56, 0xff, 0x75, 0xf8]);
        a.call(b.guard);
        a.emit(&[0x83, 0xc4, 8]);
        a.label("return");
        a.emit(&[0x8b, 0x45, 0xf4, 0x5f, 0x5e, 0x5b, 0x8b, 0xe5, 0x5d, 0xc3]);
        a.label("external");
        a.call(0xf000);
        a.emit(&[0xcc]);
        let (bytes, labels) = a.finish();
        // This synthetic cut is an explicit input contract for caller-only
        // tests. Actual prefix-byte certification is tested by handler_checks;
        // the retained original-body smoke test uses that real certificate.
        let prefix = PrefixProof {
            source: Vec::new(), // No native prefix certificate in this routing-only fixture.
            unwind_caller: String::new(),
            entry: 0, // Routing-only fixture.
            caller: String::new(),
            front: String::new(), // Routing-only fixture does not emit caller instructions.
            calls: vec![
                CallSite {
                    va: 0x1000,
                    target: 0x8600,
                    effect: CallEffect::NormalizeRecordCode,
                    arguments: vec!["record"],
                    entry_depth: 48,
                },
                CallSite {
                    va: 0x1010,
                    target: b.guard,
                    effect: CallEffect::ValidateGuards,
                    arguments: vec!["table", "frame"],
                    entry_depth: 56,
                },
                CallSite {
                    va: 0x1020,
                    target: 0x8700,
                    effect: CallEffect::ValidateContext,
                    arguments: vec!["context"],
                    entry_depth: 60,
                },
            ],
            exception_flags_mask: 0x66,
            exception_flags_branch: labels["unwind"],
            installer_start: 0x1ff1,
            end: START,
            handler_allocation: 28,
            temporary_bytes: 60,
            owner_pair_offset: -20,
            handler_pair_offset: -28,
        };
        (bytes, prefix, labels)
    }
    fn table() -> Vec<u8> {
        let mut t = Vec::new();
        for n in [-2i32, 0, -64, 0] {
            t.extend(n.to_le_bytes());
        }
        for (p, f, h) in [
            (-2i32, 0u32, 0xb020u32),
            (0, 0xb000, 0xb100),
            (1, 0, 0xb024),
        ] {
            t.extend(p.to_le_bytes());
            t.extend(f.to_le_bytes());
            t.extend(h.to_le_bytes());
        }
        t
    }
    const RETURN_CODE: &[u8] = &[0x8b, 0x45, 0xec, 0x8b, 0, 0x8b, 0, 0xc3];
    const RETURN_ONE: &[u8] = &[0x33, 0xc0, 0x83, 0xf8, 0, 0x0f, 0x94, 0xc0, 0xc3];
    fn run(
        code: &[u8],
        prefix: &PrefixProof,
        table: &[u8],
        event: u32,
        filter: &[u8],
        entry: Entry,
    ) -> Result<DispatchProof, String> {
        prove_dispatch(
            code,
            START,
            prefix,
            bindings(),
            entry,
            table,
            2,
            event,
            &BTreeMap::from([(
                0xb000,
                OriginalFilter {
                    origin: 0xb000,
                    bytes: filter,
                },
            )]),
            &FilterLayout {
                start: -128,
                end: 0,
                exception_pointers_offset: -20,
                writable_words: vec![-80],
            },
            &BTreeSet::from([0xb000, 0xb020, 0xb024, 0xb100]),
        )
    }
    fn names(p: &DispatchProof) -> Vec<&'static str> {
        p.actions
            .iter()
            .map(|a| match a {
                Action::Filter { .. } => "filter",
                Action::GlobalUnwind { .. } => "global",
                Action::LocalUnwind { .. } => "local",
                Action::ValidateGuards { .. } => "guard",
                Action::StoreTryLevel { .. } => "store",
                Action::Transfer { .. } => "transfer",
                Action::ReturnDisposition { .. } => "return",
            })
            .collect()
    }
    #[test]
    fn actual_signed_filter_extremes_determine_distinct_control_dispositions() {
        let (code, prefix, _) = fixture();
        for event in [1, 255, 0x7fff_ffff] {
            let p = run(&code, &prefix, &table(), event, RETURN_CODE, Entry::Search).unwrap();
            assert_eq!(
                names(&p),
                ["filter", "global", "local", "store", "guard", "transfer"]
            );
            assert_eq!(p.final_level, 0);
            assert!(matches!(
                p.actions[2],
                Action::LocalUnwind {
                    before: 2,
                    stop: 1,
                    after: 1,
                    ..
                }
            ));
            assert!(matches!(
                p.actions[3],
                Action::StoreTryLevel {
                    before: 1,
                    after: 0,
                    ..
                }
            ));
            assert!(matches!(
                p.actions[5],
                Action::Transfer {
                    scope: 1,
                    landing: 0xb100,
                    ..
                }
            ));
        }
        for event in [0x8000_0000, u32::MAX] {
            let p = run(&code, &prefix, &table(), event, RETURN_CODE, Entry::Search).unwrap();
            assert_eq!(names(&p), ["filter", "guard", "return"]);
            assert!(matches!(
                p.actions[2],
                Action::ReturnDisposition { value: 0, .. }
            ));
            assert_eq!(p.final_level, 2);
        }
        let p = run(&code, &prefix, &table(), 0, RETURN_CODE, Entry::Search).unwrap();
        assert_eq!(names(&p), ["filter", "guard", "return"]);
        assert!(matches!(
            p.actions[2],
            Action::ReturnDisposition { value: 1, .. }
        ));
        assert_eq!(p.final_level, 2);
    }
    #[test]
    fn unwind_uses_only_guaranteed_flag_bit_and_requires_original_local_effect() {
        let (code, prefix, _) = fixture();
        let p = run(
            &code,
            &prefix,
            &table(),
            0xe0424242,
            RETURN_CODE,
            Entry::Unwind {
                flags: KnownFlags { mask: 2, value: 2 },
            },
        )
        .unwrap();
        assert_eq!(names(&p), ["local", "guard", "return"]);
        assert!(matches!(
            p.actions[0],
            Action::LocalUnwind {
                before: 2,
                stop: -2,
                after: -2,
                ..
            }
        ));
        assert!(matches!(
            p.actions[2],
            Action::ReturnDisposition { value: 1, .. }
        ));
        assert_eq!(p.final_level, -2);
        assert_eq!(p.temporary_bytes, 56);
        assert_eq!(p.call_depths.len(), 2);
        // Two arguments below EBP-40 and the callee return word place both
        // callees 56 bytes below original handler-entry ESP (EBP+4).
        assert_eq!(p.call_depths[0].1, 56);
        assert_eq!(p.call_depths[1].1, 56);
        for flags in [
            KnownFlags { mask: 0, value: 2 },
            KnownFlags { mask: 2, value: 0 },
            KnownFlags {
                mask: u32::MAX,
                value: 1,
            },
        ] {
            assert!(run(
                &code,
                &prefix,
                &table(),
                0,
                RETURN_CODE,
                Entry::Unwind { flags }
            )
            .is_err());
        }
    }
    #[test]
    fn complete_body_and_required_callee_packets_reject_mutations() {
        let (code, prefix, labels) = fixture();
        for length in 0..code.len() {
            assert!(
                run(
                    &code[..length],
                    &prefix,
                    &table(),
                    1,
                    RETURN_CODE,
                    Entry::Search
                )
                .is_err(),
                "truncation{length}"
            );
        }
        let mut t = table();
        t[16..20].copy_from_slice(&2i32.to_le_bytes());
        assert!(run(&code, &prefix, &t, 1, RETURN_CODE, Entry::Search).is_err());
        let mut bad = code.clone();
        let at = bad.windows(3).position(|w| w == [0x89, 0x58, 12]).unwrap();
        bad[at + 2] = 8;
        assert!(run(&bad, &prefix, &table(), 1, RETURN_CODE, Entry::Search).is_err());
        let mut bad = code.clone();
        let at = bad.windows(3).position(|w| w == [0x83, 0xc4, 8]).unwrap();
        bad[at + 2] = 12;
        assert!(run(&bad, &prefix, &table(), 1, RETURN_CODE, Entry::Search).is_err());
        let mut bad = code.clone();
        let at = bad.windows(3).position(|w| w == [0x8b, 0x4d, 12]).unwrap();
        bad[at + 2] = 16;
        assert!(run(&bad, &prefix, &table(), 1, RETURN_CODE, Entry::Search).is_err());
        let mut bad = code.clone();
        let at = (labels["loop"] - START) as usize;
        bad[at + 2] = 0xfc;
        assert!(run(&bad, &prefix, &table(), 1, RETURN_CODE, Entry::Search).is_err());
        assert!(run(
            &code,
            &prefix,
            &table(),
            0xe06d7363,
            RETURN_ONE,
            Entry::Search
        )
        .err()
        .unwrap()
        .contains("external call"));
        let p = run(&code, &prefix, &table(), 1, RETURN_CODE, Entry::Search).unwrap();
        assert!(p
            .unexecuted_calls
            .contains(&(labels["external"], Some(0xf000))));
        let again = run(&code, &prefix, &table(), 1, RETURN_CODE, Entry::Search).unwrap();
        assert_eq!(p.instructions, again.instructions);
    }
}
