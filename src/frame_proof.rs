//! Original x86 prolog/initializer fragment proof. No whole-entry admission.
//! Incoming stack validity, initialized cookie and borrowed predecessor identity
//! are explicit cut premises; original instructions derive all frame contents.
use super::graph::{self, Address, Binary, Operand, Operation, Reg};
use iced_x86::{Code, Decoder, DecoderOptions, MemorySize, Mnemonic, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Unknown,
    Scalar(u32),
    Stack(i32),
    Saved(u8),
    Return,
    Borrowed,
    Cookie,
    EncodedScope(u32),
    Guard(i32),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Allocated,
    Pushed,
    Saved,
    Protected,
}
struct Word {
    value: Value,
    kind: Kind,
}
struct State<'a> {
    registers: [Value; 8],
    words: BTreeMap<i32, Word>,
    sp: i32,
    bp: Option<i32>,
    record: Option<i32>,
    read_fs: bool,
    cookie_va: u32,
    scopes: &'a BTreeSet<u32>,
    handlers: &'a BTreeSet<u32>,
    source: String,
}

/// The predecessor parameter is copied as an opaque type. Its actual
/// thread/lifetime authority must be provided by the containing proven cut.
pub(crate) const EMITTED_TYPES: &str = r#"
#[derive(Clone,Debug,PartialEq,Eq)]
enum FrameWord<P> {
 Unknown, Scalar(u32), StackAddress(u32), Saved(u8,Option<u32>), Return,
 Borrowed(P), Cookie(u32), EncodedScope{scope:u32,cookie:u32,bits:u32},
 Guard{frame:u32,cookie:u32,bits:u32},
}
struct FrameImage<P> {
 words:std::collections::BTreeMap<i32,FrameWord<P>>,
 entry_sp:u32, ebp:u32, esp:u32, record:u32,
 scope_va:u32, handler_va:u32, try_level:i32,
}
fn frame_address(base:u32,offset:i32)->Result<u32,&'static str>{
 let address=i64::from(base)+i64::from(offset);
 if !(1..=i64::from(u32::MAX)-3).contains(&address) || address%4!=0 {
  return Err("frame address/range/alignment");
 }
 Ok(address as u32)
}
"#;

pub(crate) struct ProvenFrame {
    end: u32,
    esp: i32,
    ebp: i32,
    record: i32,
    scope_va: u32,
    handler_va: u32,
    try_level_offset: i32,
    try_level: i32,
    scalar_words: BTreeMap<i32, u32>,
    ordinary_words: BTreeSet<i32>,
    pending_arguments: Vec<u32>,
    guard_offsets: Vec<i32>,
    saved_slots: BTreeMap<i32, u8>,
    body: String,
}
/// Separate original stores after an explicitly unproved gap. This does not
/// certify effects inside the gap or preservation of any earlier frame value.
pub(crate) struct InitializerFragment {
    entry: u32,
    end: u32,
    gap: Option<(u32, u32)>,
    writes: BTreeMap<i32, u32>,
    try_level: Option<i32>,
    body: String,
}
impl InitializerFragment {
    pub fn entry(&self) -> u32 {
        self.entry
    }
    pub fn end(&self) -> u32 {
        self.end
    }
    pub fn gap(&self) -> Option<(u32, u32)> {
        self.gap
    }
    pub fn writes(&self) -> &BTreeMap<i32, u32> {
        &self.writes
    }
    pub fn try_level(&self) -> Option<i32> {
        self.try_level
    }
    pub fn body(&self) -> &str {
        &self.body
    }
}
impl ProvenFrame {
    pub fn end(&self) -> u32 {
        self.end
    }
    pub fn esp_offset(&self) -> i32 {
        self.esp
    }
    pub fn ebp_offset(&self) -> i32 {
        self.ebp
    }
    pub fn record_offset(&self) -> i32 {
        self.record
    }
    pub fn scope_va(&self) -> u32 {
        self.scope_va
    }
    pub fn handler_va(&self) -> u32 {
        self.handler_va
    }
    pub fn try_level_offset(&self) -> i32 {
        self.try_level_offset
    }
    pub fn try_level(&self) -> i32 {
        self.try_level
    }
    /// Initialized, ordinary scalar cells only, keyed relative to derived EBP.
    /// Record/TryLevel, saved-register, guard, pointer and argument slots excluded.
    pub fn scalar_words(&self) -> &BTreeMap<i32, u32> {
        &self.scalar_words
    }
    /// Ordinary allocated words, including uninitialized storage. Membership
    /// grants no read permission until the composed proof establishes a write.
    pub fn ordinary_words(&self) -> &BTreeSet<i32> {
        &self.ordinary_words
    }
    /// Scalar PUSH values at final ESP+4*i, in call-argument order. These are
    /// original stores, not a binding of a later call or its observable effects.
    pub fn pending_arguments(&self) -> &[u32] {
        &self.pending_arguments
    }
    /// Layout consistency for the observed cookie XOR frame-base scheme. This
    /// does not replace execution/proof of the original EH4 guard helper.
    pub fn validate_eh4_header(&self, header: [i32; 4]) -> Result<(), String> {
        let [gs, gs_xor, eh, eh_xor] = header;
        if gs_xor != 0
            || eh_xor != 0
            || !self.guard_offsets.contains(&eh)
            || (gs != -2 && !self.guard_offsets.contains(&gs))
        {
            return Err(
                "frame: EH4 header does not match original frame-base cookie guards".into(),
            );
        }
        Ok(())
    }
    pub fn guard_offsets(&self) -> &[i32] {
        &self.guard_offsets
    }
    pub fn saved_slots(&self) -> &BTreeMap<i32, u8> {
        &self.saved_slots
    }
    pub fn initializer_body(&self) -> &str {
        &self.body
    }
    pub fn prove_initializer_fragment(
        &self,
        code: &[u8],
        origin: u32,
    ) -> Result<InitializerFragment, String> {
        if code.is_empty() || code.len() > 256 || origin < self.end {
            return Err("frame fragment: extent/order".into());
        }
        let end = origin
            .checked_add(code.len() as u32)
            .ok_or("frame fragment: overflow")?;
        let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
        let mut writes = BTreeMap::new();
        let mut try_level = None;
        let mut body = String::new();
        while decoder.can_decode() {
            let i = decoder.decode();
            if i.is_invalid() {
                return Err("frame fragment: malformed instruction".into());
            }
            let at = (i.ip() - u64::from(origin)) as usize;
            let Operation::Binary(Binary::Move, Operand::Memory(a, 32), Operand::Immediate(n)) =
                graph::normalized(&i, &code[at..at + i.len()])?
            else {
                return Err("frame fragment: unsupported effect".into());
            };
            if a.base != Some(5) || a.index.is_some() {
                return Err("frame fragment: unowned frame base".into());
            }
            let offset = a.displacement as i32;
            if offset == self.try_level_offset {
                if (n as i32) < -2 || n == u32::MAX {
                    return Err("frame fragment: invalid TryLevel".into());
                }
                try_level = Some(n as i32);
            } else if !self.scalar_words.contains_key(&offset) {
                return Err("frame fragment: not a proved scalar slot".into());
            }
            writes.insert(offset, n);
            let absolute = self
                .ebp
                .checked_add(offset)
                .ok_or("frame fragment: offset overflow")?;
            body.push_str(&format!("if !matches!(image.words.get(&{absolute}),Some(FrameWord::Scalar(_))){{return Err(\"fragment requires same live initialized frame\");}}\nimage.words.insert({absolute},FrameWord::Scalar({n}u32));\n"));
            if offset == self.try_level_offset {
                body.push_str(&format!("image.try_level={}i32;\n", n as i32));
            }
        }
        body.push_str("Ok(())\n");
        Ok(InitializerFragment {
            entry: origin,
            end,
            gap: (origin != self.end).then_some((self.end, origin)),
            writes,
            try_level,
            body,
        })
    }
}
fn full(reg: Reg) -> Result<usize, String> {
    if reg.width == 32 && reg.shift == 0 {
        Ok(reg.index as usize)
    } else {
        Err("frame: partial register".into())
    }
}
fn emitted(value: &Value) -> String {
    match value {
        Value::Unknown=>"FrameWord::Unknown".into(),
        Value::Scalar(n)=>format!("FrameWord::Scalar({n}u32)"),
        Value::Stack(at)=>format!("FrameWord::StackAddress(frame_address(entry_sp,{at})?)"),
        Value::Saved(reg)=>format!("FrameWord::Saved({reg},saved[{reg}])"),
        Value::Return=>"FrameWord::Return".into(),
        Value::Borrowed=>"FrameWord::Borrowed(predecessor.clone())".into(),
        Value::Cookie=>"FrameWord::Cookie(cookie)".into(),
        Value::EncodedScope(scope)=>format!("FrameWord::EncodedScope{{scope:{scope},cookie,bits:{scope}u32^cookie}}"),
        Value::Guard(frame)=>format!("FrameWord::Guard{{frame:frame_address(entry_sp,{frame})?,cookie,bits:frame_address(entry_sp,{frame})?^cookie}}"),
    }
}
impl State<'_> {
    fn emit_store(&mut self, at: i32, value: &Value) {
        self.source
            .push_str(&format!("words.insert({at},{});\n", emitted(value)));
    }
    fn address(&self, a: &Address) -> Result<i32, String> {
        if a.index.is_some() {
            return Err("frame: indexed frame access".into());
        }
        let Some(reg) = a.base else {
            return Err("frame: unbound absolute address".into());
        };
        let Value::Stack(base) = self.registers[reg as usize] else {
            return Err("frame: unowned base".into());
        };
        let at = base
            .checked_add(a.displacement as i32)
            .ok_or("frame: offset overflow")?;
        if at % 4 != 0 || !self.words.contains_key(&at) {
            return Err("frame: complete allocated word bounds".into());
        }
        Ok(at)
    }
    fn read(&self, operand: &Operand) -> Result<Value, String> {
        let value = match operand {
            Operand::Immediate(n) => Value::Scalar(*n),
            Operand::Reg(reg) => self.registers[full(*reg)?].clone(),
            Operand::Memory(a, 32)
                if a.base.is_none() && a.index.is_none() && a.displacement == self.cookie_va =>
            {
                Value::Cookie
            }
            Operand::Memory(a, 32) => self.words[&self.address(a)?].value.clone(),
            _ => return Err("frame: read width/form".into()),
        };
        if matches!(value, Value::Unknown | Value::Return) {
            return Err("frame: uninitialized/protected read".into());
        }
        Ok(value)
    }
    fn write(&mut self, operand: &Operand, value: Value) -> Result<(), String> {
        match operand {
            Operand::Reg(reg) => {
                let i = full(*reg)?;
                if i == 4 {
                    return Err("frame: ESP assignment outside allocation".into());
                }
                if i == 5 {
                    if self.bp.is_some()
                        || value != Value::Stack(self.sp)
                        || self
                            .words
                            .get(&self.sp)
                            .is_none_or(|w| w.value != Value::Saved(5))
                    {
                        return Err("frame: unproved EBP establishment/change".into());
                    }
                    self.bp = Some(self.sp);
                }
                self.registers[i] = value;
            }
            Operand::Memory(a, 32) => {
                let at = self.address(a)?;
                let word = &self.words[&at];
                if matches!(word.kind, Kind::Saved | Kind::Protected)
                    || matches!(
                        word.value,
                        Value::Guard(_) | Value::Cookie | Value::Stack(_) | Value::Borrowed
                    )
                {
                    return Err("frame: protected slot overwrite".into());
                }
                if let Some(record) = self.record {
                    if (record..record + 12).contains(&at) {
                        return Err("frame: installed record mutation".into());
                    }
                    if at == record + 12 {
                        let Value::Scalar(n) = value else {
                            return Err("frame: non-scalar TryLevel".into());
                        };
                        if (n as i32) < -2 || n == u32::MAX {
                            return Err("frame: invalid TryLevel sentinel".into());
                        }
                    }
                }
                if word.kind == Kind::Pushed
                    && !matches!((&word.value,&value),(Value::Scalar(scope),Value::EncodedScope(s)) if scope==s)
                    && self.record.is_none_or(|r| at != r + 12)
                {
                    return Err("frame: unproved pushed slot overwrite".into());
                }
                self.emit_store(at, &value);
                self.words.get_mut(&at).unwrap().value = value;
            }
            _ => return Err("frame: write form".into()),
        }
        Ok(())
    }
    fn push(&mut self, value: Value) -> Result<(), String> {
        let at = self.sp.checked_sub(4).ok_or("frame: push overflow")?;
        if at < -4096 || self.words.contains_key(&at) {
            return Err("frame: push budget/overlap".into());
        }
        let kind = if matches!(value, Value::Saved(_)) {
            Kind::Saved
        } else {
            Kind::Pushed
        };
        self.emit_store(at, &value);
        self.words.insert(at, Word { value, kind });
        self.sp = at;
        self.registers[4] = Value::Stack(at);
        Ok(())
    }
    fn allocate(&mut self, delta: i32) -> Result<(), String> {
        let next = self
            .sp
            .checked_add(delta)
            .ok_or("frame: allocation overflow")?;
        if delta >= 0 || delta % 4 != 0 || next < -4096 {
            return Err("frame: non-allocation stack adjustment/budget".into());
        }
        for at in (next..self.sp).step_by(4) {
            if self.words.contains_key(&at) {
                return Err("frame: overlapping allocation".into());
            }
            self.emit_store(at, &Value::Unknown);
            self.words.insert(
                at,
                Word {
                    value: Value::Unknown,
                    kind: Kind::Allocated,
                },
            );
        }
        self.sp = next;
        self.registers[4] = Value::Stack(next);
        Ok(())
    }
    fn install(&mut self, value: Value) -> Result<(), String> {
        if self.record.is_some() || !self.read_fs {
            return Err("frame: FS installation order".into());
        }
        let Value::Stack(at) = value else {
            return Err("frame: raw FS head assignment".into());
        };
        let get = |offset| self.words.get(&(at + offset)).map(|word| &word.value);
        if get(0) != Some(&Value::Borrowed) {
            return Err("frame: lost borrowed predecessor".into());
        }
        let Some(Value::Scalar(handler)) = get(4) else {
            return Err("frame: handler slot".into());
        };
        let Some(Value::EncodedScope(scope)) = get(8) else {
            return Err("frame: unencoded scope slot".into());
        };
        if !self.handlers.contains(handler)
            || !self.scopes.contains(scope)
            || get(12) != Some(&Value::Scalar((-2i32) as u32))
        {
            return Err("frame: unbound handler/scope/TryLevel record".into());
        }
        self.record = Some(at);
        self.source.push_str(&format!(
            "let installed_head=frame_address(entry_sp,{at})?;\n"
        ));
        Ok(())
    }
}

/// Decode an exact supplied prefix ending at an explicit fragment boundary.
/// Calls, branches, unknown memory effects and unmodeled FS operations reject.
pub(crate) fn prove_frame(
    code: &[u8],
    origin: u32,
    cookie_va: u32,
    allowed_scopes: &BTreeSet<u32>,
    allowed_handlers: &BTreeSet<u32>,
) -> Result<ProvenFrame, String> {
    if code.is_empty()
        || code.len() > 2048
        || !cookie_va.is_multiple_of(4)
        || allowed_scopes.is_empty()
        || allowed_handlers.is_empty()
    {
        return Err("frame: input/binding budget".into());
    }
    let end = origin
        .checked_add(code.len() as u32)
        .ok_or("frame: code overflow")?;
    let mut registers = std::array::from_fn(|i| Value::Saved(i as u8));
    registers[4] = Value::Stack(0);
    let mut s = State {
        registers,
        words: BTreeMap::from([(
            0,
            Word {
                value: Value::Return,
                kind: Kind::Protected,
            },
        )]),
        sp: 0,
        bp: None,
        record: None,
        read_fs: false,
        cookie_va,
        scopes: allowed_scopes,
        handlers: allowed_handlers,
        source:
            "let mut words=std::collections::BTreeMap::new();\nwords.insert(0,FrameWord::Return);\n"
                .into(),
    };
    let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
    let mut count = 0;
    while decoder.can_decode() {
        let i = decoder.decode();
        count += 1;
        if i.is_invalid() || count > 256 {
            return Err("frame: malformed instruction/budget".into());
        }
        let at = (i.ip() - u64::from(origin)) as usize;
        let bytes = &code[at..at + i.len()];
        if i.segment_prefix() == Register::FS {
            if bytes[0] != 0x64
                || !matches!(bytes.get(1), Some(0xa1 | 0xa3 | 0x8b | 0x89))
                || i.has_lock_prefix()
                || i.has_rep_prefix()
                || i.has_repne_prefix()
                || i.mnemonic() != Mnemonic::Mov
                || i.memory_base() != Register::None
                || i.memory_index() != Register::None
                || i.memory_displacement32() != 0
                || i.memory_size() != MemorySize::UInt32
            {
                return Err("frame: FS instruction policy".into());
            }
            let reg_index = |r| match r {
                Register::EAX => Ok(0),
                Register::ECX => Ok(1),
                Register::EDX => Ok(2),
                Register::EBX => Ok(3),
                Register::ESI => Ok(6),
                Register::EDI => Ok(7),
                _ => Err("frame: FS register"),
            };
            if matches!(i.code(), Code::Mov_EAX_moffs32 | Code::Mov_r32_rm32)
                && i.op0_kind() == OpKind::Register
                && i.op1_kind() == OpKind::Memory
            {
                if s.read_fs || s.record.is_some() {
                    return Err("frame: repeated borrowed FS capture".into());
                }
                s.registers[reg_index(i.op0_register())?] = Value::Borrowed;
                s.read_fs = true;
            } else if matches!(i.code(), Code::Mov_moffs32_EAX | Code::Mov_rm32_r32)
                && i.op0_kind() == OpKind::Memory
                && i.op1_kind() == OpKind::Register
            {
                s.install(s.registers[reg_index(i.op1_register())?].clone())?;
            } else {
                return Err("frame: FS form".into());
            }
            continue;
        }
        match graph::normalized(&i, bytes)? {
            Operation::Push(operand) => {
                let value = s.read(&operand)?;
                s.push(value)?;
            }
            Operation::Binary(Binary::Move, dst, src) => {
                let value = s.read(&src)?;
                s.write(&dst, value)?;
            }
            Operation::Binary(op, Operand::Reg(reg), Operand::Immediate(n))
                if full(reg)? == 4 && matches!(op, Binary::Add | Binary::Sub) =>
            {
                let delta = if op == Binary::Add {
                    n as i32
                } else {
                    (n as i32)
                        .checked_neg()
                        .ok_or("frame: adjustment overflow")?
                };
                s.allocate(delta)?;
            }
            Operation::Binary(Binary::Xor, dst, src) => {
                let left = s.read(&dst)?;
                let right = s.read(&src)?;
                let value = match (left, right) {
                    (Value::Scalar(scope), Value::Cookie)
                    | (Value::Cookie, Value::Scalar(scope))
                        if allowed_scopes.contains(&scope) =>
                    {
                        Value::EncodedScope(scope)
                    }
                    (Value::Cookie, Value::Stack(frame)) | (Value::Stack(frame), Value::Cookie)
                        if s.bp == Some(frame) =>
                    {
                        Value::Guard(frame)
                    }
                    _ => return Err("frame: unproved encoded pointer/guard expression".into()),
                };
                s.write(&dst, value)?;
            }
            Operation::Address(reg, address) => {
                let value = Value::Stack(s.address(&address)?);
                s.write(&Operand::Reg(reg), value)?;
            }
            Operation::Nop => {}
            _ => return Err("frame: unsupported effect/fragment crosses call or branch".into()),
        }
    }
    let bp = s.bp.ok_or("frame: missing frame base")?;
    let record = s.record.ok_or("frame: missing FS record installation")?;
    let Value::EncodedScope(scope_va) = s.words[&(record + 8)].value else {
        return Err("frame: scope identity lost".into());
    };
    let Value::Scalar(handler_va) = s.words[&(record + 4)].value else {
        return Err("frame: handler identity lost".into());
    };
    let Value::Scalar(level) = s.words[&(record + 12)].value else {
        return Err("frame: TryLevel lost".into());
    };
    let mut scalar_words = BTreeMap::new();
    let mut ordinary_words = BTreeSet::new();
    let mut guard_offsets = Vec::new();
    let mut saved_slots = BTreeMap::new();
    for (&at, word) in &s.words {
        if word.kind == Kind::Allocated
            && matches!(word.value, Value::Unknown | Value::Scalar(_))
            && !(record..record + 16).contains(&at)
        {
            ordinary_words.insert(at - bp);
        }
        match word.value {
            Value::Scalar(n)
                if word.kind == Kind::Allocated && !(record..record + 16).contains(&at) =>
            {
                scalar_words.insert(at - bp, n);
            }
            Value::Guard(frame) if frame == bp => guard_offsets.push(at - bp),
            Value::Saved(reg) => {
                saved_slots.insert(at - bp, reg);
            }
            _ => {}
        }
    }
    if guard_offsets.is_empty() {
        return Err("frame: missing frame-bound cookie guard".into());
    }
    let mut pending_arguments = Vec::new();
    let mut argument = s.sp;
    while let Some(Word {
        kind: Kind::Pushed,
        value: Value::Scalar(value),
    }) = s.words.get(&argument)
    {
        if (record..record + 16).contains(&argument) {
            break;
        }
        pending_arguments.push(*value);
        argument = argument
            .checked_add(4)
            .ok_or("frame: argument range overflow")?;
    }
    // Validate every represented word's numeric range before exposing a frame.
    let preflight = format!(
        "frame_address(entry_sp,0)?;frame_address(entry_sp,{})?;\n",
        s.sp
    );
    s.source.push_str(&format!("Ok(FrameImage{{words,entry_sp,ebp:frame_address(entry_sp,{bp})?,esp:frame_address(entry_sp,{})?,record:installed_head,scope_va:{scope_va},handler_va:{handler_va},try_level:{}i32}})\n",s.sp,level as i32));
    Ok(ProvenFrame {
        end,
        esp: s.sp - bp,
        ebp: bp,
        record: record - bp,
        scope_va,
        handler_va,
        try_level_offset: record + 12 - bp,
        try_level: level as i32,
        scalar_words,
        ordinary_words,
        pending_arguments,
        guard_offsets,
        saved_slots,
        body: preflight + &s.source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const COOKIE: u32 = 0x7000;
    fn code() -> Vec<u8> {
        let mut b = vec![0x55, 0x8b, 0xec, 0x6a, 0xfe, 0x68];
        b.extend(0x5000u32.to_le_bytes());
        b.push(0x68);
        b.extend(0x6000u32.to_le_bytes());
        b.extend([
            0x64, 0xa1, 0, 0, 0, 0, 0x50, 0x83, 0xec, 0x20, 0x53, 0x56, 0x57, 0xa1,
        ]);
        b.extend(COOKIE.to_le_bytes());
        b.extend([
            0x31, 0x45, 0xf8, 0x33, 0xc5, 0x50, 0x8d, 0x45, 0xf0, 0x64, 0xa3, 0, 0, 0, 0, 0xc7,
            0x45, 0xe8, 123, 0, 0, 0, 0xc7, 0x45, 0xe4, 2, 0, 0, 0, 0xc7, 0x45, 0xfc, 7, 0, 0, 0,
        ]);
        b
    }
    fn proof(bytes: &[u8]) -> Result<ProvenFrame, String> {
        prove_frame(
            bytes,
            0x1000,
            COOKIE,
            &BTreeSet::from([0x5000]),
            &BTreeSet::from([0x6000]),
        )
    }
    fn replace(bytes: &mut [u8], from: &[u8], to: &[u8]) {
        let at = bytes.windows(from.len()).position(|b| b == from).unwrap();
        assert_eq!(from.len(), to.len());
        bytes[at..at + from.len()].copy_from_slice(to);
    }
    #[test]
    fn derived_scalar_cells_are_distinct_from_original_record_and_try_level() {
        let p = proof(&code()).unwrap();
        assert_eq!(p.ebp_offset(), -4);
        assert_eq!(p.esp_offset(), -64);
        assert_eq!(p.record_offset(), -16);
        assert_eq!(p.try_level_offset(), -4);
        assert_eq!(p.try_level(), 7);
        assert_eq!(p.scope_va(), 0x5000);
        assert_eq!(p.handler_va(), 0x6000);
        assert_eq!(p.scalar_words(), &BTreeMap::from([(-28, 2), (-24, 123)]));
        assert_eq!(p.guard_offsets(), &[-64]);
        assert!(p.ordinary_words().contains(&-20));
        assert!(p.ordinary_words().contains(&-24));
        assert!(!p.ordinary_words().contains(&-4));
        assert!(!p.ordinary_words().contains(&-16));
        assert!(!p.ordinary_words().contains(&-64));
        assert!(p.pending_arguments().is_empty());
        assert!(p.validate_eh4_header([-2, 0, -64, 0]).is_ok());
        for header in [
            [-24, 0, -64, 0],
            [-2, 0, -4, 0],
            [-2, 4, -64, 0],
            [-2, 0, -64, 4],
        ] {
            assert!(p.validate_eh4_header(header).is_err());
        }
        let mut arguments = code();
        arguments.extend([0x6a, 0, 0x6a, 0, 0x6a, 0, 0x68, 0x42, 0x42, 0x42, 0xe0]);
        let arguments = proof(&arguments).unwrap();
        assert_eq!(arguments.pending_arguments(), &[0xe0424242, 0, 0, 0]);
        assert_eq!(arguments.scalar_words(), p.scalar_words());
        assert_eq!(arguments.ordinary_words(), p.ordinary_words());
        let mut displaced = code();
        replace(&mut displaced, &[0xc7, 0x45, 0xe8], &[0xc7, 0x45, 0xe0]);
        let q = proof(&displaced).unwrap();
        assert_eq!(q.scalar_words().get(&-32), Some(&123));
        assert_eq!(q.try_level(), 7);
    }
    #[test]
    fn native_initialization_preserves_opaque_predecessor_and_dynamic_cookie_bits() {
        let p = proof(&code()).unwrap();
        let source=format!("{}\nfn initialize<P:Clone>(entry_sp:u32,cookie:u32,saved:[Option<u32>;8],predecessor:P)->Result<FrameImage<P>,&'static str>{{{}}}\nfn main(){{let image=initialize(0x9000,0xabcdef,[None;8],String::from(\"borrowed-thread-root\")).unwrap();assert_eq!(image.ebp,0x8ffc);assert_eq!(image.record,0x8fec);assert_eq!(image.try_level,7);assert_eq!(image.words.get(&-20),Some(&FrameWord::Borrowed(String::from(\"borrowed-thread-root\"))));assert_eq!(image.words.get(&-12),Some(&FrameWord::EncodedScope{{scope:0x5000,cookie:0xabcdef,bits:0x5000^0xabcdef}}));assert_eq!(image.words.get(&-68),Some(&FrameWord::Guard{{frame:0x8ffc,cookie:0xabcdef,bits:0x8ffc^0xabcdef}}));assert_eq!(image.words.get(&-28),Some(&FrameWord::Scalar(123)));assert_eq!(image.words.get(&-32),Some(&FrameWord::Scalar(2)));assert!(initialize(4,0,[None;8],()).is_err());assert!(initialize(0x9001,0,[None;8],()).is_err());}}",EMITTED_TYPES,p.initializer_body());
        let dir = std::env::temp_dir().join(format!("w2l-frame-proof-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("frame.rs");
        let bin = dir.join(if cfg!(windows) { "frame.exe" } else { "frame" });
        std::fs::write(&file, source).unwrap();
        let output = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(&file)
            .arg("-o")
            .arg(&bin)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(std::process::Command::new(&bin).status().unwrap().success());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn protected_unknown_root_and_unmodeled_effects_reject() {
        for offset in [0, 4, 0xf0, 0xf4, 0xf8, 0xc0] {
            let mut b = code();
            replace(&mut b, &[0xc7, 0x45, 0xe8], &[0xc7, 0x45, offset]);
            assert!(proof(&b).is_err(), "protected offset {offset:02x}");
        }
        let mut uninitialized = code();
        replace(&mut uninitialized, &[0x8d, 0x45, 0xf0], &[0x8b, 0x45, 0xe0]);
        assert!(proof(&uninitialized).is_err());
        let mut badfs = code();
        replace(
            &mut badfs,
            &[0x64, 0xa1, 0, 0, 0, 0],
            &[0x64, 0xa1, 4, 0, 0, 0],
        );
        assert!(proof(&badfs).is_err());
        let mut root = code();
        replace(
            &mut root,
            &[0x64, 0xa1, 0, 0, 0, 0],
            &[0xb8, 0, 0, 0, 0, 0x90],
        );
        assert!(proof(&root).is_err());
        let mut call = code();
        call.extend([0xe8, 0, 0, 0, 0]);
        assert!(proof(&call).is_err());
        let mut bp = code();
        bp.extend([0x8b, 0xec]);
        assert!(proof(&bp).is_err());
        let mut pointer = code();
        pointer.extend([0x8b, 0x45, 0xf0, 0x8b, 0]);
        assert!(proof(&pointer).is_err());
        let mut prefix = code();
        let at = prefix.windows(2).position(|b| b == [0x64, 0xa1]).unwrap();
        prefix.insert(at + 1, 0x67);
        assert!(proof(&prefix).is_err());
    }
    #[test]
    fn separated_initializer_keeps_unproved_gap_and_does_not_change_other_slots() {
        let p = proof(&code()).unwrap();
        let fragment = p
            .prove_initializer_fragment(&[0xc7, 0x45, 0xfc, 0, 0, 0, 0], p.end() + 32)
            .unwrap();
        assert_eq!(fragment.gap(), Some((p.end(), p.end() + 32)));
        assert_eq!(fragment.try_level(), Some(0));
        assert_eq!(fragment.writes(), &BTreeMap::from([(-4, 0)]));
        assert_eq!(p.try_level(), 7);
        assert_eq!(p.scalar_words().get(&-28), Some(&2));
        assert!(p
            .prove_initializer_fragment(&[0xc7, 0x45, 0xf0, 0, 0, 0, 0], p.end())
            .is_err());
        assert!(p
            .prove_initializer_fragment(&[0xe8, 0, 0, 0, 0], p.end())
            .is_err());
    }
}
