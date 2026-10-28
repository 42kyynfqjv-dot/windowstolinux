//! Original language-filter execution and EH4 scope selection at a validated
//! frame/event boundary. This is not a thread registration or cookie proof.
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};

/// These locations must be obtained from the original live frame proof. Only
/// listed temporary words may be written; the exception-pointer slot is read-only.
pub struct FilterLayout {
    pub start: i32,
    pub end: i32,
    pub exception_pointers_offset: i32,
    pub writable_words: Vec<i32>,
}
pub struct FilterProof {
    body: String,
    result: i32,
    #[allow(dead_code)] // The CRT backend is not linked into every slice example.
    live: String,
}
impl FilterProof {
    /// Body for a private function `(code:u32, words:&mut[Option<u32>]) -> Result<i32,&str>`.
    pub fn body(&self) -> &str {
        &self.body
    }
    #[allow(dead_code)]
    pub fn live_body(&self) -> &str {
        &self.live
    }
    pub fn result(&self) -> i32 {
        self.result
    }
}
#[derive(Clone)]
enum Value {
    Unknown,
    ExceptionPointers,
    ExceptionRecord,
    Scalar { expression: String, known: u32 },
}
fn scalar(value: &Value) -> Result<(&str, u32), String> {
    match value {
        Value::Scalar { expression, known } => Ok((expression, *known)),
        _ => Err("selection: scalar provenance".into()),
    }
}
fn volatile(register: Register) -> Result<usize, String> {
    match register {
        Register::EAX => Ok(0),
        Register::ECX => Ok(1),
        Register::EDX => Ok(2),
        _ => Err("selection: protected or partial register".into()),
    }
}
fn temporary(layout: &FilterLayout, offset: i32) -> Result<usize, String> {
    layout
        .writable_words
        .iter()
        .position(|&at| at == offset)
        .ok_or("selection: unowned frame word".into())
}
fn validate_layout(layout: &FilterLayout) -> Result<(), String> {
    if layout.start < -4096
        || layout.end > 0
        || layout.start >= layout.end
        || layout.writable_words.len() > 64
    {
        return Err("selection: frame extent budget".into());
    }
    let mut seen = BTreeSet::new();
    for offset in std::iter::once(layout.exception_pointers_offset)
        .chain(layout.writable_words.iter().copied())
    {
        if offset % 4 != 0
            || offset < layout.start
            || offset.checked_add(4).is_none_or(|end| end > layout.end)
            || !seen.insert(offset)
        {
            return Err("selection: aliased or incomplete frame words".into());
        }
    }
    Ok(())
}
fn clean_instruction(i: &Instruction) -> Result<(), String> {
    if i.is_invalid()
        || i.has_lock_prefix()
        || i.has_rep_prefix()
        || i.has_repne_prefix()
        || i.segment_prefix() != Register::None
        || i.memory_index() != Register::None
    {
        return Err("selection: instruction or address policy".into());
    }
    Ok(())
}

/// Executes the original filter over a known event code and owned pointer graph:
/// frame[exception slot] -> EXCEPTION_POINTERS[0] -> EXCEPTION_RECORD[0].
/// The caller must prove the original handler installed those objects and that
/// preceding exception-code transformations preserve the supplied code. Complete
/// integers or a guessed EBP do not satisfy these premises by themselves.
pub fn prove_filter(
    code: &[u8],
    origin: u32,
    layout: &FilterLayout,
    event_code: u32,
) -> Result<FilterProof, String> {
    validate_layout(layout)?;
    if code.is_empty() || code.len() > 512 || origin.checked_add(code.len() as u32).is_none() {
        return Err("selection: filter extent".into());
    }
    let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
    let mut registers = [Value::Unknown, Value::Unknown, Value::Unknown];
    let mut words = vec![None; layout.writable_words.len()];
    let mut zero = None;
    let mut serial = 0;
    let mut count = 0;
    let mut body = format!(
        "if code!={event_code}u32 || words.len()!={} {{return Err(\"filter entry boundary\");}}\n",
        words.len()
    );
    let mut live = String::from("frame.validate()?;\n");
    while decoder.can_decode() {
        let i = decoder.decode();
        count += 1;
        clean_instruction(&i)?;
        if count > 64 {
            return Err("selection: instruction budget".into());
        }
        match i.mnemonic() {
            Mnemonic::Mov if i.code() == Code::Mov_r32_rm32 => {
                let destination = volatile(i.op0_register())?;
                let value = if i.op1_kind() == OpKind::Register {
                    registers[volatile(i.op1_register())?].clone()
                } else if i.op1_kind() == OpKind::Memory {
                    let offset = i.memory_displacement32() as i32;
                    if i.memory_base() == Register::EBP {
                        if offset == layout.exception_pointers_offset {
                            Value::ExceptionPointers
                        } else {
                            let index = temporary(layout, offset)?;
                            let known =
                                words[index].ok_or("selection: uninitialized temporary read")?;
                            let name = format!("v{serial}");
                            serial += 1;
                            body.push_str(&format!("let {name}=words[{index}].ok_or(\"uninitialized filter word\")?;\n"));
                            Value::Scalar {
                                expression: name,
                                known,
                            }
                        }
                    } else {
                        let base = volatile(i.memory_base())?;
                        if offset != 0 {
                            return Err("selection: exception object field bounds".into());
                        }
                        match &registers[base] {
                            Value::ExceptionPointers => Value::ExceptionRecord,
                            Value::ExceptionRecord => {
                                let name = format!("v{serial}");
                                serial += 1;
                                body.push_str(&format!("let {name}=code;\n"));
                                Value::Scalar {
                                    expression: name,
                                    known: event_code,
                                }
                            }
                            _ => return Err("selection: exception object ownership".into()),
                        }
                    }
                } else {
                    return Err("selection: MOV source".into());
                };
                if matches!(value, Value::Unknown) {
                    return Err("selection: unknown register read".into());
                }
                let source = if i.op1_kind() == OpKind::Register {
                    format!("cpu.r[{}]", volatile(i.op1_register())?)
                } else if i.memory_base() == Register::EBP {
                    format!("frame.read({})?", i.memory_displacement32() as i32)
                } else {
                    format!(
                        "frame.rt.load(CrtCpu::pointer(cpu.r[{}])?,32)?",
                        volatile(i.memory_base())?
                    )
                };
                live.push_str(&format!("cpu.r[{destination}]={source};\n"));
                if i.op1_kind() == OpKind::Memory
                    && i.memory_base() != Register::EBP
                    && matches!(
                        registers[volatile(i.memory_base())?],
                        Value::ExceptionRecord
                    )
                {
                    live.push_str(&format!("if cpu.r[{destination}].known_scalar()? != {event_code}u32{{return Err(\"live filter event proof boundary\");}}\n"));
                }
                registers[destination] = value;
            }
            Mnemonic::Mov if i.code() == Code::Mov_rm32_r32 && i.op0_kind() == OpKind::Memory => {
                if i.memory_base() != Register::EBP {
                    return Err("selection: external/protected write".into());
                }
                let index = temporary(layout, i.memory_displacement32() as i32)?;
                let (expression, known) = scalar(&registers[volatile(i.op1_register())?])?;
                body.push_str(&format!("words[{index}]=Some({expression});\n"));
                live.push_str(&format!(
                    "frame.write_u32({},cpu.r[{}].known_scalar()?)?;\n",
                    i.memory_displacement32() as i32,
                    volatile(i.op1_register())?
                ));
                words[index] = Some(known);
            }
            Mnemonic::Xor
                if i.op0_kind() == OpKind::Register
                    && i.op1_kind() == OpKind::Register
                    && i.op0_register() == i.op1_register() =>
            {
                let index = volatile(i.op0_register())?;
                let name = format!("v{serial}");
                serial += 1;
                body.push_str(&format!("let {name}=0u32;\n"));
                registers[index] = Value::Scalar {
                    expression: name,
                    known: 0,
                };
                live.push_str(&format!("cpu.r[{index}]=cpu.zero();\n"));
                zero = Some((String::from("true"), true));
            }
            Mnemonic::Cmp if matches!(i.code(), Code::Cmp_rm32_imm32 | Code::Cmp_rm32_imm8) => {
                let left = if i.op0_kind() == OpKind::Register {
                    registers[volatile(i.op0_register())?].clone()
                } else if i.op0_kind() == OpKind::Memory && i.memory_base() == Register::EBP {
                    let index = temporary(layout, i.memory_displacement32() as i32)?;
                    let known = words[index].ok_or("selection: uninitialized compare")?;
                    let name = format!("v{serial}");
                    serial += 1;
                    body.push_str(&format!(
                        "let {name}=words[{index}].ok_or(\"uninitialized filter compare\")?;\n"
                    ));
                    Value::Scalar {
                        expression: name,
                        known,
                    }
                } else {
                    return Err("selection: compare operand".into());
                };
                let immediate = if i.code() == Code::Cmp_rm32_imm8 {
                    i.immediate8to32() as u32
                } else {
                    i.immediate32()
                };
                let (expression, known) = scalar(&left)?;
                let operand = if i.op0_kind() == OpKind::Register {
                    format!("cpu.r[{}]", volatile(i.op0_register())?)
                } else {
                    format!("frame.read({})?", i.memory_displacement32() as i32)
                };
                live.push_str(&format!(
                    "cpu.binary(frame.rt,7,{operand},CrtValue::scalar({immediate}),32)?;\n"
                ));
                zero = Some((format!("{expression}=={immediate}u32"), known == immediate));
            }
            Mnemonic::Sete if i.op0_kind() == OpKind::Register => {
                let index = match i.op0_register() {
                    Register::AL => 0,
                    Register::CL => 1,
                    Register::DL => 2,
                    _ => return Err("selection: SETE partial width".into()),
                };
                let (old, known) = scalar(&registers[index])?;
                let (condition, value) = zero.as_ref().ok_or("selection: unknown equality flag")?;
                let name = format!("v{serial}");
                serial += 1;
                body.push_str(&format!(
                    "let {name}=({old}&!255u32)|u32::from({condition});\n"
                ));
                live.push_str(&format!("cpu.set({index},8,0,CrtValue::scalar(u32::from(cpu.flags.zf.ok_or(\"filter unknown ZF\")?)))?;\n"));
                registers[index] = Value::Scalar {
                    expression: name,
                    known: (known & !255) | u32::from(*value),
                };
            }
            Mnemonic::Ret if i.code() == Code::Retnd => {
                if decoder.can_decode() {
                    return Err("selection: trailing filter bytes".into());
                }
                let (expression, known) = scalar(&registers[0])?;
                body.push_str(&format!("Ok({expression} as i32)\n"));
                live.push_str("cpu.r[0].known_scalar()?;Ok(cpu.r[0])\n");
                return Ok(FilterProof {
                    body,
                    result: known as i32,
                    live,
                });
            }
            _ => return Err("selection: unsupported original filter effect".into()),
        }
    }
    Err("selection: missing filter return".into())
}

/// A proof of the original code transformation's identity for one independently
/// derived event code. It does not assert identity for another event or establish
/// the lifetime/initialization of the supplied global read capabilities.
pub struct CodeIdentity {
    body: String,
    returns: usize,
    temporary_bytes: u32,
    #[allow(dead_code)]
    globals: Vec<u32>,
}
impl CodeIdentity {
    /// Body for `(code:u32) -> Result<u32,&'static str>`. Original guard loads can
    /// be eliminated only because every possible guard result was proved to
    /// return this same code without observable writes.
    #[allow(dead_code)] // CRT integration, not every standalone slice.
    pub fn normal_call(&self, name: &str) -> String {
        self.emit_normal_call(name, false)
    }
    #[allow(dead_code)]
    pub fn prefix_call(&self, name: &str) -> String {
        self.emit_normal_call(name, true)
    }
    fn emit_normal_call(&self, name: &str, caller_arguments: bool) -> String {
        let arguments = if caller_arguments {
            "if frame.rt.load(CrtCpu::pointer(cpu.r[4])?,32)?.known_scalar()?!=code{return Err(\"normalizer prefix argument\");}"
        } else {
            "cpu.push(frame.rt,CrtValue::scalar(code))?;"
        };
        let cleanup = if caller_arguments {
            ""
        } else {
            "cpu.discard(frame.rt,4)?;cpu.flags=CrtFlags::unknown();"
        };
        let globals=self.globals.iter().map(|at|format!("frame.rt.load(frame.rt.resolve_absolute({at},CrtRegionKind::Module)?,32)?.known_scalar()?;\n")).collect::<String>();
        format!(
            r#"fn {name}(frame:&mut CrtLiveFrame<'_,'_>,cpu:&mut CrtCpu,objects:&CrtNormalObjects,continuation:u32)->RegistryResult<CrtValue>{{
 frame.validate()?;objects.validate(frame.event,frame.rt,frame.epoch)?;
 {globals}
 let code=frame.rt.load(objects.record,32)?.known_scalar()?;
 let value=(||{{ {body} }})()?;
 let sp=CrtCpu::pointer(cpu.r[4])?;let low=frame.rt.offset(sp,-{depth})?;frame.rt.valid(low,{depth})?;
 frame.epoch.registry.range(low.address(),u64::from(sp.address()))?;
 if frame.rt.overlapping_tags(low.address(),{depth}).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)|CrtValue::OpaqueSaved(_))){{return Err("normalizer temporary stack aliases protected storage");}}
 {arguments}
 let returned=frame.call(cpu,continuation,|f,child|{{
  if f.rt.load(f.rt.offset(CrtCpu::pointer(child.entry[4])?,4)?,32)?.known_scalar()?!=code{{return Err("normalizer original argument");}}
  child.clobber(CrtValue::scalar(value));child.finish(f.rt)
 }})?;
 {cleanup}Ok(returned)
}}"#,
            body = self.body,
            depth = self.temporary_bytes + 8
        )
    }
    pub fn body(&self) -> &str {
        &self.body
    }
    pub fn proved_return_paths(&self) -> usize {
        self.returns
    }
    pub fn temporary_bytes(&self) -> u32 {
        self.temporary_bytes
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum HelperValue {
    Unknown,
    Integer(u32),
    Stack(i32),
    Saved(usize),
}
#[derive(Clone)]
struct HelperState {
    registers: [HelperValue; 8],
    sp: i32,
    words: BTreeMap<i32, HelperValue>,
    zero: Option<bool>,
    less: Option<bool>,
    visited: BTreeSet<u32>,
}
fn helper_register(register: Register) -> Result<usize, String> {
    match register {
        Register::EAX => Ok(0),
        Register::ECX => Ok(1),
        Register::EDX => Ok(2),
        Register::EBX => Ok(3),
        Register::ESP => Ok(4),
        Register::EBP => Ok(5),
        Register::ESI => Ok(6),
        Register::EDI => Ok(7),
        _ => Err("selection helper: partial register".into()),
    }
}
impl HelperState {
    fn read_register(&self, register: Register) -> Result<HelperValue, String> {
        let index = helper_register(register)?;
        Ok(if index == 4 {
            HelperValue::Stack(self.sp)
        } else {
            self.registers[index].clone()
        })
    }
    fn set_register(&mut self, register: Register, value: HelperValue) -> Result<(), String> {
        let index = helper_register(register)?;
        if index == 4 {
            return Err("selection helper: unsupported ESP assignment".into());
        }
        self.registers[index] = value;
        Ok(())
    }
    fn operand(
        &self,
        i: &Instruction,
        kind: OpKind,
        register: Register,
        initialized_globals: &BTreeSet<u32>,
    ) -> Result<HelperValue, String> {
        if kind == OpKind::Register {
            return self.read_register(register);
        }
        if kind != OpKind::Memory {
            return Err("selection helper: unsupported operand".into());
        }
        if i.memory_base() == Register::None {
            let address = i.memory_displacement32();
            if i.memory_displ_size() != 4
                || address.checked_add(4).is_none()
                || !initialized_globals.contains(&address)
            {
                return Err("selection helper: unbound initialized global read".into());
            }
            return Ok(HelperValue::Unknown);
        }
        let HelperValue::Stack(base) = self.read_register(i.memory_base())? else {
            return Err("selection helper: unowned stack read".into());
        };
        let offset = base
            .checked_add(i.memory_displacement32() as i32)
            .ok_or("selection helper: stack address overflow")?;
        if offset < self.sp || offset % 4 != 0 {
            return Err("selection helper: stack word lifetime/bounds".into());
        }
        self.words
            .get(&offset)
            .cloned()
            .ok_or("selection helper: protected or uninitialized stack read".into())
    }
}

/// Prove a bounded original helper returns its known input unchanged on every
/// reachable path. Each supplied address grants only an initialized, readable
/// four-byte global value, otherwise unknown; composition must establish this
/// capability from the actual image/module and its original startup state. Both
/// outcomes of an unknown comparison are explored, never sampled. Only private
/// stack writes are admitted, and the return/argument and nonvolatile registers
/// must be intact. Calls, exception-generating or unmodeled reachable operations,
/// cycles, and exhausted budgets fail closed. This is a valid-stack/no-fault
/// instruction contract, not proof of Windows loader or exception dispatch.
/// The emitted scalar result does not expose a guest register/flag snapshot:
/// callers must invalidate volatile ECX/EDX and status flags at this ABI boundary.
pub fn prove_code_identity(
    code: &[u8],
    origin: u32,
    initialized_globals: &BTreeSet<u32>,
    event_code: u32,
) -> Result<CodeIdentity, String> {
    if code.is_empty() || code.len() > 512 || origin.checked_add(code.len() as u32).is_none() {
        return Err("selection helper: code extent".into());
    }
    let mut decoder = Decoder::with_ip(32, code, origin as u64, DecoderOptions::NONE);
    let mut instructions = BTreeMap::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        if i.is_invalid() || instructions.len() == 128 {
            return Err("selection helper: malformed code or instruction budget".into());
        }
        instructions.insert(i.ip32(), i);
    }
    let initial = HelperState {
        registers: std::array::from_fn(|index| {
            if [3, 5, 6, 7].contains(&index) {
                HelperValue::Saved(index)
            } else {
                HelperValue::Unknown
            }
        }),
        sp: 0,
        words: BTreeMap::from([(4, HelperValue::Integer(event_code))]),
        zero: None,
        less: None,
        visited: BTreeSet::new(),
    };
    let mut pending = vec![(origin, initial)];
    let mut explored = 0;
    let mut returns = 0;
    let mut temporary_bytes = 0;
    while let Some((mut pc, mut state)) = pending.pop() {
        loop {
            explored += 1;
            if explored > 256 || !state.visited.insert(pc) {
                return Err("selection helper: cyclic path or state budget".into());
            }
            let i = instructions
                .get(&pc)
                .ok_or("selection helper: instruction boundary")?;
            clean_instruction(i)?;
            let first = code[(pc - origin) as usize];
            if matches!(first, 0x66 | 0x67) {
                return Err("selection helper: operand/address size prefix".into());
            }
            match i.code() {
                Code::Push_r32 => {
                    let value = state.read_register(i.op0_register())?;
                    let next = state
                        .sp
                        .checked_sub(4)
                        .ok_or("selection helper: stack wrap")?;
                    if next < -128 || state.words.contains_key(&next) {
                        return Err("selection helper: stack allocation budget/alias".into());
                    }
                    state.words.insert(next, value);
                    state.sp = next;
                    temporary_bytes = temporary_bytes.max((-next) as u32);
                }
                Code::Pop_r32 => {
                    if state.sp >= 0 || i.op0_register() == Register::ESP {
                        return Err("selection helper: protected stack pop".into());
                    }
                    let value = state
                        .words
                        .remove(&state.sp)
                        .ok_or("selection helper: uninitialized pop")?;
                    state.sp += 4;
                    state.set_register(i.op0_register(), value)?;
                }
                Code::Mov_r32_rm32 | Code::Mov_rm32_r32 => {
                    if i.op0_kind() != OpKind::Register {
                        return Err("selection helper: observable memory write".into());
                    }
                    let value =
                        state.operand(i, i.op1_kind(), i.op1_register(), initialized_globals)?;
                    state.set_register(i.op0_register(), value)?;
                }
                Code::Mov_r32_imm32 => {
                    state.set_register(i.op0_register(), HelperValue::Integer(i.immediate32()))?;
                }
                Code::Cmp_rm32_imm32 | Code::Cmp_rm32_imm8 | Code::Cmp_EAX_imm32 => {
                    let value =
                        state.operand(i, i.op0_kind(), i.op0_register(), initialized_globals)?;
                    let immediate = if i.code() == Code::Cmp_rm32_imm8 {
                        i.immediate8to32() as u32
                    } else {
                        i.immediate32()
                    };
                    match value {
                        HelperValue::Integer(value) => {
                            state.zero = Some(value == immediate);
                            state.less = Some((value as i32) < (immediate as i32));
                        }
                        HelperValue::Unknown => {
                            state.zero = None;
                            state.less = None;
                        }
                        _ => return Err("selection helper: pointer/saved scalar compare".into()),
                    }
                }
                Code::Jl_rel8_32
                | Code::Jl_rel32_32
                | Code::Je_rel8_32
                | Code::Je_rel32_32
                | Code::Jne_rel8_32
                | Code::Jne_rel32_32 => {
                    let target = i.near_branch32();
                    if !instructions.contains_key(&target)
                        || !instructions.contains_key(&i.next_ip32())
                    {
                        return Err("selection helper: branch target boundary".into());
                    }
                    let condition = match i.mnemonic() {
                        Mnemonic::Jl => state.less,
                        Mnemonic::Je => state.zero,
                        _ => state.zero.map(|value| !value),
                    };
                    match condition {
                        Some(true) => {
                            pc = target;
                            continue;
                        }
                        Some(false) => {}
                        None => pending.push((target, state.clone())),
                    }
                }
                Code::Jmp_rel8_32 | Code::Jmp_rel32_32 => {
                    pc = i.near_branch32();
                    continue;
                }
                Code::Leaved => {
                    let HelperValue::Stack(frame) = state.registers[5] else {
                        return Err("selection helper: unowned LEAVE frame".into());
                    };
                    if frame < state.sp || frame >= 0 {
                        return Err("selection helper: LEAVE lifetime/protected boundary".into());
                    }
                    let saved = state
                        .words
                        .get(&frame)
                        .cloned()
                        .ok_or("selection helper: missing saved frame")?;
                    state.words.retain(|offset, _| *offset > frame);
                    state.sp = frame + 4;
                    state.registers[5] = saved;
                }
                Code::Retnd => {
                    if state.sp != 0
                        || state.registers[0] != HelperValue::Integer(event_code)
                        || [3, 5, 6, 7]
                            .into_iter()
                            .any(|index| state.registers[index] != HelperValue::Saved(index))
                        || state.words != BTreeMap::from([(4, HelperValue::Integer(event_code))])
                    {
                        return Err("selection helper: return identity/ABI/ownership".into());
                    }
                    returns += 1;
                    break;
                }
                _ => return Err("selection helper: unproved reachable instruction effect".into()),
            }
            pc = i.next_ip32();
        }
    }
    if returns == 0 {
        return Err("selection helper: no proved return".into());
    }
    Ok(CodeIdentity {
        body: format!(
            "if code!={event_code}u32{{return Err(\"original code-transform domain\");}} Ok(code)\n"
        ),
        returns,
        temporary_bytes,
        globals: initialized_globals.iter().copied().collect(),
    })
}

#[derive(Clone, Debug)]
struct Row {
    parent: i32,
    filter: u32,
    target: u32,
}
pub struct ScopeTable {
    rows: Vec<Row>,
    header: [i32; 4],
}
impl ScopeTable {
    pub fn cookie_header(&self) -> [i32; 4] {
        self.header
    }
}
/// Parse actual EH4 rows (four-word cookie header then parent/filter/handler
/// triples). Header cookie effects remain a separate original prolog proof.
/// Executable targets must be independently bound to the retained image.
pub fn parse_eh4(bytes: &[u8], executable_targets: &BTreeSet<u32>) -> Result<ScopeTable, String> {
    if bytes.len() < 28 || !(bytes.len() - 16).is_multiple_of(12) || bytes.len() > 16 + 32 * 12 {
        return Err("selection: EH4 table extent".into());
    }
    let read = |at| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let header = std::array::from_fn(|i| read(i * 4) as i32);
    let rows: Vec<_> = (16..bytes.len())
        .step_by(12)
        .map(|at| Row {
            parent: read(at) as i32,
            filter: read(at + 4),
            target: read(at + 8),
        })
        .collect();
    for row in &rows {
        if (row.parent != -2 && (row.parent < 0 || row.parent as usize >= rows.len()))
            || row.target == 0
            || !executable_targets.contains(&row.target)
            || (row.filter != 0 && !executable_targets.contains(&row.filter))
        {
            return Err("selection: unbound EH4 row".into());
        }
    }
    for start in 0..rows.len() {
        let mut at = start as i32;
        let mut seen = BTreeSet::new();
        while at != -2 {
            if !seen.insert(at) {
                return Err("selection: cyclic EH4 chain".into());
            }
            at = rows[at as usize].parent;
        }
    }
    Ok(ScopeTable { rows, header })
}
pub struct FrameSelection<'a> {
    pub table: &'a ScopeTable,
    pub try_level: i32,
    pub layout: &'a FilterLayout,
}
pub struct OriginalFilter<'a> {
    pub origin: u32,
    pub bytes: &'a [u8],
}
pub struct FilterStep {
    pub frame: usize,
    pub scope: i32,
    pub proof: FilterProof,
}
pub struct Selection {
    frame: usize,
    scope: i32,
    target: u32,
    cleanups: Vec<(usize, i32, u32)>,
    filters: Vec<FilterStep>,
}
impl Selection {
    pub fn selected_frame(&self) -> usize {
        self.frame
    }
    pub fn selected_scope(&self) -> i32 {
        self.scope
    }
    pub fn target(&self) -> u32 {
        self.target
    }
    pub fn cleanups(&self) -> &[(usize, i32, u32)] {
        &self.cleanups
    }
    pub fn filters(&self) -> &[FilterStep] {
        &self.filters
    }
}
/// Derived language-filter selection. Frames are ordered outermost to innermost.
/// This does not establish registration-chain ownership, cookie integrity or code
/// transformation effects; composition must close those before emission.
pub fn select_frames(
    frames: &[FrameSelection<'_>],
    filters: &BTreeMap<u32, OriginalFilter<'_>>,
    event_code: u32,
) -> Result<Selection, String> {
    if frames.is_empty() || frames.len() > 8 {
        return Err("selection: frame budget".into());
    }
    let mut cleanup = Vec::new();
    let mut executed = Vec::new();
    let mut count = 0;
    for (frame, input) in frames.iter().enumerate().rev() {
        let mut at = input.try_level;
        if at != -2 && (at < 0 || at as usize >= input.table.rows.len()) {
            return Err("selection: invalid derived TryLevel".into());
        }
        while at != -2 {
            count += 1;
            if count > 128 {
                return Err("selection: scope budget".into());
            }
            let row = &input.table.rows[at as usize];
            if row.filter == 0 {
                cleanup.push((frame, at, row.target));
            } else {
                // These are original EH4 frame metadata, not arbitrary filter
                // temporaries: registration, saved ESP, and header-named guards.
                // Full cookie validation remains the parent's prolog obligation.
                if input.layout.writable_words.iter().any(|offset| {
                    *offset >= -24
                        || input
                            .table
                            .header
                            .iter()
                            .any(|guard| *guard != -2 && guard == offset)
                }) {
                    return Err("selection: temporary aliases EH4 frame metadata".into());
                }
                let original = filters
                    .get(&row.filter)
                    .ok_or("selection: missing original filter")?;
                if original.origin != row.filter {
                    return Err("selection: filter target provenance".into());
                }
                let proof =
                    prove_filter(original.bytes, original.origin, input.layout, event_code)?;
                let result = proof.result();
                executed.push(FilterStep {
                    frame,
                    scope: at,
                    proof,
                });
                if result < 0 {
                    return Err("selection: unproved ContinueExecution filter result".into());
                }
                if result > 0 {
                    return Ok(Selection {
                        frame,
                        scope: at,
                        target: row.target,
                        cleanups: cleanup,
                        filters: executed,
                    });
                }
            }
            at = row.parent;
        }
    }
    Err("selection: uncontained search reaches borrowed root".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn layout() -> FilterLayout {
        FilterLayout {
            start: -800,
            end: -16,
            exception_pointers_offset: -20,
            writable_words: vec![-776, -780],
        }
    }
    fn body() -> Vec<u8> {
        vec![
            0x8b, 0x55, 0xec, 0x8b, 2, 0x8b, 8, 0x89, 0x8d, 0xf8, 0xfc, 0xff, 0xff, 0x8b, 0x95,
            0xf8, 0xfc, 0xff, 0xff, 0x89, 0x95, 0xf4, 0xfc, 0xff, 0xff, 0x33, 0xc0, 0x81, 0xbd,
            0xf4, 0xfc, 0xff, 0xff, 0x42, 0x42, 0x42, 0xe0, 0x0f, 0x94, 0xc0, 0xc3,
        ]
    }
    fn table(rows: &[(i32, u32, u32)]) -> ScopeTable {
        let mut bytes = vec![0; 16];
        for &(parent, filter, target) in rows {
            bytes.extend(parent.to_le_bytes());
            bytes.extend(filter.to_le_bytes());
            bytes.extend(target.to_le_bytes());
        }
        let addresses = rows
            .iter()
            .flat_map(|&(_, f, h)| [f, h])
            .filter(|&p| p != 0)
            .collect();
        parse_eh4(&bytes, &addresses).unwrap()
    }
    #[test]
    fn original_filter_preserves_temporary_stores_and_derives_language_result() {
        let a = prove_filter(&body(), 0x1333, &layout(), 0xe0424242).unwrap();
        assert_eq!(a.result(), 1);
        assert!(a.body().contains("words[0]=Some("));
        assert!(a.body().contains("words[1]=Some("));
        assert_eq!(
            a.body(),
            prove_filter(&body(), 0x1333, &layout(), 0xe0424242)
                .unwrap()
                .body()
        );
        assert_eq!(
            prove_filter(&body(), 0x1333, &layout(), 0xe0424243)
                .unwrap()
                .result(),
            0
        );
    }
    #[test]
    fn pointer_graph_initialization_aliases_and_flag_provenance_reject() {
        for (index, value) in [(2, 0xe8), (4, 0x42), (6, 0x48), (9, 0xec), (26, 0xc9)] {
            let mut bytes = body();
            bytes[index] = value;
            assert!(prove_filter(&bytes, 0x1333, &layout(), 0xe0424242).is_err());
        }
        let mut missing = body();
        missing.drain(7..13);
        assert!(prove_filter(&missing, 0x1333, &layout(), 0xe0424242).is_err());
        let mut alias = layout();
        alias.writable_words.push(-20);
        assert!(prove_filter(&body(), 0x1333, &alias, 0xe0424242).is_err());
        for end in 0..body().len() {
            assert!(prove_filter(&body()[..end], 0x1333, &layout(), 0xe0424242).is_err());
        }
    }
    #[test]
    fn selected_frame_comes_from_original_filter_not_custom_cursor() {
        let outer = table(&[(-2, 0x1333, 0x135c)]);
        let inner = table(&[(-2, 0, 0x117f), (0, 0, 0x116e)]);
        let l = layout();
        let code = body();
        let filters = BTreeMap::from([(
            0x1333,
            OriginalFilter {
                origin: 0x1333,
                bytes: &code,
            },
        )]);
        let frames = [
            FrameSelection {
                table: &outer,
                try_level: 0,
                layout: &l,
            },
            FrameSelection {
                table: &inner,
                try_level: 1,
                layout: &l,
            },
        ];
        let selection = select_frames(&frames, &filters, 0xe0424242).unwrap();
        assert_eq!(selection.selected_frame(), 0);
        assert_eq!(selection.selected_scope(), 0);
        assert_eq!(selection.target(), 0x135c);
        assert_eq!(selection.cleanups(), &[(1, 1, 0x116e), (1, 0, 0x117f)]);
        assert_eq!(selection.filters().len(), 1);
        assert!(select_frames(&frames, &filters, 0xe0424243).is_err());
        let wrong = [FrameSelection {
            table: &inner,
            try_level: -1,
            layout: &l,
        }];
        assert!(select_frames(&wrong, &filters, 0xe0424242).is_err());
        // Header-named cookie or XOR words are metadata regardless of which
        // header field names them. A permitted scratch list cannot grant write
        // authority over those words.
        for header_index in 0..4 {
            let mut guarded = table(&[(-2, 0x1333, 0x135c)]);
            guarded.header[header_index] = -776;
            let frames = [FrameSelection {
                table: &guarded,
                try_level: 0,
                layout: &l,
            }];
            assert!(select_frames(&frames, &filters, 0xe0424242).is_err());
        }
    }
    #[test]
    fn eh4_cycles_unbound_callbacks_and_wrong_sentinel_reject() {
        let addresses = BTreeSet::from([0x1000]);
        for parent in [-1i32, 0, 1] {
            let mut b = vec![0; 16];
            b.extend(parent.to_le_bytes());
            b.extend(0u32.to_le_bytes());
            b.extend(0x1000u32.to_le_bytes());
            assert!(parse_eh4(&b, &addresses).is_err());
        }
        let mut b = vec![0; 16];
        b.extend((-2i32).to_le_bytes());
        b.extend(0x2000u32.to_le_bytes());
        b.extend(0x1000u32.to_le_bytes());
        assert!(parse_eh4(&b, &addresses).is_err());
    }

    // Independently assembled instruction-contract case. A readable global
    // enables two paths; special input codes would reach an unsupported MXCSR
    // effect. No Windows runtime source or fixture bytes are imported here.
    fn identity_helper() -> Vec<u8> {
        vec![
            0x55, 0x89, 0xe5, 0x51, 0x83, 0x3d, 0x00, 0x20, 0x00, 0x00, 0x01, 0x8b, 0x4d, 0x08,
            0x7c, 0x14, 0x81, 0xf9, 0xb4, 0x02, 0x00, 0xc0, 0x74, 0x08, 0x81, 0xf9, 0xb5, 0x02,
            0x00, 0xc0, 0x75, 0x04, 0x0f, 0xae, 0x5d, 0xfc, 0x8b, 0xc1, 0xc9, 0xc3,
        ]
    }

    #[test]
    fn original_code_identity_explores_both_unknown_guard_outcomes() {
        let globals = BTreeSet::from([0x2000]);
        for event in [0, 0xe0424242, 0xc00002b3, 0xc00002b6, u32::MAX] {
            let proof = prove_code_identity(&identity_helper(), 0x1000, &globals, event).unwrap();
            assert_eq!(proof.proved_return_paths(), 2);
            assert!(proof.body().ends_with("Ok(code)\n"));
        }
        for event in [0xc00002b4, 0xc00002b5] {
            assert!(prove_code_identity(&identity_helper(), 0x1000, &globals, event).is_err());
        }
        assert!(prove_code_identity(&identity_helper(), 0x1000, &BTreeSet::new(), 0).is_err());
    }

    #[test]
    fn code_identity_rejects_changed_effects_stack_targets_and_unproved_paths() {
        let globals = BTreeSet::from([0x2000]);
        for (index, replacement) in [
            (13, 4),    // Reads the protected return instead of the original argument.
            (15, 21),   // Branch enters the middle of MOV.
            (15, 254),  // Self-cycle.
            (37, 0xc2), // EAX copied from unknown EDX, not known code.
            (38, 0x90), // Frame teardown omitted.
            (39, 0xcb), // Far return has different stack/control behavior.
            (1, 0x88),  // Partial-width MOV.
        ] {
            let mut code = identity_helper();
            code[index] = replacement;
            assert!(
                prove_code_identity(&code, 0x1000, &globals, 0xe0424242).is_err(),
                "mutation {index}"
            );
        }
        // The second branch can no longer avoid the MXCSR effect, even though
        // the global's other outcome still reaches a valid identity return.
        let mut code = identity_helper();
        code[30] = 0x74;
        assert!(prove_code_identity(&code, 0x1000, &globals, 0xe0424242).is_err());
        // Shortening at a complete intermediate RET is not enough: the first
        // global branch would leave the proven code range.
        let mut code = identity_helper();
        code[32] = 0xc3;
        code.truncate(33);
        assert!(prove_code_identity(&code, 0x1000, &globals, 0xe0424242).is_err());
    }

    #[test]
    fn emitted_filter_executes_original_scalar_and_temporary_effects() {
        let mut source = String::new();
        let codes = [0xe0424242u32, 0xe0424243, 0, 0xffff_ffff];
        for (index, code) in codes.into_iter().enumerate() {
            let proof = prove_filter(&body(), 0x1333, &layout(), code).unwrap();
            source.push_str(&format!("fn filter_{index}(code:u32,words:&mut[Option<u32>])->Result<i32,&'static str>{{ {} }}\n",proof.body()));
        }
        // Equivalent instruction contract with different pointer registers.
        let mut alternative = body();
        alternative[..7].copy_from_slice(&[0x8b, 0x4d, 0xec, 0x8b, 0x11, 0x8b, 0x0a]);
        let proof = prove_filter(&alternative, 0x2000, &layout(), 0xe0424242).unwrap();
        source.push_str(&format!(
            "fn permuted(code:u32,words:&mut[Option<u32>])->Result<i32,&'static str>{{ {} }}\n",
            proof.body()
        ));
        let identity = prove_code_identity(
            &identity_helper(),
            0x1000,
            &BTreeSet::from([0x2000]),
            0xe0424242,
        )
        .unwrap();
        source.push_str(&format!(
            "fn identity(code:u32)->Result<u32,&'static str>{{ {} }}\n",
            identity.body()
        ));
        source.push_str("fn main(){\n");
        for (index, code) in codes.into_iter().enumerate() {
            let expected = i32::from(code == 0xe0424242);
            source.push_str(&format!("let mut w=[None,None];assert_eq!(filter_{index}({code},&mut w),Ok({expected}));assert_eq!(w,[Some({code}),Some({code})]);let mut wrong=[None,None];assert!(filter_{index}({},&mut wrong).is_err());assert_eq!(wrong,[None,None]);\n",code.wrapping_add(1)));
        }
        source.push_str("let mut w=[None,None];assert_eq!(permuted(0xe0424242,&mut w),Ok(1));assert_eq!(w,[Some(0xe0424242),Some(0xe0424242)]);assert_eq!(identity(0xe0424242),Ok(0xe0424242));assert!(identity(0xc00002b4).is_err());}\n");
        let directory =
            std::env::temp_dir().join(format!("w2l-selection-native-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("filter.rs");
        let binary = directory.join(if cfg!(windows) {
            "filter.exe"
        } else {
            "filter"
        });
        std::fs::write(&file, source).unwrap();
        let result = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(&file)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(std::process::Command::new(&binary)
            .status()
            .unwrap()
            .success());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
