//! Instruction-derived local-unwind helpers. These proofs describe original
//! control flow and typed effects; they do not provide Windows dispatch, cookie
//! checking, notification, or nested-unwind semantics by themselves.
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Body,
    Wrapper,
    NestedHandler,
}
#[derive(Clone, Copy)]
pub(crate) struct Bindings {
    pub body: u32,
    pub nested_handler: u32,
    pub cookie: u32,
    pub notify: u32,
    pub invoke: u32,
    pub check_cookie: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Effect {
    InstallTemporary,
    RestorePreviousHead,
    DecodeScope,
    ReadTryLevel,
    ReadScopeRow,
    WriteTryLevel,
    Notify,
    InvokeFinally,
    LocalUnwind,
    CheckTemporaryCookie,
    ReenterLocalUnwind,
    WriteCollidedRecord,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EffectSite {
    pub instruction: u32,
    pub effect: Effect,
    pub target: Option<u32>,
    /// Below this helper's entry ESP, including a CALL return where applicable.
    pub entry_depth: u32,
}
pub(crate) struct Proof {
    pub source: String,
    pub effects: Vec<EffectSite>,
    pub temporary_bytes: u32,
    pub callee_pop_bytes: u32,
    pub kind: Kind,
    /// A representative flags value requires proof of this original predicate;
    /// unknown unobserved bits are not claimed to be zero.
    pub exception_flag_mask: Option<u32>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ScopeRow {
    pub parent: i32,
    pub filter: u32,
    pub handler: u32,
}
pub(crate) struct ScopeGraph {
    rows: Vec<ScopeRow>,
}
impl ScopeGraph {
    pub fn rows(&self) -> &[ScopeRow] {
        &self.rows
    }
}
/// Complete original EH4 scope-data gate. Image provenance, cookie decoding and
/// readonly lifetime and a live initial TryLevel naming one of these rows or
/// sentinel -2 are additional integration obligations, not inferred here.
/// Callback proof must forbid arbitrary writes to this graph or the TryLevel;
/// nested unwind may only advance through this same finite ancestor relation.
pub(crate) fn prove_scope_graph(
    bytes: &[u8],
    executable: &BTreeSet<u32>,
) -> Result<ScopeGraph, String> {
    if bytes.len() < 28 || !(bytes.len() - 16).is_multiple_of(12) || bytes.len() > 16 + 32 * 12 {
        return Err("local unwind: scope extent/budget".into());
    }
    let rows: Vec<_> = bytes[16..]
        .as_chunks::<12>()
        .0
        .iter()
        .map(|r| ScopeRow {
            parent: i32::from_le_bytes(r[..4].try_into().unwrap()),
            filter: u32::from_le_bytes(r[4..8].try_into().unwrap()),
            handler: u32::from_le_bytes(r[8..12].try_into().unwrap()),
        })
        .collect();
    for r in &rows {
        if (r.parent != -2 && (r.parent < 0 || r.parent as usize >= rows.len()))
            || !executable.contains(&r.handler)
            || (r.filter != 0 && !executable.contains(&r.filter))
        {
            return Err("local unwind: unbound scope target/parent".into());
        }
    }
    for first in 0..rows.len() {
        let mut at = first as i32;
        let mut seen = BTreeSet::new();
        while at != -2 {
            if !seen.insert(at) {
                return Err("local unwind: cyclic parent relation".into());
            }
            at = rows[at as usize].parent;
        }
    }
    Ok(ScopeGraph { rows })
}
/// The actual PUSH sequence derives these offsets. Typed record authority still
/// belongs to ThreadRegistry, and must remain live across every called effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TemporaryLayout {
    pub below_entry: u32,
    pub predecessor: u32,
    pub handler: u32,
    pub guard: u32,
    pub target: u32,
    pub establisher: u32,
    pub cookie_address: u32,
    pub owner_ebp: u32,
}
pub(crate) const TEMPORARY_LAYOUT: TemporaryLayout = TemporaryLayout {
    below_entry: 40,
    predecessor: 0,
    handler: 4,
    guard: 8,
    target: 12,
    establisher: 16,
    cookie_address: 20,
    owner_ebp: 24,
};

/// Required private integration surface for generated native blocks. Each method
/// is an original effect at its emitted instruction, not a manufactured cleanup
/// schedule. Implementations must bind owner/record/table identity, full ranges,
/// initialized values, readonly scope data, and validated callback code. A
/// failing effect keeps preceding original writes and the installed temporary
/// head; it must not be converted into normal return or automatic unlink.
///
/// In particular CheckTemporaryCookie must preserve the original EAX record
/// capability; ReenterLocalUnwind and WriteCollidedRecord are mandatory on the
/// original flags&6 edge. No samples or `cannot happen` flag substitute for them.
pub(crate) const EMITTED_TYPES: &str = r#"
#[derive(Clone,Copy)]
struct LocalScope { parent:i32, filter:u32, handler:u32 }
trait LocalUnwindEffects {
 fn install_temporary(&mut self,below_entry:u32,nested_handler:u32)->Result<(),&'static str>;
 fn restore_previous_head(&mut self)->Result<(),&'static str>;
 fn decode_scope(&mut self)->Result<(),&'static str>;
 fn read_try_level(&mut self)->Result<i32,&'static str>;
 fn scope_row(&mut self,level:i32)->Result<LocalScope,&'static str>;
 fn write_try_level(&mut self,parent:i32)->Result<(),&'static str>;
 fn notify(&mut self,handler:u32,reason:u32)->Result<(),&'static str>;
 fn invoke_finally(&mut self,handler:u32,abnormal:u32)->Result<(),&'static str>;
 fn local_unwind(&mut self,target:i32)->Result<(),&'static str>;
 fn check_temporary_cookie(&mut self)->Result<(),&'static str>;
 fn reenter_local_unwind(&mut self)->Result<(),&'static str>;
 fn write_collided_record(&mut self)->Result<(),&'static str>;
}
"#;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum V {
    Unknown,
    Saved(u8),
    Stack(i32),
    Return,
    Owner,
    CookieAddress,
    Cookie,
    Establisher,
    Target,
    EncodedScope,
    Table,
    Level,
    ScaledLevel,
    Row,
    Parent,
    Filter,
    Handler,
    Head,
    NestedHandler,
    Guard(i32),
    Exception,
    ExceptionFlags,
    Context,
    Temporary,
    TemporaryGuard,
    Dispatcher,
    Constant(u32),
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Flags {
    Compare(V, V),
    Test(V, u32),
}
// A row transition is admitted only after the original sentinel/target
// predicates. Phase edges preserve their immutable current-iteration identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Route {
    BeforeInstall,
    Start,
    Nonterminal,
    TargetBounded,
    Visit,
    RowLoaded,
    ParentStored,
    FilterZero,
    SkipFinally,
    Notified,
    Invoked,
    Exit,
    NestedSearch,
    NestedUnwind,
    NestedGuarded,
    NestedCalled,
    NestedRecorded,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct State {
    regs: [V; 8],
    stack: BTreeMap<i32, V>,
    sp: i32,
    flags: Option<Flags>,
    installed: bool,
    restored: bool,
    called: bool,
    iteration_wrote: bool,
    route: Route,
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
        _ => Err("local unwind: register width".into()),
    }
}
fn immediate(i: &Instruction, operand: u32) -> Result<u32, String> {
    Ok(match i.op_kind(operand) {
        OpKind::Immediate32 => i.immediate32(),
        OpKind::Immediate8to32 => i.immediate8to32() as u32,
        _ => return Err("local unwind: immediate width".into()),
    })
}
fn number(v: &V) -> bool {
    scalar(v) || matches!(v, V::ScaledLevel)
}
fn runtime_read(s: &State, i: &Instruction, operand: u32, b: &Bindings) -> Result<String, String> {
    let value = s.read(i, operand, b)?;
    if !number(&value) {
        return Err("local unwind: nonnumeric runtime read".into());
    }
    if i.op_kind(operand) == OpKind::Register {
        return Ok(format!("r[{}]", reg(i.op_register(operand))?));
    }
    if matches!(
        i.op_kind(operand),
        OpKind::Immediate32 | OpKind::Immediate8to32
    ) {
        return Ok(format!("{}u32", immediate(i, operand)?));
    }
    let (base, offset) = s.address(i)?;
    Ok(match (base, offset) {
        (V::Stack(base), off) => format!(
            "*stack_values.get(&{}i32).ok_or(\"local scalar stack snapshot\")?",
            base.checked_add(off)
                .ok_or("local stack expression overflow")?
        ),
        (V::Establisher, 12) => "effects.read_try_level()? as u32".into(),
        (V::Row, off) => {
            let register = reg(i.memory_base())?;
            let field = match off {
                0 => "parent as u32",
                4 => "filter",
                8 => "handler",
                _ => return Err("local scope field".into()),
            };
            format!("row_values[{register}].ok_or(\"local scope snapshot\")?.{field}")
        }
        (V::Exception, 4) => "exception_flags".into(),
        (V::Temporary, 12) => "target_level as u32".into(),
        _ => return Err("local unwind: runtime scalar source".into()),
    })
}
fn scalar(v: &V) -> bool {
    matches!(
        v,
        V::Level
            | V::Target
            | V::Parent
            | V::Filter
            | V::Handler
            | V::ExceptionFlags
            | V::Constant(_)
    )
}
impl State {
    fn new(kind: Kind) -> Self {
        let mut regs = std::array::from_fn(|n| V::Saved(n as u8));
        regs[4] = V::Stack(0);
        let mut stack = BTreeMap::from([(0, V::Return)]);
        match kind {
            Kind::Body => {
                regs[5] = V::Owner;
                stack.extend([(4, V::CookieAddress), (8, V::Establisher), (12, V::Target)]);
            }
            Kind::Wrapper => {
                regs[1] = V::Establisher;
                regs[2] = V::Target;
                stack.extend([(4, V::Owner), (8, V::CookieAddress)]);
            }
            Kind::NestedHandler => {
                stack.extend([
                    (4, V::Exception),
                    (8, V::Temporary),
                    (12, V::Context),
                    (16, V::Dispatcher),
                ]);
            }
        }
        Self {
            regs,
            stack,
            sp: 0,
            flags: None,
            installed: false,
            restored: false,
            called: false,
            iteration_wrote: false,
            route: Route::BeforeInstall,
        }
    }
    fn address(&self, i: &Instruction) -> Result<(V, i32), String> {
        if i.memory_index() != Register::None {
            return Err("local unwind: indexed memory outside LEA".into());
        }
        let base = if i.memory_base() == Register::None {
            V::Constant(0)
        } else {
            self.regs[reg(i.memory_base())?].clone()
        };
        Ok((base, i.memory_displacement32() as i32))
    }
    fn read(&self, i: &Instruction, operand: u32, b: &Bindings) -> Result<V, String> {
        if i.op_kind(operand) == OpKind::Register {
            return Ok(self.regs[reg(i.op_register(operand))?].clone());
        }
        if matches!(
            i.op_kind(operand),
            OpKind::Immediate32 | OpKind::Immediate8to32
        ) {
            let n = immediate(i, operand)?;
            return Ok(if n == b.nested_handler {
                V::NestedHandler
            } else {
                V::Constant(n)
            });
        }
        if i.op_kind(operand) != OpKind::Memory {
            return Err("local unwind: unsupported read".into());
        }
        let (base, offset) = self.address(i)?;
        if i.segment_prefix() == Register::FS {
            return if base == V::Constant(0) && offset == 0 {
                Ok(V::Head)
            } else {
                Err("local unwind: FS range".into())
            };
        }
        Ok(match (base, offset) {
            (V::Stack(base), off) => self
                .stack
                .get(
                    &base
                        .checked_add(off)
                        .ok_or("local unwind: stack overflow")?,
                )
                .cloned()
                .ok_or("local unwind: unknown stack word")?,
            (V::Constant(0), va) if va as u32 == b.cookie => V::Cookie,
            (V::CookieAddress, 0) => V::Cookie,
            (V::Establisher, 8) => V::EncodedScope,
            (V::Establisher, 12) => V::Level,
            (V::Row, 0) => V::Parent,
            (V::Row, 4) => V::Filter,
            (V::Row, 8) => V::Handler,
            (V::Exception, 4) => V::ExceptionFlags,
            (V::Temporary, 8) => V::TemporaryGuard,
            (V::Temporary, 12) => V::Target,
            (V::Temporary, 16) => V::Establisher,
            (V::Temporary, 20) => V::CookieAddress,
            (V::Temporary, 24) => V::Owner,
            _ => return Err("local unwind: unowned or incomplete word read".into()),
        })
    }
    fn push(&mut self, value: V) -> Result<(), String> {
        if matches!(value, V::Unknown | V::Return | V::Row) {
            return Err("local unwind: unknown/protected or row-pointer push".into());
        }
        self.sp = self
            .sp
            .checked_sub(4)
            .ok_or("local unwind: push overflow")?;
        if self.sp < -256 || self.stack.insert(self.sp, value).is_some() {
            return Err("local unwind: push alias/budget".into());
        }
        self.regs[4] = V::Stack(self.sp);
        Ok(())
    }
    fn pop(&mut self) -> Result<V, String> {
        if self.sp >= 0 || self.installed && self.sp >= -40 {
            return Err("local unwind: protected pop".into());
        }
        let v = self
            .stack
            .remove(&self.sp)
            .ok_or("local unwind: absent stack word")?;
        self.sp += 4;
        self.regs[4] = V::Stack(self.sp);
        Ok(v)
    }
    fn discard(&mut self, bytes: u32) -> Result<(), String> {
        if !bytes.is_multiple_of(4) || bytes > 256 {
            return Err("local unwind: cleanup width/budget".into());
        }
        for _ in 0..bytes / 4 {
            self.pop()?;
        }
        Ok(())
    }
}

/// All reachable typed CFG states are checked, including both sides of unknown
/// conditions. Loop states converge on tags; the emitter retains original runtime
/// branches and reads. No initial TryLevel or preselected cleanup list is input.
/// The emitted body signature is `(effects:&mut impl LocalUnwindEffects,
/// target_level:i32,exception_flags:u32)->Result<Option<i32>,&'static str>`.
/// Body/Wrapper return no claimed EAX value; NestedHandler returns original1/3.
pub(crate) fn prove(code: &[u8], origin: u32, kind: Kind, b: &Bindings) -> Result<Proof, String> {
    if code.is_empty()
        || code.len() > 512
        || origin == 0
        || origin.checked_add(code.len() as u32).is_none()
        || [
            b.body,
            b.nested_handler,
            b.cookie,
            b.notify,
            b.invoke,
            b.check_cookie,
        ]
        .contains(&0)
    {
        return Err("local unwind: extent/bindings".into());
    }
    let mut decoder = Decoder::with_ip(32, code, origin as u64, DecoderOptions::NONE);
    let mut instructions = BTreeMap::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        if i.is_invalid() || instructions.len() >= 128 {
            return Err("local unwind: malformed code/budget".into());
        }
        instructions.insert(i.ip32(), i);
    }
    let mut todo = VecDeque::from([(origin, State::new(kind))]);
    let mut seen = BTreeSet::new();
    let mut blocks = BTreeMap::<u32, String>::new();
    let mut effect_sites = BTreeMap::<u32, EffectSite>::new();
    let mut temporary = 0;
    let mut returns = 0;
    let mut pop_bytes = None;
    let mut loop_entry = None;
    while let Some((pc, mut s)) = todo.pop_front() {
        if Some(pc) == loop_entry {
            s.iteration_wrote = false;
            s.route = Route::Start;
            // A previous iteration (or pre-install read) cannot authorize this
            // iteration's scope-row access or progress proof.
            for value in s.regs.iter_mut().chain(s.stack.values_mut()) {
                if matches!(
                    value,
                    V::Level | V::ScaledLevel | V::Row | V::Parent | V::Filter | V::Handler
                ) {
                    *value = V::Unknown;
                }
            }
        }
        if !seen.insert((pc, s.clone())) {
            continue;
        }
        if seen.len() > 2048 {
            return Err("local unwind: typed state budget".into());
        }
        let i = instructions
            .get(&pc)
            .ok_or("local unwind: target not instruction boundary")?;
        if i.has_lock_prefix()
            || i.has_rep_prefix()
            || i.has_repne_prefix()
            || !matches!(i.segment_prefix(), Register::None | Register::FS)
        {
            return Err("local unwind: instruction prefixes".into());
        }
        let next = i.next_ip32();
        let mut emitted = String::new();
        let mut successors = vec![next];
        let mut branch_states: Option<Vec<(u32, State)>> = None;
        let mut effect = None;
        match i.code() {
            Code::Push_r32 | Code::Pushd_imm32 | Code::Pushd_imm8 | Code::Push_rm32 => {
                let value = s.read(i, 0, b)?;
                let snapshot = if number(&value) {
                    Some(runtime_read(&s, i, 0, b)?)
                } else {
                    None
                };
                s.push(value)?;
                if let Some(snapshot) = snapshot {
                    emitted.push_str(&format!(
                        "let value={snapshot};stack_values.insert({}i32,value);\n",
                        s.sp
                    ));
                }
            }
            Code::Pop_r32 => {
                let index = reg(i.op0_register())?;
                if index == 4 {
                    return Err("local unwind: POP ESP".into());
                }
                let old_sp = s.sp;
                let value = s.pop()?;
                if number(&value) {
                    emitted.push_str(&format!("r[{index}]=*stack_values.get(&{old_sp}i32).ok_or(\"local POP snapshot\")?;\n"));
                }
                emitted.push_str(&format!("stack_values.remove(&{old_sp}i32);\n"));
                s.regs[index] = value;
            }
            Code::Pop_rm32 if i.segment_prefix() == Register::FS => {
                if s.address(i)? != (V::Constant(0), 0)
                    || !s.installed
                    || s.restored
                    || s.sp != -40
                    || s.route != Route::Exit
                    || s.stack.get(&s.sp) != Some(&V::Head)
                {
                    return Err("local unwind: original FS teardown ownership".into());
                }
                s.restored = true;
                s.installed = false;
                s.pop()?;
                emitted.push_str("effects.restore_previous_head()?;\n");
                effect = Some((Effect::RestorePreviousHead, None));
            }
            Code::Mov_r32_rm32
            | Code::Mov_rm32_r32
            | Code::Mov_r32_imm32
            | Code::Mov_EAX_moffs32 => {
                let v = s.read(i, 1, b)?;
                if v == V::Unknown || v == V::Return {
                    return Err("local unwind: unknown/protected MOV".into());
                }
                if i.op0_kind() == OpKind::Register {
                    let index = reg(i.op0_register())?;
                    if index == 4 {
                        return Err("local unwind: unsupported ESP assignment".into());
                    }
                    if number(&v) {
                        emitted.push_str(&format!("r[{index}]={};\n", runtime_read(&s, i, 1, b)?));
                    }
                    if v == V::Row {
                        if i.op1_kind() != OpKind::Register {
                            return Err("local unwind: row pointer snapshot".into());
                        }
                        emitted.push_str(&format!(
                            "row_values[{index}]=row_values[{}];\n",
                            reg(i.op1_register())?
                        ));
                    }
                    if v == V::Level
                        && i.op1_kind() == OpKind::Memory
                        && s.address(i)? == (V::Establisher, 12)
                    {
                        if kind == Kind::Body
                            && !matches!(
                                s.route,
                                Route::Start
                                    | Route::Nonterminal
                                    | Route::TargetBounded
                                    | Route::Visit
                            )
                        {
                            return Err("local unwind: stale or changed level epoch".into());
                        }
                        effect = Some((Effect::ReadTryLevel, None));
                    }
                    s.regs[index] = v;
                } else if i.op0_kind() == OpKind::Memory {
                    let (base, offset) = s.address(i)?;
                    if i.segment_prefix() == Register::FS {
                        if kind != Kind::Body
                            || base != V::Constant(0)
                            || offset != 0
                            || v != V::Stack(s.sp)
                            || s.sp != -40
                            || s.installed
                            || s.restored
                        {
                            return Err("local unwind: FS installation identity".into());
                        }
                        let expected = [
                            V::Head,
                            V::NestedHandler,
                            V::Guard(-40),
                            V::Target,
                            V::Establisher,
                            V::CookieAddress,
                            V::Owner,
                        ];
                        for (n, value) in expected.iter().enumerate() {
                            if s.stack.get(&(-40 + n as i32 * 4)) != Some(value) {
                                return Err(
                                    "local unwind: temporary record layout/initialization".into()
                                );
                            }
                        }
                        s.installed = true;
                        if loop_entry.is_some_and(|old| old != next) {
                            return Err("local unwind: ambiguous loop entry".into());
                        }
                        loop_entry = Some(next);
                        emitted.push_str(&format!(
                            "effects.install_temporary(40,{}u32)?;\n",
                            b.nested_handler
                        ));
                        effect = Some((Effect::InstallTemporary, None));
                    } else {
                        match (base, offset, v) {
                            (V::Stack(base), offset, v) => {
                                let at = base
                                    .checked_add(offset)
                                    .ok_or("local unwind: write overflow")?;
                                if at >= 0 || at < s.sp || at % 4 != 0 || !s.stack.contains_key(&at)
                                {
                                    return Err("local unwind: stack write bounds".into());
                                }
                                if at != -32
                                    || v != V::Guard(-40)
                                    || kind != Kind::Body
                                    || s.installed
                                {
                                    return Err("local unwind: protected record overwrite".into());
                                }
                                s.stack.insert(at, v);
                            }
                            (V::Establisher, 12, V::Parent)
                                if kind == Kind::Body && s.installed =>
                            {
                                if s.iteration_wrote || s.route != Route::RowLoaded {
                                    return Err(
                                        "local unwind: repeated or unbound parent store".into()
                                    );
                                }
                                s.iteration_wrote = true;
                                s.route = Route::ParentStored;
                                emitted.push_str(&format!(
                                    "effects.write_try_level({} as i32)?;\n",
                                    runtime_read(&s, i, 1, b)?
                                ));
                                effect = Some((Effect::WriteTryLevel, None));
                            }
                            (V::Dispatcher, 0, V::Temporary)
                                if kind == Kind::NestedHandler
                                    && s.called
                                    && s.route == Route::NestedCalled =>
                            {
                                s.route = Route::NestedRecorded;
                                emitted.push_str("effects.write_collided_record()?;\n");
                                effect = Some((Effect::WriteCollidedRecord, None));
                            }
                            _ => return Err("local unwind: unproved memory write".into()),
                        }
                    }
                } else {
                    return Err("local unwind: MOV destination".into());
                }
            }
            Code::Xor_r32_rm32 | Code::Xor_rm32_r32 => {
                if i.op0_kind() != OpKind::Register {
                    return Err("local unwind: XOR write".into());
                }
                let index = reg(i.op0_register())?;
                let right = s.read(i, 1, b)?;
                s.regs[index] = match (&s.regs[index], right) {
                    (V::Cookie, V::Stack(at)) if at == s.sp => V::Guard(at),
                    (V::EncodedScope, V::Cookie) => {
                        emitted.push_str("effects.decode_scope()?;\n");
                        effect = Some((Effect::DecodeScope, None));
                        V::Table
                    }
                    (V::TemporaryGuard, V::Temporary) => V::Cookie,
                    _ => return Err("local unwind: XOR provenance".into()),
                };
                s.flags = None;
            }
            Code::Lea_r32_m => {
                if i.segment_prefix() != Register::None {
                    return Err("local unwind: LEA segment".into());
                }
                let dest = reg(i.op0_register())?;
                if dest == 4 {
                    return Err("local unwind: LEA ESP pivot".into());
                }
                let base = s.regs[reg(i.memory_base())?].clone();
                let index = s.regs[reg(i.memory_index())?].clone();
                s.regs[dest] = match (
                    base,
                    index,
                    i.memory_index_scale(),
                    i.memory_displacement32(),
                ) {
                    (V::Level, V::Level, 2, 0) if i.memory_base() == i.memory_index() => {
                        let register = reg(i.memory_base())?;
                        emitted.push_str(&format!("r[{dest}]=r[{register}].checked_mul(3).ok_or(\"local scope index overflow\")?;\n"));
                        V::ScaledLevel
                    }
                    (V::Table, V::ScaledLevel, 4, 16) => {
                        if s.route != Route::Visit {
                            return Err(
                                "local unwind: missing contained-row guards or stale row epoch"
                                    .into(),
                            );
                        }
                        s.route = Route::RowLoaded;
                        let register = reg(i.memory_index())?;
                        emitted.push_str(&format!("if r[{register}]%3!=0{{return Err(\"local scope index\");}}row_values[{dest}]=Some(effects.scope_row((r[{register}]/3) as i32)?);\n"));
                        effect = Some((Effect::ReadScopeRow, None));
                        V::Row
                    }
                    _ => return Err("local unwind: scope address arithmetic".into()),
                };
            }
            Code::Cmp_rm32_imm8
            | Code::Cmp_rm32_imm32
            | Code::Cmp_r32_rm32
            | Code::Cmp_rm32_r32 => {
                let left = s.read(i, 0, b)?;
                let right = s.read(i, 1, b)?;
                if !scalar(&left)
                    || !scalar(&right)
                    || left == V::ExceptionFlags
                    || right == V::ExceptionFlags
                {
                    return Err("local unwind: non-scalar comparison".into());
                }
                emitted.push_str(&format!("let lhs={};let rhs={};comparison_equal=lhs==rhs;comparison_below_equal=lhs<=rhs;\n",runtime_read(&s,i,0,b)?,runtime_read(&s,i,1,b)?));
                s.flags = Some(Flags::Compare(left, right));
            }
            Code::Test_rm32_imm32 => {
                let left = s.read(i, 0, b)?;
                if kind != Kind::NestedHandler || left != V::ExceptionFlags || immediate(i, 1)? != 6
                {
                    return Err("local unwind: flags provenance".into());
                }
                emitted.push_str(&format!(
                    "comparison_equal=({}&6u32)==0;\n",
                    runtime_read(&s, i, 0, b)?
                ));
                s.flags = Some(Flags::Test(left, 6));
            }
            Code::Je_rel8_32
            | Code::Je_rel32_32
            | Code::Jne_rel8_32
            | Code::Jne_rel32_32
            | Code::Jbe_rel8_32
            | Code::Jbe_rel32_32 => {
                let condition = match s
                    .flags
                    .as_ref()
                    .ok_or("local unwind: unknown condition flags")?
                {
                    Flags::Compare(_, _) => match i.mnemonic() {
                        iced_x86::Mnemonic::Je => "comparison_equal",
                        iced_x86::Mnemonic::Jne => "!comparison_equal",
                        _ => "comparison_below_equal",
                    },
                    Flags::Test(_, _) if i.mnemonic() == iced_x86::Mnemonic::Je => {
                        "comparison_equal"
                    }
                    _ => return Err("local unwind: unsupported condition".into()),
                };
                let target = i.near_branch32();
                emitted.push_str(&format!(
                    "pc=if {condition}{{{target}u32}}else{{{next}u32}};continue;\n"
                ));
                successors = vec![next, target];
                if kind == Kind::Body {
                    use iced_x86::Mnemonic;
                    let (taken, fallthrough) = match (s.route, s.flags.as_ref(), i.mnemonic()) {
                        (
                            Route::Start,
                            Some(Flags::Compare(V::Level, V::Constant(0xffff_fffe))),
                            Mnemonic::Je,
                        ) => (Route::Exit, Route::Nonterminal),
                        (
                            Route::Nonterminal,
                            Some(Flags::Compare(V::Target, V::Constant(0xffff_fffe))),
                            Mnemonic::Je,
                        ) => (Route::Visit, Route::TargetBounded),
                        (
                            Route::TargetBounded,
                            Some(Flags::Compare(V::Level, V::Target)),
                            Mnemonic::Jbe,
                        ) => (Route::Exit, Route::Visit),
                        (
                            Route::ParentStored,
                            Some(Flags::Compare(V::Filter, V::Constant(0))),
                            Mnemonic::Jne,
                        ) => (Route::SkipFinally, Route::FilterZero),
                        _ => {
                            return Err(
                                "local unwind: missing original predicate containment".into()
                            )
                        }
                    };
                    let mut yes = s.clone();
                    yes.route = taken;
                    let mut no = s.clone();
                    no.route = fallthrough;
                    branch_states = Some(vec![(next, no), (target, yes)]);
                } else if kind == Kind::NestedHandler {
                    if s.route != Route::BeforeInstall
                        || !matches!(s.flags, Some(Flags::Test(V::ExceptionFlags, 6)))
                        || i.mnemonic() != iced_x86::Mnemonic::Je
                    {
                        return Err("local unwind: nested flags containment".into());
                    }
                    let mut yes = s.clone();
                    yes.route = Route::NestedSearch;
                    let mut no = s.clone();
                    no.route = Route::NestedUnwind;
                    branch_states = Some(vec![(next, no), (target, yes)]);
                }
            }
            Code::Jmp_rel8_32 | Code::Jmp_rel32_32 => {
                let target = i.near_branch32();
                emitted.push_str(&format!("pc={target}u32;continue;\n"));
                successors = vec![target];
            }
            Code::Add_rm32_imm8 | Code::Add_rm32_imm32 if i.op0_register() == Register::ESP => {
                if s.installed && kind == Kind::Body {
                    return Err("local unwind: active record discarded".into());
                }
                let old_sp = s.sp;
                s.discard(immediate(i, 1)?)?;
                emitted.push_str(&format!(
                    "stack_values.retain(|offset,_| !({old_sp}i32..{}i32).contains(offset));\n",
                    s.sp
                ));
                s.flags = None;
            }
            Code::Call_rel32_32 => {
                let target = i.near_branch32();
                let depth =
                    s.sp.unsigned_abs()
                        .checked_add(4)
                        .ok_or("local unwind: call depth")?;
                temporary = temporary.max(depth);
                let effect_kind = if target == b.notify && kind == Kind::Body {
                    if !s.installed
                        || !s.iteration_wrote
                        || s.route != Route::FilterZero
                        || s.regs[0] != V::Handler
                        || s.regs[5] != V::Owner
                        || s.stack.get(&s.sp) != Some(&V::Constant(0x101))
                    {
                        return Err("local unwind: notification argument/owner".into());
                    }
                    s.route = Route::Notified;
                    let arg_sp = s.sp;
                    s.discard(4)?;
                    emitted.push_str(&format!(
                        "effects.notify(r[0],0x101u32)?;stack_values.remove(&{arg_sp}i32);\n"
                    ));
                    Effect::Notify
                } else if target == b.invoke && kind == Kind::Body {
                    if !s.installed
                        || !s.iteration_wrote
                        || s.route != Route::Notified
                        || s.regs[0] != V::Handler
                        || s.regs[1] != V::Constant(1)
                        || s.regs[5] != V::Owner
                    {
                        return Err("local unwind: finally call provenance".into());
                    }
                    s.route = Route::Invoked;
                    emitted.push_str("effects.invoke_finally(r[0],r[1])?;\n");
                    Effect::InvokeFinally
                } else if target == b.body && matches!(kind, Kind::Wrapper | Kind::NestedHandler) {
                    if kind == Kind::Wrapper && s.called {
                        return Err("local unwind: duplicate wrapper body call".into());
                    }
                    for (n, value) in [V::CookieAddress, V::Establisher, V::Target]
                        .iter()
                        .enumerate()
                    {
                        if s.stack.get(&(s.sp + n as i32 * 4)) != Some(value) {
                            return Err("local unwind: recursive argument order".into());
                        }
                    }
                    if s.regs[5] != V::Owner {
                        return Err("local unwind: recursive live owner".into());
                    }
                    if kind == Kind::NestedHandler {
                        if s.route != Route::NestedGuarded {
                            return Err("local unwind: nested reentry lacks guard".into());
                        }
                        s.route = Route::NestedCalled;
                    }
                    s.called = true;
                    if kind == Kind::Wrapper {
                        emitted.push_str(&format!("effects.local_unwind(*stack_values.get(&{}i32).ok_or(\"local target snapshot\")? as i32)?;\n",s.sp+8));
                        Effect::LocalUnwind
                    } else {
                        emitted.push_str("effects.reenter_local_unwind()?;\n");
                        Effect::ReenterLocalUnwind
                    }
                } else if target == b.check_cookie && kind == Kind::NestedHandler {
                    if s.regs[0] != V::Temporary
                        || s.regs[1] != V::Cookie
                        || s.route != Route::NestedUnwind
                    {
                        return Err("local unwind: temporary guard identity".into());
                    }
                    s.route = Route::NestedGuarded;
                    emitted.push_str("effects.check_temporary_cookie()?;\n");
                    Effect::CheckTemporaryCookie
                } else {
                    return Err("local unwind: unbound call effect".into());
                };
                if effect_kind != Effect::CheckTemporaryCookie {
                    for n in [0, 1, 2] {
                        s.regs[n] = V::Unknown;
                    }
                }
                s.flags = None;
                let site = EffectSite {
                    instruction: pc,
                    effect: effect_kind,
                    target: Some(target),
                    entry_depth: depth,
                };
                if effect_sites.get(&pc).is_some_and(|old| old != &site) {
                    return Err("local unwind: ambiguous call frame".into());
                }
                effect_sites.insert(pc, site);
            }
            Code::Retnd | Code::Retnd_imm16 => {
                let pop = if i.code() == Code::Retnd_imm16 {
                    u32::from(i.immediate16())
                } else {
                    0
                };
                let initial = State::new(kind);
                if s.sp != 0
                    || s.stack != initial.stack
                    || [3, 5, 6, 7].iter().any(|&n| s.regs[n] != initial.regs[n])
                    || s.installed
                    || kind == Kind::Body && !s.restored
                    || kind == Kind::Wrapper && !s.called
                    || pop != if kind == Kind::Wrapper { 8 } else { 0 }
                {
                    return Err("local unwind: return ownership/lifetime".into());
                }
                let result = if kind == Kind::NestedHandler {
                    match s.regs[0] {
                        V::Constant(1) if s.route == Route::NestedSearch => "Some(r[0] as i32)",
                        V::Constant(3) if s.called && s.route == Route::NestedRecorded => {
                            "Some(r[0] as i32)"
                        }
                        _ => return Err("local unwind: invalid nested disposition".into()),
                    }
                } else {
                    "None"
                };
                emitted.push_str(&format!("return Ok({result});\n"));
                successors.clear();
                returns += 1;
                pop_bytes = Some(pop);
            }
            _ => {
                return Err(format!(
                    "local unwind: unsupported instruction at {pc:#x}: {:?}",
                    i.code()
                ))
            }
        }
        temporary = temporary.max(s.sp.unsigned_abs());
        if let Some((effect, target)) = effect {
            let site = EffectSite {
                instruction: pc,
                effect,
                target,
                entry_depth: s.sp.unsigned_abs(),
            };
            if effect_sites.get(&pc).is_some_and(|old| old != &site) {
                return Err("local unwind: ambiguous effect site".into());
            }
            effect_sites.insert(pc, site);
        }
        if successors.len() == 1 && !emitted.contains("continue;") {
            emitted.push_str(&format!("pc={next}u32;\n"));
        }
        if blocks.get(&pc).is_some_and(|old| old != &emitted) {
            return Err("local unwind: path-dependent emitted effect".into());
        }
        blocks.insert(pc, emitted);
        let paths = branch_states
            .unwrap_or_else(|| successors.into_iter().map(|pc| (pc, s.clone())).collect());
        for (successor, state) in paths {
            if successor <= pc
                && (kind != Kind::Body
                    || Some(successor) != loop_entry
                    || !state.iteration_wrote
                    || !state.installed
                    || !matches!(state.route, Route::SkipFinally | Route::Invoked))
            {
                return Err("local unwind: unproved cyclic control edge".into());
            }
            if !instructions.contains_key(&successor) {
                return Err("local unwind: successor boundary".into());
            }
            todo.push_back((successor, state));
        }
    }
    if returns == 0 {
        return Err("local unwind: no proved return".into());
    }
    let setup = match kind {
        Kind::Body => "stack_values.insert(12i32,target_level as u32);",
        Kind::Wrapper => "r[2]=target_level as u32;",
        Kind::NestedHandler => "",
    };
    let locals=format!("let mut r=[0u32;8];let mut row_values:[Option<LocalScope>;8]=[None;8];let mut stack_values=std::collections::BTreeMap::<i32,u32>::new();let mut comparison_equal=false;let mut comparison_below_equal=false;{setup}");
    let source=format!("let _=(target_level,exception_flags);let mut pc={origin}u32;{locals}let mut steps=0u32;loop{{steps+=1;if steps>8192{{return Err(\"local unwind runtime budget\");}}match pc{{{} _=>return Err(\"local unwind code boundary\"),}}}}",blocks.iter().map(|(pc,body)|format!("{pc}u32=>{{{body}}},")).collect::<String>());
    Ok(Proof {
        source,
        effects: effect_sites.into_values().collect(),
        temporary_bytes: temporary,
        callee_pop_bytes: pop_bytes.unwrap(),
        kind,
        exception_flag_mask: if kind == Kind::NestedHandler {
            Some(6)
        } else {
            None
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const BODY: u32 = 0x3000;
    const WRAPPER: u32 = 0x4000;
    const NESTED: u32 = 0x5000;
    fn bindings() -> Bindings {
        Bindings {
            body: BODY,
            nested_handler: NESTED,
            cookie: 0x8000,
            notify: 0x9000,
            invoke: 0x9100,
            check_cookie: 0x9200,
        }
    }
    struct Asm {
        origin: u32,
        bytes: Vec<u8>,
        labels: BTreeMap<&'static str, usize>,
        fixes: Vec<(usize, &'static str)>,
    }
    impl Asm {
        fn new(origin: u32) -> Self {
            Self {
                origin,
                bytes: Vec::new(),
                labels: BTreeMap::new(),
                fixes: Vec::new(),
            }
        }
        fn e(&mut self, b: &[u8]) {
            self.bytes.extend(b);
        }
        fn u(&mut self, n: u32) {
            self.bytes.extend(n.to_le_bytes());
        }
        fn label(&mut self, s: &'static str) {
            self.labels.insert(s, self.bytes.len());
        }
        fn j(&mut self, op: &[u8], s: &'static str) {
            self.e(op);
            self.fixes.push((self.bytes.len(), s));
            self.u(0);
        }
        fn call(&mut self, target: u32) {
            self.e(&[0xe8]);
            self.u(target.wrapping_sub(self.origin + self.bytes.len() as u32 + 4));
        }
        fn done(mut self) -> Vec<u8> {
            for (at, name) in self.fixes {
                let end = self.origin + at as u32 + 4;
                let target = self.origin + self.labels[name] as u32;
                self.bytes[at..at + 4].copy_from_slice(&target.wrapping_sub(end).to_le_bytes());
            }
            self.bytes
        }
    }
    // Independently assembled instruction contracts with different locations,
    // branch encodings and call targets from the retained compiler PE.
    fn body() -> Vec<u8> {
        body_variant(0)
    }
    fn body_variant(variant: u8) -> Vec<u8> {
        let b = bindings();
        let mut a = Asm::new(BODY);
        a.e(&[
            0x53, 0x56, 0x57, 0x8b, 0x54, 0x24, 16, 0x8b, 0x44, 0x24, 20, 0x8b, 0x4c, 0x24, 24,
        ]);
        if variant == 2 {
            a.e(&[0x8b, 0x78, 12]);
        } // pre-install stale TryLevel in EDI
        a.e(&[0x55, 0x52, 0x50, 0x51, 0x51, 0x68]);
        a.u(b.nested_handler);
        a.e(&[0x64, 0xff, 0x35, 0, 0, 0, 0, 0xa1]);
        a.u(b.cookie);
        a.e(&[
            0x33, 0xc4, 0x89, 0x44, 0x24, 8, 0x64, 0x89, 0x25, 0, 0, 0, 0,
        ]);
        a.label("loop");
        a.e(&[
            0x8b, 0x44, 0x24, 48, 0x8b, 0x58, 8, 0x8b, 0x4c, 0x24, 44, 0x33, 0x19,
        ]);
        if variant == 2 {
            a.e(&[0x8b, 0xf7]);
        } else {
            a.e(&[0x8b, 0x70, 12]);
        }
        if variant == 4 {
            a.e(&[0x8b, 0xfe, 0x57, 0x5e]);
        } // copies, not additional memory reads
        a.e(&[0x83, 0xfe, 0xfe]);
        a.j(&[0x0f, 0x84], "end");
        a.e(&[0x8b, 0x54, 0x24, 52, 0x83, 0xfa, 0xfe]);
        a.j(&[0x0f, 0x84], "row");
        a.e(&[0x3b, 0xf2]);
        a.j(&[0x0f, 0x86], "end");
        a.label("row");
        if variant == 3 {
            a.e(&[0x8d, 0x24, 0x76, 0x50, 0x58]);
        } // pivot then fake tracked reset
        a.e(&[0x8d, 0x34, 0x76, 0x8d, 0x5c, 0xb3, 16]);
        if variant == 5 {
            a.e(&[0x53, 0x5f, 0x8b, 0xdf]);
        } // row stack alias lacks an admitted capability transfer
        a.e(&[0x8b, 0x0b, 0x89, 0x48, 12, 0x83, 0x7b, 4, 0]);
        a.j(&[0x0f, 0x85], "loop");
        if variant == 1 {
            a.e(&[0x5f, 0x6a, 0]);
        } // corrupt live predecessor across callbacks
        a.e(&[0x68]);
        a.u(0x101);
        a.e(&[0x8b, 0x43, 8]);
        a.call(b.notify);
        a.e(&[0xb9]);
        a.u(1);
        a.e(&[0x8b, 0x43, 8]);
        a.call(b.invoke);
        if variant == 1 {
            a.e(&[0x5a, 0x57]);
        } // put predecessor back before teardown
        a.j(&[0xe9], "loop");
        a.label("end");
        a.e(&[
            0x64, 0x8f, 5, 0, 0, 0, 0, 0x83, 0xc4, 24, 0x5f, 0x5e, 0x5b, 0xc3,
        ]);
        a.done()
    }
    fn wrapper() -> Vec<u8> {
        let mut a = Asm::new(WRAPPER);
        a.e(&[0x55, 0x8b, 0x6c, 0x24, 8, 0x52, 0x51, 0xff, 0x74, 0x24, 20]);
        a.call(BODY);
        a.e(&[0x83, 0xc4, 12, 0x5d, 0xc2, 8, 0]);
        a.done()
    }
    fn nested() -> Vec<u8> {
        nested_variant(0)
    }
    fn nested_variant(variant: u8) -> Vec<u8> {
        let mut a = Asm::new(NESTED);
        a.e(&[0x8b, 0x4c, 0x24, 4, 0xf7, 0x41, 4]);
        a.u(6);
        a.e(&[0xb8]);
        a.u(1);
        a.j(&[0x0f, 0x84], "end");
        a.e(&[0x8b, 0x44, 0x24, 8, 0x8b, 0x48, 8, 0x33, 0xc8]);
        if variant != 1 {
            a.call(bindings().check_cookie);
        }
        a.e(&[
            0x55, 0x8b, 0x68, 24, 0xff, 0x70, 12, 0xff, 0x70, 16, 0xff, 0x70, 20,
        ]);
        a.call(BODY);
        a.e(&[
            0x83, 0xc4, 12, 0x5d, 0x8b, 0x44, 0x24, 8, 0x8b, 0x54, 0x24, 16,
        ]);
        if variant != 2 {
            a.e(&[0x89, 2]);
        }
        a.e(&[0xb8]);
        a.u(3);
        a.label("end");
        a.e(&[0xc3]);
        a.done()
    }
    fn change(code: &mut [u8], from: &[u8], to: &[u8]) {
        assert_eq!(from.len(), to.len());
        let at = code.windows(from.len()).position(|w| w == from).unwrap();
        code[at..at + from.len()].copy_from_slice(to);
    }
    #[test]
    fn instruction_proof_derives_record_calls_and_both_nested_edges() {
        let b = bindings();
        let p = prove(&body(), BODY, Kind::Body, &b).unwrap();
        assert_eq!(p.temporary_bytes, 48);
        assert_eq!(p.callee_pop_bytes, 0);
        assert_eq!(p.kind, Kind::Body);
        assert_eq!(
            p.effects
                .iter()
                .map(|e| e.effect.clone())
                .collect::<Vec<_>>(),
            [
                Effect::InstallTemporary,
                Effect::DecodeScope,
                Effect::ReadTryLevel,
                Effect::ReadScopeRow,
                Effect::WriteTryLevel,
                Effect::Notify,
                Effect::InvokeFinally,
                Effect::RestorePreviousHead
            ]
        );
        assert_eq!(
            p.source,
            prove(&body(), BODY, Kind::Body, &b).unwrap().source
        );
        let p = prove(&wrapper(), WRAPPER, Kind::Wrapper, &b).unwrap();
        assert_eq!(p.temporary_bytes, 20);
        assert_eq!(p.callee_pop_bytes, 8);
        assert_eq!(p.effects[0].effect, Effect::LocalUnwind);
        let p = prove(&nested(), NESTED, Kind::NestedHandler, &b).unwrap();
        assert_eq!(p.temporary_bytes, 20);
        assert_eq!(p.exception_flag_mask, Some(6));
        assert_eq!(
            p.effects
                .iter()
                .map(|e| e.effect.clone())
                .collect::<Vec<_>>(),
            [
                Effect::CheckTemporaryCookie,
                Effect::ReenterLocalUnwind,
                Effect::WriteCollidedRecord
            ]
        );
        assert_eq!(TEMPORARY_LAYOUT.target, 12);
        assert_eq!(TEMPORARY_LAYOUT.cookie_address, 20);
    }
    #[test]
    fn unknown_alias_record_call_order_and_control_mutations_reject() {
        for (from, to) in [
            (&[0x89, 0x44, 0x24, 8][..], &[0x89, 0x44, 0x24, 12][..]),
            (&[0x8b, 0x58, 8], &[0x8b, 0x58, 4]),
            (&[0x89, 0x48, 12], &[0x89, 0x48, 8]),
            (&[0x83, 0xc4, 24], &[0x83, 0xc4, 20]),
            (&[0x8b, 0x4c, 0x24, 44], &[0x8b, 0x4c, 0x24, 40]),
        ] {
            let mut bad = body();
            change(&mut bad, from, to);
            assert!(prove(&bad, BODY, Kind::Body, &bindings()).is_err());
        }
        let mut bad = nested();
        change(
            &mut bad,
            &[0xff, 0x70, 12, 0xff, 0x70, 16],
            &[0xff, 0x70, 16, 0xff, 0x70, 12],
        );
        assert!(prove(&bad, NESTED, Kind::NestedHandler, &bindings()).is_err());
        let mut bad = wrapper();
        change(&mut bad, &[0xc2, 8, 0], &[0xc2, 4, 0]);
        assert!(prove(&bad, WRAPPER, Kind::Wrapper, &bindings()).is_err());
        let mut bad = body();
        let at = bad.iter().rposition(|&b| b == 0xe9).unwrap();
        bad[at + 1..at + 5].copy_from_slice(&(-5i32).to_le_bytes());
        assert!(prove(&bad, BODY, Kind::Body, &bindings()).is_err());
        assert!(prove(&[0x90; 513], BODY, Kind::Body, &bindings()).is_err());
        let mut wrong = bindings();
        wrong.invoke += 1;
        assert!(prove(&body(), BODY, Kind::Body, &wrong).is_err());
    }
    #[test]
    fn independent_record_stale_progress_and_stack_pivot_regressions() {
        for (variant, expected) in [
            (1, "protected pop"),
            (2, "stale or changed level epoch"),
            (3, "LEA ESP pivot"),
            (5, "row-pointer push"),
        ] {
            let error = prove(&body_variant(variant), BODY, Kind::Body, &bindings())
                .err()
                .expect("unsafe helper admitted");
            assert!(error.contains(expected), "variant {variant}: {error}");
        }
        for mask in [0u32, 1, 2, 4, 8, 0xffff_ffff] {
            let mut code = nested();
            change(&mut code, &[6, 0, 0, 0], &mask.to_le_bytes());
            assert!(prove(&code, NESTED, Kind::NestedHandler, &bindings()).is_err());
        }
        for variant in [1, 2] {
            assert!(prove(
                &nested_variant(variant),
                NESTED,
                Kind::NestedHandler,
                &bindings()
            )
            .is_err());
        }
        let mut code = nested();
        change(&mut code, &[0x0f, 0x84], &[0x0f, 0x85]);
        assert!(prove(&code, NESTED, Kind::NestedHandler, &bindings()).is_err());
        let mut code = nested();
        change(&mut code, &[0xf7, 0x41, 4], &[0x81, 0x79, 4]);
        assert!(prove(&code, NESTED, Kind::NestedHandler, &bindings()).is_err());
    }
    #[test]
    fn containment_guards_and_finally_edges_are_proved_before_emission() {
        // Redirect the sentinel JE to fallthrough. The bytes remain a valid CFG
        // but a valid finite parent chain would eventually index sentinel -2.
        let mut bad = body();
        let at = bad.windows(2).position(|w| w == [0x0f, 0x84]).unwrap();
        bad[at + 2..at + 6].copy_from_slice(&0i32.to_le_bytes());
        assert!(prove(&bad, BODY, Kind::Body, &bindings()).is_err());
        // Reverse the sentinel predicate: no numerical containment certificate.
        let mut bad = body();
        bad[at + 1] = 0x85;
        assert!(prove(&bad, BODY, Kind::Body, &bindings()).is_err());
        // The filter-bearing edge cannot enter a finally that does not belong
        // to that scope, nor bypass a required finally on the zero edge.
        let mut bad = body();
        let at = bad.windows(2).position(|w| w == [0x0f, 0x85]).unwrap();
        bad[at + 2..at + 6].copy_from_slice(&0i32.to_le_bytes());
        assert!(prove(&bad, BODY, Kind::Body, &bindings()).is_err());
        let mut bad = body();
        bad[at + 1] = 0x84;
        assert!(prove(&bad, BODY, Kind::Body, &bindings()).is_err());
        let mut bad = body();
        let call = Decoder::with_ip(32, &bad, BODY as u64, DecoderOptions::NONE)
            .into_iter()
            .find(|i| i.code() == Code::Call_rel32_32 && i.near_branch32() == bindings().invoke)
            .unwrap();
        let offset = (call.ip32() - BODY) as usize;
        bad[offset + 1..offset + 5].copy_from_slice(
            &bindings()
                .notify
                .wrapping_sub(call.next_ip32())
                .to_le_bytes(),
        );
        assert!(prove(&bad, BODY, Kind::Body, &bindings()).is_err());
    }
    #[test]
    fn wrapper_requires_exactly_one_body_invocation_before_return() {
        for calls in [0, 2] {
            let mut a = Asm::new(WRAPPER);
            a.e(&[0x55, 0x8b, 0x6c, 0x24, 8, 0x52, 0x51, 0xff, 0x74, 0x24, 20]);
            for _ in 0..calls {
                a.call(BODY);
            }
            a.e(&[0x83, 0xc4, 12, 0x5d, 0xc2, 8, 0]);
            let error = prove(&a.done(), WRAPPER, Kind::Wrapper, &bindings())
                .err()
                .expect("wrapper cardinality was not proved");
            assert!(
                error.contains(if calls == 0 {
                    "return ownership"
                } else {
                    "duplicate wrapper body call"
                }),
                "{error}"
            );
        }
        let original = prove(&wrapper(), WRAPPER, Kind::Wrapper, &bindings()).unwrap();
        assert_eq!(
            original
                .effects
                .iter()
                .filter(|s| s.effect == Effect::LocalUnwind)
                .count(),
            1
        );
    }
    #[test]
    fn scope_graph_requires_full_acyclic_bound_rows() {
        let make = |rows: &[(i32, u32, u32)]| {
            let mut b = vec![0; 16];
            for &(p, f, h) in rows {
                b.extend(p.to_le_bytes());
                b.extend(f.to_le_bytes());
                b.extend(h.to_le_bytes());
            }
            b
        };
        let bound = BTreeSet::from([0x1000, 0x2000]);
        let good = make(&[(-2, 0, 0x1000), (0, 0x2000, 0x1000)]);
        let p = prove_scope_graph(&good, &bound).unwrap();
        assert_eq!(p.rows()[1].parent, 0);
        for rows in [
            vec![(0, 0, 0x1000)],
            vec![(1, 0, 0x1000), (0, 0, 0x2000)],
            vec![(-1, 0, 0x1000)],
            vec![(-2, 0, 0x3000)],
            vec![(-2, 0x3000, 0x1000)],
            vec![(2, 0, 0x1000)],
        ] {
            assert!(prove_scope_graph(&make(&rows), &bound).is_err());
        }
        assert!(prove_scope_graph(&good[..good.len() - 1], &bound).is_err());
        assert!(prove_scope_graph(&vec![0; 16 + 33 * 12], &bound).is_err());
    }
    #[test]
    fn generated_native_loop_and_collision_order_are_instruction_driven() {
        let mut source = String::from("#![allow(dead_code,unused_mut,unused_assignments)]\n");
        source.push_str(EMITTED_TYPES);
        for (name, code, origin, kind) in [
            ("run_body", body(), BODY, Kind::Body),
            ("run_snapshots", body_variant(4), BODY, Kind::Body),
            ("run_wrapper", wrapper(), WRAPPER, Kind::Wrapper),
            ("run_nested", nested(), NESTED, Kind::NestedHandler),
        ] {
            let proof = prove(&code, origin, kind, &bindings()).unwrap();
            source.push_str(&format!("fn {name}(effects:&mut impl LocalUnwindEffects,target_level:i32,exception_flags:u32)->Result<Option<i32>,&'static str>{{{}}}\n",proof.source));
        }
        source.push_str(r#"
struct E{reads:u32,level:i32,rows:Vec<LocalScope>,log:Vec<String>,live:bool,fail:&'static str}
impl E{fn new()->Self{Self{reads:0,level:2,rows:vec![LocalScope{parent:-2,filter:0,handler:10},LocalScope{parent:0,filter:99,handler:20},LocalScope{parent:1,filter:0,handler:30}],log:vec![],live:false,fail:""}}}
impl LocalUnwindEffects for E{
 fn install_temporary(&mut self,depth:u32,handler:u32)->Result<(),&'static str>{assert_eq!((depth,handler),(40,0x5000));assert!(!self.live);self.live=true;self.log.push("install".into());Ok(())}
 fn restore_previous_head(&mut self)->Result<(),&'static str>{assert!(self.live);self.live=false;self.log.push("pop".into());Ok(())}
 fn decode_scope(&mut self)->Result<(),&'static str>{assert!(self.live);Ok(())}
 fn read_try_level(&mut self)->Result<i32,&'static str>{self.reads+=1;Ok(self.level)}
 fn scope_row(&mut self,level:i32)->Result<LocalScope,&'static str>{self.rows.get(usize::try_from(level).map_err(|_|"negative level")?).copied().ok_or("scope bounds")}
 fn write_try_level(&mut self,parent:i32)->Result<(),&'static str>{self.level=parent;self.log.push(format!("level:{parent}"));Ok(())}
 fn notify(&mut self,handler:u32,reason:u32)->Result<(),&'static str>{assert_eq!(reason,0x101);self.log.push(format!("notify:{handler}"));if self.fail=="notify"{Err("notify")}else{Ok(())}}
 fn invoke_finally(&mut self,handler:u32,abnormal:u32)->Result<(),&'static str>{assert_eq!(abnormal,1);assert_eq!(self.level,if handler==30{1}else{-2});self.log.push(format!("finally:{handler}"));if self.fail=="finally"{Err("finally")}else{Ok(())}}
 fn local_unwind(&mut self,target:i32)->Result<(),&'static str>{self.log.push(format!("wrapper:{target}"));Ok(())}
 fn check_temporary_cookie(&mut self)->Result<(),&'static str>{self.log.push("guard".into());if self.fail=="guard"{Err("guard")}else{Ok(())}}
 fn reenter_local_unwind(&mut self)->Result<(),&'static str>{self.log.push("nested".into());if self.fail=="nested"{Err("nested")}else{Ok(())}}
 fn write_collided_record(&mut self)->Result<(),&'static str>{self.log.push("dispatcher-record".into());Ok(())}
}
fn main(){
 let mut snapshots=E::new();assert_eq!(run_snapshots(&mut snapshots,-2,0),Ok(None));assert_eq!(snapshots.reads,4);assert_eq!(snapshots.level,-2);
 let mut e=E::new();assert_eq!(run_body(&mut e,-2,0),Ok(None));assert_eq!(e.level,-2);assert!(!e.live);assert_eq!(e.log,vec!["install","level:1","notify:30","finally:30","level:0","level:-2","notify:10","finally:10","pop"]);
 let mut e=E::new();assert_eq!(run_body(&mut e,1,0),Ok(None));assert_eq!(e.level,1);assert_eq!(e.log,vec!["install","level:1","notify:30","finally:30","pop"]);
 let mut e=E::new();e.level=-2;assert_eq!(run_body(&mut e,-2,0),Ok(None));assert_eq!(e.log,vec!["install","pop"]);
 let mut e=E::new();e.level=0;assert_eq!(run_body(&mut e,1,0),Ok(None));assert_eq!(e.level,0);assert_eq!(e.log,vec!["install","pop"]);
 for fail in ["notify","finally"]{let mut e=E::new();e.fail=fail;assert_eq!(run_body(&mut e,-2,0),Err(fail));assert_eq!(e.level,1);assert!(e.live);assert!(!e.log.contains(&"pop".into()));}
 let mut e=E::new();assert_eq!(run_wrapper(&mut e,7,0),Ok(None));assert_eq!(e.log,vec!["wrapper:7"]);
 for flags in [0,1,8,0x80000000]{let mut e=E::new();assert_eq!(run_nested(&mut e,0,flags),Ok(Some(1)));assert!(e.log.is_empty());}
 for flags in [2,4,6,7,0xffffffff]{let mut e=E::new();assert_eq!(run_nested(&mut e,0,flags),Ok(Some(3)));assert_eq!(e.log,vec!["guard","nested","dispatcher-record"]);}
 for fail in ["guard","nested"]{let mut e=E::new();e.fail=fail;assert_eq!(run_nested(&mut e,0,2),Err(fail));assert!(!e.log.contains(&"dispatcher-record".into()));}
}
"#);
        let directory =
            std::env::temp_dir().join(format!("w2l-local-native-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("check.rs");
        let exe = directory.join(if cfg!(windows) { "check.exe" } else { "check" });
        std::fs::write(&path, source).unwrap();
        let built = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(&path)
            .arg("-o")
            .arg(&exe)
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        assert!(std::process::Command::new(&exe).status().unwrap().success());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
