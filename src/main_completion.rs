//! Instruction-derived completion of an owned function frame. This is not CRT
//! admission: the bound variadic callee needs a separate reviewed stdio effect.
//! In particular neither its symbol name nor an observed output grants authority.
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Word {
    Uninitialized,
    Scalar,
    Stack,
    Module,
    Continuation,
}
pub(crate) struct Layout {
    /// Initialized ordinary words, EBP relative. Protected slots are separate.
    pub words: BTreeMap<i32, Word>,
    pub esp: i32,
    pub saved: BTreeMap<i32, u8>,
    pub guards: BTreeSet<i32>,
    pub predecessor: i32,
}
pub(crate) struct Bindings {
    pub module_base: u32,
    pub module_size: u32,
    pub globals: BTreeMap<u32, usize>,
    pub printf: u32,
    pub format: u32,
    pub security_check: u32,
}
#[derive(Debug)]
pub(crate) struct ProvenCompletion {
    source: String,
    scratch: u32,
    pub printf_pc: u32,
    pub argument_count: usize,
    pub pops: Vec<(i32, u8, bool)>,
    pub cookie_offset: i32,
    pub security_target: u32,
    pub return_offset: i32,
    pub return_pc: u32,
}
impl ProvenCompletion {
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn temporary_bytes(&self) -> u32 {
        self.scratch
    }
}
pub(crate) const EMITTED_TYPES: &str = r#"
struct PrintRequest<'a>{call_pc:u32,target:u32,format:u32,arguments:&'a [u32]}
struct CompletionOutcome<P>{value:u32,saved:[Option<u32>;8],predecessor:P,caller_sp:u32}
enum CompletionEffect<'a,P>{
 RestorePredecessor(&'a P),
 Pop{offset:i32,register:u8,saved:Option<u32>,guard:bool},
 Cookie{offset:i32,frame:u32,cookie:u32,bits:u32,target:u32},
 Return{offset:i32,value:u32,saved:[Option<u32>;8],caller_sp:u32},
}
"#;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ty {
    Unknown,
    Scalar(Option<u32>),
    Stack,
    Module,
    Pointer,
    Borrowed,
    Guard(i32),
    Cookie(i32),
    Saved(u8),
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    regs: [Ty; 8],
    sp: i32,
    pending: Vec<Ty>,
    initialized: BTreeSet<i32>,
    format_known: bool,
    flags: bool,
    printed: bool,
    unlinked: bool,
    checked: bool,
    restored: u8,
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
        _ => Err("completion: unsupported register width".into()),
    }
}
fn scalar(t: Ty) -> bool {
    matches!(t, Ty::Scalar(_))
}
fn full_range(base: u32, size: u32, address: u32, bytes: u32) -> bool {
    base != 0
        && base.checked_add(size).is_some_and(|end| {
            address >= base && address.checked_add(bytes).is_some_and(|a| a <= end)
        })
}
fn memory(i: &Instruction) -> Result<Option<i32>, String> {
    if i.memory_index() != Register::None || i.memory_size() != iced_x86::MemorySize::UInt32 {
        return Err("completion: full-word nonindexed address required".into());
    }
    match i.memory_base() {
        Register::EBP => Ok(Some(i.memory_displacement32() as i32)),
        Register::None => Ok(None),
        _ => Err("completion: address owner".into()),
    }
}
fn read(
    i: &Instruction,
    n: u32,
    s: &State,
    l: &Layout,
    b: &Bindings,
) -> Result<(Ty, String), String> {
    match i.op_kind(n) {
        OpKind::Register => {
            let r = reg(i.op_register(n))?;
            let t = s.regs[r];
            if matches!(t, Ty::Unknown | Ty::Saved(_)) {
                return Err("completion: unknown register read".into());
            }
            Ok((t, format!("r[{r}]")))
        }
        OpKind::Immediate8to32 | OpKind::Immediate32 => {
            let v = i.immediate(n) as u32;
            Ok((
                if full_range(b.module_base, b.module_size, v, 1) {
                    Ty::Pointer
                } else {
                    Ty::Scalar(Some(v))
                },
                format!("{v}u32"),
            ))
        }
        OpKind::Memory => {
            if i.segment_prefix() != Register::None {
                return Err("completion: unbound segment read".into());
            }
            if let Some(at) = memory(i)? {
                if at % 4 != 0 {
                    return Err("completion: unaligned word".into());
                }
                if at == l.predecessor {
                    return Ok((Ty::Borrowed,format!("{{predecessor=Some(match memory.image.words.get(&memory.key({at})?){{Some(FrameWord::Borrowed(p))=>p.clone(),_=>return Err(\"completion predecessor ownership\")}});0u32}}")));
                }
                if l.guards.contains(&at) {
                    return Ok((Ty::Guard(at),format!("{{let(gf,gc,gb)=memory.read_guard({at})?;if gf!=memory.frame_pointer()||gc!=cookie{{return Err(\"completion protected cookie\");}}gb}}")));
                }
                let (t, method) = match l.words.get(&at) {
                    Some(Word::Scalar) => (Ty::Scalar(None), "read_u32"),
                    Some(Word::Uninitialized) if s.initialized.contains(&at) => {
                        (Ty::Scalar(None), "read_u32")
                    }
                    Some(Word::Stack) => (Ty::Stack, "read_stack"),
                    Some(Word::Module) => (Ty::Module, "read_module"),
                    Some(Word::Continuation) => (Ty::Pointer, "read_continuation"),
                    _ => return Err("completion: uninitialized/protected frame read".into()),
                };
                Ok((t, format!("memory.{method}({at})?")))
            } else {
                let at = i.memory_displacement32();
                let index = b.globals.get(&at).ok_or("completion: unbound global")?;
                Ok((
                    Ty::Scalar(None),
                    format!("*globals.get({index}).ok_or(\"completion global bounds\")?"),
                ))
            }
        }
        _ => Err("completion: unsupported operand".into()),
    }
}
fn merge(old: &mut State, new: &State) -> Result<bool, String> {
    let mut a = old.clone();
    let mut c = new.clone();
    a.regs = [Ty::Unknown; 8];
    c.regs = [Ty::Unknown; 8];
    a.flags = false;
    c.flags = false;
    a.initialized.clear();
    c.initialized.clear();
    if a != c {
        return Err("completion: incompatible control/stack/ownership join".into());
    }
    let before = old.clone();
    for (x, y) in old.regs.iter_mut().zip(new.regs) {
        if *x != y {
            *x = if scalar(*x) && scalar(y) {
                Ty::Scalar(None)
            } else {
                Ty::Unknown
            };
        }
    }
    old.flags &= new.flags;
    old.initialized.retain(|at| new.initialized.contains(at));
    Ok(*old != before)
}
/// Source is a Rust expression. Lexical inputs: memory:&mut FrameMemory<P>,
/// globals:&mut [u32], cookie:u32, printf:FnMut(PrintRequest)->Result<Option<u32>,_>,
/// effects:FnMut(CompletionEffect<P>)->Result<(),_>. P:Clone. Callee effects must be admitted by
/// the parent: caller-saved clobbers, preserved frame/global memory, owned CRT
/// state and exact output/error semantics. A callback is not an admission token.
pub(crate) fn prove(
    code: &[u8],
    origin: u32,
    l: &Layout,
    b: &Bindings,
) -> Result<ProvenCompletion, String> {
    if code.is_empty()
        || code.len() > 2048
        || origin == 0
        || origin.checked_add(code.len() as u32).is_none()
    {
        return Err("completion: code extent/budget".into());
    }
    if !full_range(b.module_base, b.module_size, origin, code.len() as u32)
        || ![b.printf, b.format, b.security_check]
            .into_iter()
            .all(|v| full_range(b.module_base, b.module_size, v, 1))
        || b.printf == b.security_check
    {
        return Err("completion: module/callee binding".into());
    }
    if l.esp >= 0
        || l.esp < -16384
        || l.predecessor < l.esp
        || l.predecessor >= 0
        || l.saved.get(&0) != Some(&5)
        || l.saved.iter().any(|(at, reg)| {
            *at < l.esp
                || *at > 0
                || !matches!(*reg, 3 | 5 | 6 | 7)
                || l.guards.contains(at)
                || *at == l.predecessor
        })
        || l.guards
            .iter()
            .any(|at| *at < l.esp || *at >= 0 || *at % 4 != 0)
        || l.esp % 4 != 0
        || l.predecessor % 4 != 0
        || l.words.keys().any(|at| {
            *at >= 0
                || *at < l.esp
                || *at % 4 != 0
                || l.saved.contains_key(at)
                || l.guards.contains(at)
                || *at == l.predecessor
        })
        || l.saved.iter().any(|(at, r)| *at % 4 != 0 || *r > 7)
        || l.guards.contains(&l.predecessor)
    {
        return Err("completion: layout ownership".into());
    }
    let mut global_indices = BTreeSet::new();
    if b.globals.iter().any(|(va, index)| {
        va % 4 != 0
            || !full_range(b.module_base, b.module_size, *va, 4)
            || !global_indices.insert(*index)
            || (*va < origin + code.len() as u32 && va.saturating_add(4) > origin)
    }) {
        return Err("completion: global map alias/range".into());
    }
    let mut ins = BTreeMap::new();
    let mut decoder = Decoder::with_ip(32, code, origin as u64, DecoderOptions::NONE);
    while decoder.can_decode() {
        let i = decoder.decode();
        let raw = &code[(i.ip() as u32 - origin) as usize..(i.next_ip() as u32 - origin) as usize];
        if i.is_invalid()
            || i.has_lock_prefix()
            || i.has_rep_prefix()
            || i.has_repne_prefix()
            || ins.len() >= 192
            || raw.first().is_some_and(|x| {
                matches!(
                    x,
                    0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3 | 0x26 | 0x2e | 0x36 | 0x3e | 0x65
                )
            })
        {
            return Err("completion: malformed/prefixed instruction".into());
        }
        ins.insert(i.ip() as u32, i);
    }
    let mut initial = State {
        regs: [Ty::Unknown; 8],
        sp: l.esp,
        pending: Vec::new(),
        initialized: BTreeSet::new(),
        format_known: false,
        flags: false,
        printed: false,
        unlinked: false,
        checked: false,
        restored: 0,
    };
    initial.regs[4] = Ty::Stack;
    initial.regs[5] = Ty::Stack;
    let mut states = BTreeMap::from([(origin, initial)]);
    let mut bodies = BTreeMap::new();
    let mut scratch = 0;
    let mut print_site = None;
    let mut returns = 0;
    let mut pops = Vec::new();
    let mut cookie_site = None;
    let mut unlink_site = None;
    let mut return_pc = 0;
    for (&pc, i) in &ins {
        let mut s = states
            .get(&pc)
            .cloned()
            .ok_or("completion: unreachable/hidden instruction")?;
        let mut out = String::new();
        let mut successors = vec![i.next_ip() as u32];
        let mut next = String::new();
        match i.mnemonic() {
            Mnemonic::Mov => {
                if i.segment_prefix() == Register::FS {
                    if i.op0_kind() != OpKind::Memory
                        || i.memory_base() != Register::None
                        || i.memory_index() != Register::None
                        || i.memory_displacement32() != 0
                        || i.op1_kind() != OpKind::Register
                        || s.regs[reg(i.op1_register())?] != Ty::Borrowed
                        || !s.printed
                        || s.unlinked
                        || !s.pending.is_empty()
                    {
                        return Err("completion: FS predecessor restoration".into());
                    }
                    out.push_str("effects(CompletionEffect::RestorePredecessor(predecessor.as_ref().ok_or(\"completion missing predecessor\")?))?;\n");
                    s.unlinked = true;
                    if unlink_site.replace(pc).is_some() {
                        return Err("completion: multiple predecessor restore sites".into());
                    }
                } else if i.op0_kind() == OpKind::Register {
                    let dst = reg(i.op0_register())?;
                    if dst == 4 {
                        if i.op1_register() != Register::EBP
                            || !s.checked
                            || !s.unlinked
                            || !s.pending.is_empty()
                        {
                            return Err("completion: invalid final stack restoration".into());
                        }
                        s.sp = 0;
                        out.push_str("r[4]=memory.frame_pointer();\n");
                    } else {
                        if dst == 5 {
                            return Err("completion: EBP overwrite".into());
                        }
                        let (t, e) = read(i, 1, &s, l, b)?;
                        s.regs[dst] = t;
                        out.push_str(&format!("r[{dst}]={e};\n"));
                    }
                } else {
                    if i.segment_prefix() != Register::None {
                        return Err("completion: segment write".into());
                    }
                    let at = memory(i)?.ok_or("completion: global stores not admitted")?;
                    if !matches!(l.words.get(&at), Some(Word::Scalar | Word::Uninitialized)) {
                        return Err("completion: protected/non-scalar store".into());
                    }
                    let (t, e) = read(i, 1, &s, l, b)?;
                    if !scalar(t) {
                        return Err("completion: pointer scalar store".into());
                    }
                    out.push_str(&format!("memory.write_u32({at},{e})?;\n"));
                    s.initialized.insert(at);
                }
            }
            Mnemonic::Xor => {
                let d = reg(i.op0_register())?;
                let q = reg(i.op1_register())?;
                if i.op0_kind() != OpKind::Register
                    || i.op1_kind() != OpKind::Register
                    || matches!(d, 4 | 5)
                {
                    return Err("completion: XOR form".into());
                }
                if d == q {
                    s.regs[d] = Ty::Scalar(Some(0));
                    out.push_str(&format!("r[{d}]=0;zf=true;\n"));
                    s.flags = true;
                } else if let (Ty::Guard(offset), 5) = (s.regs[d], q) {
                    s.regs[d] = Ty::Cookie(offset);
                    out.push_str(&format!("r[{d}]^=r[5];\n"));
                    s.flags = false;
                } else {
                    return Err("completion: XOR provenance".into());
                }
            }
            Mnemonic::Sub => {
                let dst = reg(i.op0_register())?;
                let (a, x) = read(i, 0, &s, l, b)?;
                let (c, y) = read(i, 1, &s, l, b)?;
                if matches!(dst, 4 | 5)
                    || !((a == Ty::Pointer && c == Ty::Module) || (scalar(a) && scalar(c)))
                {
                    return Err("completion: subtraction provenance".into());
                }
                if a == Ty::Pointer {
                    out.push_str(&format!("if !({}u32..{}u32).contains(&{x})||{y}!={}u32{{return Err(\"completion same-module subtraction\");}}\n",b.module_base,b.module_base.checked_add(b.module_size).ok_or("module end")?,b.module_base));
                }
                out.push_str(&format!(
                    "r[{dst}]=({x}).wrapping_sub({y});zf=r[{dst}]==0;\n"
                ));
                s.regs[dst] = Ty::Scalar(None);
                s.flags = true;
            }
            Mnemonic::Cmp => {
                let (a, x) = read(i, 0, &s, l, b)?;
                let (c, y) = read(i, 1, &s, l, b)?;
                if !((scalar(a) && scalar(c)) || (a == Ty::Stack && c == Ty::Stack)) {
                    return Err("completion: comparison provenance".into());
                }
                out.push_str(&format!("zf=({x})==({y});\n"));
                s.flags = true;
            }
            Mnemonic::Sete => {
                if !s.flags || i.op0_kind() != OpKind::Register {
                    return Err("completion: unknown equality flag".into());
                }
                let dst = match i.op0_register() {
                    Register::AL => 0,
                    Register::CL => 1,
                    Register::DL => 2,
                    _ => return Err("completion: SET width".into()),
                };
                if !scalar(s.regs[dst]) {
                    return Err("completion: unknown upper bits".into());
                }
                out.push_str(&format!("r[{dst}]=(r[{dst}]&0xffffff00)|u32::from(zf);\n"));
                s.regs[dst] = Ty::Scalar(None);
            }
            Mnemonic::Push => {
                if s.printed || s.pending.len() >= 32 {
                    return Err("completion: unexpected arguments".into());
                }
                let (t, e) = read(i, 0, &s, l, b)?;
                if !scalar(t) && t != Ty::Pointer {
                    return Err("completion: invalid variadic word".into());
                }
                s.format_known =
                    matches!(i.op0_kind(), OpKind::Immediate32 | OpKind::Immediate8to32)
                        && i.immediate(0) as u32 == b.format;
                s.pending.push(t);
                s.sp = s.sp.checked_sub(4).ok_or("push overflow")?;
                out.push_str(&format!("args.push({e});\n"));
                scratch = scratch.max((l.esp - s.sp) as u32);
            }
            Mnemonic::Call => {
                if i.code() != Code::Call_rel32_32 {
                    return Err("completion: indirect/unbound call".into());
                }
                let target = i.near_branch32();
                if target == b.printf {
                    if s.printed
                        || s.pending.is_empty()
                        || s.pending.last() != Some(&Ty::Pointer)
                        || !s.format_known
                    {
                        return Err("completion: printf arguments/phase".into());
                    }
                    if s.pending[..s.pending.len() - 1].iter().any(|t| !scalar(*t)) {
                        return Err("completion: nonscalar variadic argument".into());
                    }
                    let argc = s.pending.len() - 1;
                    if print_site.replace((pc, argc)).is_some() {
                        return Err("completion: multiple printf sites".into());
                    }
                    scratch = scratch.max((l.esp - s.sp + 4) as u32);
                    out.push_str(&format!("if args.pop()!=Some({}u32){{return Err(\"completion format identity\");}}args.reverse();let _opaque_printf_return=printf(PrintRequest{{call_pc:{pc},target:{target},format:{},arguments:&args}})?;args.clear();\n",b.format,b.format));
                    s.printed = true;
                    s.regs[0] = Ty::Unknown;
                    s.regs[1] = Ty::Unknown;
                    s.regs[2] = Ty::Unknown;
                    s.flags = false;
                } else if target == b.security_check {
                    if !s.printed
                        || !s.unlinked
                        || s.checked
                        || !matches!(s.regs[1], Ty::Cookie(_))
                        || !s.pending.is_empty()
                    {
                        return Err("completion: security-check authority/order".into());
                    }
                    let Ty::Cookie(offset) = s.regs[1] else {
                        unreachable!()
                    };
                    if cookie_site.replace(offset).is_some() {
                        return Err("completion: multiple cookie check sites".into());
                    }
                    out.push_str(&format!("if r[1]!=cookie{{return Err(\"completion cookie mismatch\");}}effects(CompletionEffect::Cookie{{offset:{offset},frame:r[5],cookie,bits:r[1]^r[5],target:{target}}})?;\n"));
                    s.checked = true;
                    s.flags = false;
                } else {
                    return Err("completion: unbound call target".into());
                }
            }
            Mnemonic::Add => {
                if i.op0_register() != Register::ESP
                    || !matches!(i.op1_kind(), OpKind::Immediate8to32 | OpKind::Immediate32)
                    || !s.printed
                    || s.pending.is_empty()
                    || i.immediate(1) as usize != s.pending.len() * 4
                {
                    return Err("completion: exact caller cleanup".into());
                }
                s.sp =
                    s.sp.checked_add((s.pending.len() * 4) as i32)
                        .ok_or("cleanup overflow")?;
                s.pending.clear();
                s.format_known = false;
                s.flags = false;
            }
            Mnemonic::Jne | Mnemonic::Je => {
                if !s.flags || s.unlinked {
                    return Err("completion: unknown branch flag/epilog branch".into());
                }
                let target = i.near_branch32();
                successors.push(target);
                next = format!(
                    "pc=if {}zf{{{target}}}else{{{}}};continue;",
                    if i.mnemonic() == Mnemonic::Jne {
                        "!"
                    } else {
                        ""
                    },
                    i.next_ip()
                );
            }
            Mnemonic::Jmp => {
                if s.unlinked || !matches!(i.code(), Code::Jmp_rel8_32 | Code::Jmp_rel32_32) {
                    return Err("completion: indirect transfer".into());
                }
                successors = vec![i.near_branch32()];
            }
            Mnemonic::Pop => {
                if !s.unlinked || !s.pending.is_empty() {
                    return Err("completion: pop before unlink/cleanup".into());
                }
                let dst = reg(i.op0_register())?;
                if let Some(&saved) = l.saved.get(&s.sp) {
                    if saved as usize != dst || s.restored & (1 << dst) != 0 {
                        return Err("completion: saved-register order".into());
                    }
                    out.push_str(&format!("restored[{dst}]=match memory.image.words.get(&memory.key({})?){{Some(FrameWord::Saved({dst},v))=>*v,_=>return Err(\"completion saved ownership\")}};\n",s.sp));
                    out.push_str(&format!("effects(CompletionEffect::Pop{{offset:{},register:{dst},saved:restored[{dst}],guard:false}})?;\n",s.sp));
                    pops.push((s.sp, dst as u8, false));
                    s.restored |= 1 << dst;
                    s.regs[dst] = Ty::Saved(saved);
                } else if l.guards.contains(&s.sp) && dst == 1 && !s.checked {
                    out.push_str(&format!("let(gf,gc,_gb)=memory.read_guard({})?;if gf!=memory.frame_pointer()||gc!=cookie{{return Err(\"completion discarded guard ownership\");}}effects(CompletionEffect::Pop{{offset:{},register:{dst},saved:None,guard:true}})?;\n",s.sp,s.sp));
                    pops.push((s.sp, dst as u8, true));
                    s.regs[dst] = Ty::Unknown;
                } else {
                    return Err("completion: protected pop".into());
                }
                s.sp = s.sp.checked_add(4).ok_or("pop overflow")?;
            }
            Mnemonic::Ret => {
                if i.code() != Code::Retnd
                    || !s.checked
                    || !s.unlinked
                    || s.sp != 4
                    || !s.pending.is_empty()
                    || !scalar(s.regs[0])
                    || l.saved
                        .values()
                        .any(|r| s.restored & (1 << r) == 0 || s.regs[*r as usize] != Ty::Saved(*r))
                {
                    return Err("completion: return obligations".into());
                }
                out.push_str("if !matches!(memory.image.words.get(&memory.key(4)?),Some(FrameWord::Return)){return Err(\"completion protected return\");}let caller_sp=frame_address(memory.frame_pointer(),8)?;effects(CompletionEffect::Return{offset:4,value:r[0],saved:restored,caller_sp})?;return Ok(CompletionOutcome{value:r[0],saved:restored,predecessor:predecessor.take().ok_or(\"completion predecessor\")?,caller_sp});\n");
                successors.clear();
                returns += 1;
                return_pc = pc;
            }
            _ => {
                return Err(format!(
                    "completion: unsupported instruction at {pc:x}: {:?}",
                    i.code()
                ))
            }
        }
        if i.segment_prefix() != Register::None
            && !(i.segment_prefix() == Register::FS
                && i.mnemonic() == Mnemonic::Mov
                && i.op0_kind() == OpKind::Memory)
        {
            return Err("completion: segment prefix".into());
        }
        if matches!(i.mnemonic(), Mnemonic::Push | Mnemonic::Pop | Mnemonic::Add) {
            out.push_str(&format!(
                "r[4]=frame_address(memory.frame_pointer(),{})?;\n",
                s.sp
            ));
        }
        for &target in &successors {
            if target <= pc || !ins.contains_key(&target) {
                return Err("completion: nonforward/misaligned/outside target".into());
            }
            if let Some(old) = states.get_mut(&target) {
                merge(old, &s)?;
            } else {
                states.insert(target, s.clone());
            }
        }
        if !successors.is_empty() {
            if next.is_empty() {
                next = format!("pc={};continue;", successors[0]);
            }
            out.push_str(&next);
        }
        bodies.insert(pc, out);
    }
    if scratch > 128 {
        return Err("completion: temporary stack budget".into());
    }
    if returns != 1 {
        return Err("completion: no protected return".into());
    }
    let (printf_pc, argument_count) = print_site.ok_or("completion: missing printf")?;
    let mut source=format!("{{memory.preflight_call_stack({scratch})?;let mut r=[0u32;8];r[5]=memory.frame_pointer();r[4]=memory.stack_pointer();if r[4]!=frame_address(r[5],{})?{{return Err(\"completion initial stack\");}}let mut zf=false;let mut args=Vec::<u32>::new();let mut predecessor=None;let mut restored=[None;8];let mut pc={origin}u32;loop{{match pc{{",l.esp);
    for (pc, body) in bodies {
        source.push_str(&format!("{pc}=>{{{body}}},"));
    }
    source.push_str("_=>return Err(\"completion invalid control\"),}}}");
    Ok(ProvenCompletion {
        source,
        scratch,
        printf_pc,
        argument_count,
        pops,
        cookie_offset: cookie_site.ok_or("completion: missing cookie")?,
        security_target: b.security_check,
        return_offset: 4,
        return_pc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn call(code: &mut Vec<u8>, origin: u32, target: u32) {
        let next = origin + code.len() as u32 + 5;
        code.push(0xe8);
        code.extend_from_slice(&target.wrapping_sub(next).to_le_bytes());
    }
    fn fixture() -> (Vec<u8>, Layout, Bindings) {
        let mut c = vec![
            0x8b, 0x4d, 0xd0, 0x51, 0xb8, 0x00, 0x18, 0, 0, 0x2b, 0x45, 0xd4, 0x50, 0x68, 0, 0x19,
            0, 0,
        ];
        call(&mut c, 0x1100, 0x1a00);
        c.extend([
            0x83, 0xc4, 12, 0x83, 0x7d, 0xd0, 42, 0x75, 9, 0xc7, 0x45, 0xd8, 7, 0, 0, 0, 0xeb, 7,
            0xc7, 0x45, 0xd8, 9, 0, 0, 0, 0x8b, 0x45, 0xd8, 0x8b, 0x4d, 0xf0, 0x64, 0x89, 0x0d, 0,
            0, 0, 0, 0x59, 0x5f, 0x5e, 0x5b, 0x8b, 0x4d, 0xe4, 0x33, 0xcd,
        ]);
        call(&mut c, 0x1100, 0x1b00);
        c.extend([0x8b, 0xe5, 0x5d, 0xc3]);
        (
            c,
            Layout {
                words: BTreeMap::from([
                    (-48, Word::Scalar),
                    (-44, Word::Module),
                    (-40, Word::Uninitialized),
                ]),
                esp: -64,
                saved: BTreeMap::from([(-60, 7), (-56, 6), (-52, 3), (0, 5)]),
                guards: BTreeSet::from([-64, -28]),
                predecessor: -16,
            },
            Bindings {
                module_base: 0x1000,
                module_size: 0x2000,
                globals: BTreeMap::new(),
                printf: 0x1a00,
                format: 0x1900,
                security_check: 0x1b00,
            },
        )
    }
    #[test]
    fn decoded_branch_variadic_order_and_ignored_io_failure_execute_natively() {
        let (c, l, b) = fixture();
        let proof = prove(&c, 0x1100, &l, &b).unwrap();
        assert_eq!(proof.argument_count, 2);
        assert_eq!(proof.temporary_bytes(), 16);
        let source = format!(
            r#"#![allow(dead_code,unused_assignments,unused_mut)]
{}
{}
{}
fn execute(memory:&mut FrameMemory<'_,u64>,cookie:u32,seen:&mut Vec<String>)->Result<CompletionOutcome<u64>,&'static str>{{
let globals:&mut[u32]=&mut[];
let mut printf=|request:PrintRequest<'_>|->Result<Option<u32>,&'static str>{{assert_eq!(request.target,0x1a00);assert_eq!(request.format,0x1900);assert_eq!(request.arguments[0],0x800);seen.push(format!("print:{{}}",request.arguments[1]));Ok(None)}};
let mut effects=|effect:CompletionEffect<'_,u64>|->Result<(),&'static str>{{match effect{{CompletionEffect::RestorePredecessor(p)=>assert_eq!(*p,77),CompletionEffect::Pop{{..}}=>{{}},CompletionEffect::Cookie{{target,bits,frame,cookie,..}}=>{{assert_eq!(target,0x1b00);assert_eq!(bits,frame^cookie)}},CompletionEffect::Return{{value,..}}=>assert!(value==7||value==9)}}Ok(())}};
{}
}}
fn main(){{for (input,expected) in [(42,7),(43,9),(u32::MAX,9)]{{
let ebp=0x9000u32;let cookie=0x12345678;let mut words=std::collections::BTreeMap::new();
for (at,word) in [(-64,FrameWord::Guard{{frame:ebp,cookie,bits:ebp^cookie}}),(-60,FrameWord::Saved(7,None)),(-56,FrameWord::Saved(6,Some(66))),(-52,FrameWord::Saved(3,None)),(-48,FrameWord::Scalar(input)),(-44,FrameWord::ModuleBase{{owner:2,base:0x1000}}),(-40,FrameWord::Unknown),(-28,FrameWord::Guard{{frame:ebp,cookie,bits:ebp^cookie}}),(-16,FrameWord::Borrowed(77)),(0,FrameWord::Saved(5,None)),(4,FrameWord::Return)]{{words.insert(at-4,word);}}
let mut image=FrameImage{{words,entry_sp:ebp+4,ebp,esp:ebp-64,record:ebp-16,scope_va:0x2000,handler_va:0x2100,try_level:0}};
let mut memory=FrameMemory::new(&mut image,2,&[-48,-44,-40]).unwrap();let mut seen=vec![];let result=execute(&mut memory,cookie,&mut seen).unwrap();assert_eq!(result.value,expected);assert_eq!(result.saved[6],Some(66));assert_eq!(result.saved[7],None);assert_eq!(result.predecessor,77);assert_eq!(result.caller_sp,ebp+8);assert_eq!(seen,vec![format!("print:{{input}}")]);
}}}}
"#,
            super::super::frame_proof::EMITTED_TYPES,
            super::super::frame_memory::EMITTED_TYPES,
            EMITTED_TYPES,
            proof.source()
        );
        let dir = std::env::temp_dir().join(format!("w2l-main-completion-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("main.rs");
        let binary = dir.join("main");
        std::fs::write(&src, source).unwrap();
        let compile = std::process::Command::new("rustc")
            .args(["--edition=2021"])
            .arg(&src)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );
        let run = std::process::Command::new(binary).output().unwrap();
        assert!(
            run.status.success(),
            "{}",
            String::from_utf8_lossy(&run.stderr)
        );
    }
    #[test]
    fn unknown_return_uninitialized_word_and_wrong_cleanup_reject() {
        let (c, l, b) = fixture();
        let mut unknown = c.clone();
        let add = unknown
            .windows(3)
            .position(|w| w == [0x83, 0xc4, 12])
            .unwrap();
        unknown[add + 3..add + 7].copy_from_slice(&[0x83, 0xf8, 42, 0x90]);
        assert!(prove(&unknown, 0x1100, &l, &b).is_err());
        let mut bad = c.clone();
        bad[add + 2] = 8;
        assert!(prove(&bad, 0x1100, &l, &b).unwrap_err().contains("cleanup"));
        let mut bad = c.clone();
        bad[14] = 1;
        assert!(prove(&bad, 0x1100, &l, &b).is_err());
        let mut branch_missing = c.clone();
        let fail = branch_missing
            .windows(7)
            .position(|w| w == [0xc7, 0x45, 0xd8, 9, 0, 0, 0])
            .unwrap();
        branch_missing[fail..fail + 7].copy_from_slice(&[0xb9, 9, 0, 0, 0, 0x31, 0xc9]);
        assert!(prove(&branch_missing, 0x1100, &l, &b)
            .unwrap_err()
            .contains("uninitialized"));
        let mut bad = c.clone();
        bad[2] = 0xd8;
        assert!(prove(&bad, 0x1100, &l, &b)
            .unwrap_err()
            .contains("uninitialized"));
        let mut bad = c.clone();
        let pop = bad
            .windows(4)
            .position(|w| w == [0x59, 0x5f, 0x5e, 0x5b])
            .unwrap();
        bad[pop + 1] = 0x5b;
        assert!(prove(&bad, 0x1100, &l, &b).is_err());
    }
    #[test]
    fn hidden_prefix_cycle_branch_mid_instruction_and_postpop_clobber_reject() {
        let (c, l, b) = fixture();
        for bytes in [vec![0x66], vec![0xf3], vec![0x64]] {
            let mut bad = bytes;
            bad.extend(&c);
            assert!(prove(&bad, 0x1100, &l, &b).is_err());
        }
        let branch = c.windows(2).position(|w| w == [0x75, 9]).unwrap();
        for target in [0xfe, 1, 0x7f] {
            let mut bad = c.clone();
            bad[branch + 1] = target;
            assert!(prove(&bad, 0x1100, &l, &b).is_err());
        }
        let mut bad = c.clone();
        let ret = bad.len() - 1;
        bad.splice(ret..ret, [0x31, 0xdb]);
        assert!(prove(&bad, 0x1100, &l, &b)
            .unwrap_err()
            .contains("return obligations"));
    }
}
