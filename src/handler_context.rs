//! Decoded x86 context/TEB stack-bound helper at an explicit same-thread cut.
//! This proves the local helper, not acquisition of a Windows TEB or CONTEXT,
//! original exception delivery, or emulation of the INT 29 failure path.
//!
//! Primary contracts: Microsoft Learn x86 CONTEXT (`winnt/ns-winnt-context-r2`)
//! identifies the architecture-specific Esp field; `cpp/intrinsics/fastfail`
//! specifies nonreturning x86 INT 29 with its code in ECX. The TEB documentation
//! (`winternl/ns-winternl-teb`) explicitly warns that its layout can change.
//! Consequently FS:[0x18], NT_TIB offsets 4/8, and CONTEXT offset 0xc4 below
//! are bound to the decoded x86 helper and a declared captured-state contract,
//! not a portable host ABI assumption. Native fast-fail support starts in
//! Windows 8; this component supplies no XP/7 failure-behavior claim.
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};

/// The containing proof owns the initialized selector word and its runtime
/// value. The value stored in a PE file is not the live selector value.
pub(crate) struct ContextCheckProof {
    body: String,
    projection_body: String,
    selector_va: u32,
    bypass_selector: u32,
    temporary_bytes: u32,
}
impl ContextCheckProof {
    /// Body of `ThreadContext::check(&self, owner:u64, selector:u32)
    /// -> Result<(), &'static str>`. Include EMITTED_TYPES in the same module.
    pub(crate) fn body(&self) -> &str {
        &self.body
    }
    /// The same decoded decision over an event-owned opaque captured context.
    /// `self` must provide preflight(owner), captured_below_limit(owner) and
    /// captured_at_most_base(owner), each fallible. No raw ESP, EIP or general
    /// register value is manufactured by this lowering. The event capability
    /// supplies only the explicitly admitted same-thread valid-stack domain.
    pub(crate) fn projection_body(&self) -> &str {
        &self.projection_body
    }
    /// Connect the decoded helper to live pending-event object storage. The
    /// selector is read from the original module cell, never supplied as a
    /// Boolean bypass. Acquisition of captured objects remains a separate cut.
    #[allow(dead_code)] // Shared emitter used by the CRT composition harness, not every slice example.
    pub(crate) fn normal_object_check(&self) -> String {
        format!(
            r#"
impl ThreadContext {{fn original_check(&self,owner:u64,selector:u32)->Result<(),&'static str>{{{body}}}}}
impl CrtNormalObjects {{
 fn check_prefix_context(&self,frame:&CrtLiveFrame<'_,'_>)->RegistryResult<()>{{self.check_original_context(frame.event,frame.rt,frame.epoch)}}
 fn check_original_context(&self,event:&CrtNormalException,rt:&CrtStreamRuntime,epoch:&NormalCallEpoch<'_>)->RegistryResult<()>{{
  self.validate(event,rt,epoch)?;
  let selector=rt.load(rt.resolve_absolute({selector},CrtRegionKind::Module)?,32)?.known_scalar()?;
  let captured=ThreadContext::new(self.identity.owner,epoch.registry.limit,epoch.registry.base,self.captured_esp)?;
  captured.original_check(self.identity.owner,selector)
 }}
}}
{prefix}
impl CrtNormalException {{
 fn execute_context_checked_handler<F>(&mut self,objects:&CrtNormalObjects,rt:&mut CrtStreamRuntime,interrupted:&CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&CrtNormalBinding,dispatcher:&mut CrtCpu,continuation:u32,body:F)->RegistryResult<CrtNormalHandlerReturn>
 where F:FnOnce(&mut CrtStreamRuntime,&mut CrtCpu)->RegistryResult<CrtValue>{{
  objects.check_original_context(self,rt,epoch)?;
  self.execute_bound_handler(objects,rt,interrupted,epoch,binding,dispatcher,continuation,body)
 }}
 fn execute_context_checked_live_handler<F>(&mut self,objects:&CrtNormalObjects,rt:&mut CrtStreamRuntime,interrupted:&CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&CrtNormalBinding,dispatcher:&mut CrtCpu,continuation:u32,body:F)->RegistryResult<CrtNormalHandlerReturn>
 where F:FnOnce(&mut CrtLiveFrame<'_,'_>,&mut CrtCpu)->RegistryResult<CrtValue>{{
  objects.check_original_context(self,rt,epoch)?;
  self.execute_live_handler(objects,rt,interrupted,epoch,binding,dispatcher,continuation,body)
 }}
}}
"#,
            body = self.body,
            selector = self.selector_va,
            prefix = self.emit_prefix_call("context_prefix_call", false, false)
        )
    }
    #[allow(dead_code)] // Owned source retains its separate captured-object authority.
    pub(crate) fn owned_prefix_call(&self, name: &str) -> String {
        let helper = self.emit_prefix_call(name, true, false);
        format!(
            r#"impl CrtOwnedPrefixInput{{
 fn check_prefix_context(&self,frame:&CrtOwnedFrameView<'_>)->RegistryResult<()>{{
  self.validate_prefix_source(frame)?;
  let selector=frame.rt.load(frame.rt.resolve_absolute({selector},CrtRegionKind::Module)?,32)?.known_scalar()?;
  let captured=ThreadContext::new(self.identity.owner,frame.registry.limit,frame.registry.base,self.captured_esp)?;
  captured.original_check(self.identity.owner,selector)
 }}
}}
{helper}"#,
            selector = self.selector_va
        )
    }
    #[allow(dead_code)]
    pub fn owned_delivery_prefix_call(&self, name: &str) -> String {
        let helper = self.emit_prefix_call(name, true, true);
        let selector = self.selector_va;
        format!("impl CrtOwnedDeliveryPrefix<'_,'_,'_>{{fn check_prefix_context(&self,frame:&CrtOwnedFrameView<'_>)->RegistryResult<()>{{self.validate_prefix_source(frame)?;let selector=frame.rt.load(frame.rt.resolve_absolute({selector},CrtRegionKind::Module)?,32)?.known_scalar()?;ThreadContext::new(frame.rt.owner,frame.registry.limit,frame.registry.base,self.token.captured_esp)?.original_check(frame.rt.owner,selector)}}}}{helper}")
    }
    fn emit_prefix_call(&self, name: &str, owned: bool, delivery: bool) -> String {
        let (frame_type, object_type) = if owned {
            (
                "CrtOwnedFrameView<'_>",
                if delivery {
                    "CrtOwnedDeliveryPrefix<'_,'_,'_>"
                } else {
                    "CrtOwnedPrefixInput"
                },
            )
        } else {
            ("CrtLiveFrame<'_,'_>", "CrtNormalObjects")
        };
        format!(
            r#"fn {name}(frame:&mut {frame_type},cpu:&mut CrtCpu,objects:&{object_type},continuation:u32)->RegistryResult<()>{{
 frame.validate()?;objects.check_prefix_context(frame)?;
 if frame.rt.load(CrtCpu::pointer(cpu.r[4])?,32)?!=CrtValue::Pointer(objects.context){{return Err("context prefix argument");}}
 let sp=CrtCpu::pointer(cpu.r[4])?;let low=frame.rt.offset(sp,-{depth})?;frame.rt.valid(low,{depth})?;
 frame.stack_range(low.address(),u64::from(sp.address()))?;
 if frame.rt.overlapping_tags(low.address(),{depth}).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_))){{return Err("context temporary protected overlap");}}
 frame.call(cpu,continuation,|f,child|{{objects.check_prefix_context(f)?;child.clobber(CrtValue::Scalar{{bits:0,known:0}});child.finish(f.rt)}})?;Ok(())
}}"#,
            depth = self.temporary_bytes + 4
        )
    }
    pub(crate) fn selector_va(&self) -> u32 {
        self.selector_va
    }
    pub(crate) fn bypass_selector(&self) -> u32 {
        self.bypass_selector
    }
    pub(crate) fn failure_code(&self) -> u32 {
        13
    }
    pub(crate) fn temporary_bytes(&self) -> u32 {
        self.temporary_bytes
    }
}

/// The owner is the containing private activation/thread identity, not a guest
/// integer that authorizes access. Construction is an explicit captured-state
/// boundary: the caller must establish that these are the same live thread's
/// initialized NT_TIB StackLimit/StackBase and x86 CONTEXT Esp fields.
///
/// This component deliberately narrows admission to a valid captured ESP even
/// when the selector would bypass the original bounds test. Invalid boundaries
/// reject before fragment effects; no INT 29 or process termination is emulated.
/// No Rust layout is asserted to match an external TEB/CONTEXT layout.
pub(crate) const EMITTED_TYPES: &str = r#"
struct ThreadContext {
 owner:u64, limit:u32, base:u32, captured_esp:u32, live:bool,
}
impl ThreadContext {
 fn new(owner:u64,limit:u32,base:u32,captured_esp:u32)->Result<Self,&'static str>{
  if owner==0 || limit==0 || limit>=base || captured_esp<limit || captured_esp>base {
   return Err("invalid captured same-thread stack boundary");
  }
  Ok(Self{owner,limit,base,captured_esp,live:true})
 }
 fn preflight(&self,owner:u64)->Result<(),&'static str>{
  if !self.live || owner==0 || owner!=self.owner {
   return Err("stale or foreign captured thread context");
  }
  if self.limit==0 || self.limit>=self.base || self.captured_esp<self.limit || self.captured_esp>self.base {
   return Err("invalid captured same-thread stack boundary");
  }
  Ok(())
 }
 fn invalidate(&mut self){self.live=false;}
}
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scalar {
    Selector,
    Esp,
    Limit,
    Base,
    Constant(u32),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    Unknown,
    Saved(u8),
    Stack(i32),
    Context,
    Teb,
    Number(Scalar),
    Return,
}
#[derive(Clone)]
struct State {
    registers: [Value; 8],
    stack: BTreeMap<i32, Value>,
    sp: i32,
    flags: Option<(Scalar, Scalar)>,
    visited: BTreeSet<u32>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Predicate {
    SelectorEquals(u32),
    EspBelowLimit,
    EspAtMostBase,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Decision {
    Return,
    FailFast13,
    Branch(Predicate, Box<Decision>, Box<Decision>),
}
#[derive(Clone, Copy)]
enum ContextAccess {
    Numeric,
    OpaqueProjection,
}
impl Decision {
    fn source(&self, access: ContextAccess) -> String {
        match self {
            Self::Return => "Ok(())".into(),
            Self::FailFast13 => {
                "Err(\"captured boundary would reach original INT 29 with ECX=13\")".into()
            }
            Self::Branch(predicate, yes, no) => {
                let predicate = match predicate {
                    Predicate::SelectorEquals(value) => format!("selector=={value}u32"),
                    Predicate::EspBelowLimit => match access {
                        ContextAccess::Numeric => "self.captured_esp<self.limit".into(),
                        ContextAccess::OpaqueProjection => {
                            "self.captured_below_limit(owner)?".into()
                        }
                    },
                    Predicate::EspAtMostBase => match access {
                        ContextAccess::Numeric => "self.captured_esp<=self.base".into(),
                        ContextAccess::OpaqueProjection => {
                            "self.captured_at_most_base(owner)?".into()
                        }
                    },
                };
                format!(
                    "if {predicate} {{ {} }} else {{ {} }}",
                    yes.source(access),
                    no.source(access)
                )
            }
        }
    }
}

fn register(register: Register) -> Result<usize, String> {
    match register {
        Register::EAX => Ok(0),
        Register::ECX => Ok(1),
        Register::EDX => Ok(2),
        Register::EBX => Ok(3),
        Register::ESP => Ok(4),
        Register::EBP => Ok(5),
        Register::ESI => Ok(6),
        Register::EDI => Ok(7),
        _ => Err("context helper: partial register".into()),
    }
}
fn number(value: Value) -> Result<Scalar, String> {
    if let Value::Number(value) = value {
        Ok(value)
    } else {
        Err("context helper: scalar provenance".into())
    }
}
fn memory(i: &Instruction, state: &State, selector_va: u32) -> Result<Value, String> {
    if i.memory_index() != Register::None {
        return Err("context helper: indexed address".into());
    }
    let displacement = i.memory_displacement32();
    if i.segment_prefix() == Register::FS {
        if i.memory_base() == Register::None && displacement == 0x18 {
            // Original x86 NT_TIB.Self access. This is a typed thread object,
            // never a host pointer or a Rust structure layout cast.
            return Ok(Value::Teb);
        }
        return Err("context helper: unsupported FS field".into());
    }
    if i.segment_prefix() != Register::None {
        return Err("context helper: segment override".into());
    }
    if i.memory_base() == Register::None {
        return if displacement == selector_va {
            Ok(Value::Number(Scalar::Selector))
        } else {
            Err("context helper: unbound image read".into())
        };
    }
    match state.registers[register(i.memory_base())?] {
        Value::Stack(offset) => {
            let offset = offset
                .checked_add(displacement as i32)
                .ok_or("context helper: stack offset overflow")?;
            if offset % 4 != 0 {
                return Err("context helper: unaligned stack read".into());
            }
            match state.stack.get(&offset) {
                Some(value) if *value != Value::Return => Ok(*value),
                _ => Err("context helper: protected or absent stack read".into()),
            }
        }
        Value::Context if displacement == 0xc4 => Ok(Value::Number(Scalar::Esp)),
        Value::Teb if displacement == 8 => Ok(Value::Number(Scalar::Limit)),
        Value::Teb if displacement == 4 => Ok(Value::Number(Scalar::Base)),
        _ => Err("context helper: object field ownership/bounds".into()),
    }
}
fn operand(i: &Instruction, index: u32, state: &State, selector_va: u32) -> Result<Value, String> {
    match i.op_kind(index) {
        OpKind::Register => Ok(state.registers[register(i.op_register(index))?]),
        OpKind::Memory => memory(i, state, selector_va),
        OpKind::Immediate32 => Ok(Value::Number(Scalar::Constant(i.immediate32()))),
        OpKind::Immediate8to32 => Ok(Value::Number(Scalar::Constant(i.immediate8to32() as u32))),
        _ => Err("context helper: operand form".into()),
    }
}

struct Proof<'a> {
    instructions: &'a BTreeMap<u32, Instruction>,
    selector_va: u32,
    budget: usize,
    covered: BTreeSet<u32>,
    temporary_bytes: u32,
}
impl Proof<'_> {
    fn walk(&mut self, mut pc: u32, mut state: State) -> Result<Decision, String> {
        loop {
            self.budget += 1;
            if self.budget > 128 || !state.visited.insert(pc) {
                return Err("context helper: cycle/path budget".into());
            }
            let i = self
                .instructions
                .get(&pc)
                .ok_or("context helper: instruction-boundary target")?;
            self.covered.insert(pc);
            let next = pc
                .checked_add(i.len() as u32)
                .ok_or("context helper: instruction overflow")?;
            match i.code() {
                Code::Push_r32 | Code::Pushd_imm8 | Code::Pushd_imm32 => {
                    let value = operand(i, 0, &state, self.selector_va)?;
                    if !matches!(value, Value::Saved(_) | Value::Number(Scalar::Constant(_))) {
                        return Err("context helper: unsupported stack value".into());
                    }
                    let sp = state
                        .sp
                        .checked_sub(4)
                        .ok_or("context helper: stack overflow")?;
                    if sp < -16 || state.stack.insert(sp, value).is_some() {
                        return Err("context helper: stack ownership/budget".into());
                    }
                    state.sp = sp;
                    self.temporary_bytes = self.temporary_bytes.max((-sp) as u32);
                    state.registers[4] = Value::Stack(sp);
                }
                Code::Pop_r32 => {
                    let target = register(i.op0_register())?;
                    if target == 4 || state.sp >= 0 {
                        return Err("context helper: protected POP".into());
                    }
                    let value = state
                        .stack
                        .remove(&state.sp)
                        .ok_or("context helper: absent POP")?;
                    if matches!(value,Value::Saved(index) if usize::from(index)!=target) {
                        return Err("context helper: mismatched saved register".into());
                    }
                    state.registers[target] = value;
                    state.sp += 4;
                    state.registers[4] = Value::Stack(state.sp);
                }
                Code::Mov_r32_rm32 | Code::Mov_rm32_r32 if i.op0_kind() == OpKind::Register => {
                    let target = register(i.op0_register())?;
                    if !matches!(target, 0 | 1 | 2 | 5) {
                        return Err("context helper: protected register write".into());
                    }
                    let value = operand(i, 1, &state, self.selector_va)?;
                    if matches!(value, Value::Unknown | Value::Return) {
                        return Err("context helper: unknown/protected MOV".into());
                    }
                    state.registers[target] = value;
                }
                Code::Cmp_rm32_imm32 | Code::Cmp_rm32_imm8 | Code::Cmp_r32_rm32 => {
                    state.flags = Some((
                        number(operand(i, 0, &state, self.selector_va)?)?,
                        number(operand(i, 1, &state, self.selector_va)?)?,
                    ));
                }
                Code::Je_rel8_32 | Code::Jb_rel8_32 | Code::Jbe_rel8_32 => {
                    let predicate = match (i.code(), state.flags) {
                        (Code::Je_rel8_32, Some((Scalar::Selector, Scalar::Constant(value)))) => {
                            Predicate::SelectorEquals(value)
                        }
                        (Code::Jb_rel8_32, Some((Scalar::Esp, Scalar::Limit))) => {
                            Predicate::EspBelowLimit
                        }
                        (Code::Jbe_rel8_32, Some((Scalar::Esp, Scalar::Base))) => {
                            Predicate::EspAtMostBase
                        }
                        _ => {
                            return Err("context helper: unknown or unsupported branch flags".into())
                        }
                    };
                    let yes = self.walk(i.near_branch32(), state.clone())?;
                    let no = self.walk(next, state)?;
                    return Ok(Decision::Branch(predicate, Box::new(yes), Box::new(no)));
                }
                Code::Jmp_rel8_32 | Code::Jmp_rel32_32 => {
                    pc = i.near_branch32();
                    continue;
                }
                Code::Int_imm8 => {
                    if i.immediate8() != 0x29
                        || state.registers[1] != Value::Number(Scalar::Constant(13))
                        || state.sp != -4
                        || state.stack.get(&-4) != Some(&Value::Saved(5))
                    {
                        return Err("context helper: unproved failure/trap contract".into());
                    }
                    return Ok(Decision::FailFast13);
                }
                Code::Retnd => {
                    if state.sp != 0
                        || state.stack != initial_stack()
                        || [3, 5, 6, 7]
                            .into_iter()
                            .any(|index| state.registers[index] != Value::Saved(index as u8))
                    {
                        return Err("context helper: return stack/saved-state contract".into());
                    }
                    return Ok(Decision::Return);
                }
                _ => return Err("context helper: unsupported instruction/effect".into()),
            }
            pc = next;
        }
    }
}
fn initial_stack() -> BTreeMap<i32, Value> {
    BTreeMap::from([(0, Value::Return), (4, Value::Context)])
}

/// Derive the complete selector/bounds/failure decision from original decoded
/// instructions. All selector outcomes are explored; neither file contents nor
/// sampled runtime selector values choose a proof path. Unsupported instructions,
/// target interiors, cycles, changed field widths/offsets and changed failure or
/// saved-state contracts reject before native source is returned.
pub(crate) fn prove_context_check(
    code: &[u8],
    origin: u32,
    selector_va: u32,
) -> Result<ContextCheckProof, String> {
    let end = origin
        .checked_add(u32::try_from(code.len()).map_err(|_| "context helper size")?)
        .ok_or("context helper: code overflow")?;
    let selector_end = selector_va
        .checked_add(4)
        .ok_or("context helper: selector overflow")?;
    if code.is_empty()
        || code.len() > 256
        || origin == 0
        || selector_va == 0
        || !selector_va.is_multiple_of(4)
        || (origin < selector_end && selector_va < end)
    {
        return Err("context helper: code/selector range contract".into());
    }
    let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
    let mut instructions = BTreeMap::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        let offset = (i.ip() as u32 - origin) as usize;
        let first = code[offset];
        let fs_load = first == 0x64
            && i.code() == Code::Mov_r32_rm32
            && i.op1_kind() == OpKind::Memory
            && i.segment_prefix() == Register::FS;
        if i.is_invalid()
            || i.has_lock_prefix()
            || i.has_rep_prefix()
            || i.has_repne_prefix()
            || i.memory_index() != Register::None
            || (i.segment_prefix() != Register::None && !fs_load)
            || (matches!(first, 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67) && !fs_load)
            || instructions.len() >= 64
        {
            return Err("context helper: instruction/prefix/width policy".into());
        }
        // Reject doubled or hidden width/address prefixes on the one FS form.
        if fs_load && (i.len() != 7 || code[offset + 1] != 0x8b) {
            return Err("context helper: exact FS self form".into());
        }
        instructions.insert(i.ip() as u32, i);
    }
    let mut registers = std::array::from_fn(|index| {
        if [3, 5, 6, 7].contains(&index) {
            Value::Saved(index as u8)
        } else {
            Value::Unknown
        }
    });
    registers[4] = Value::Stack(0);
    let mut proof = Proof {
        instructions: &instructions,
        selector_va,
        budget: 0,
        covered: BTreeSet::new(),
        temporary_bytes: 0,
    };
    let decision = proof.walk(
        origin,
        State {
            registers,
            stack: initial_stack(),
            sp: 0,
            flags: None,
            visited: BTreeSet::new(),
        },
    )?;
    if proof.covered.len() != instructions.len() {
        return Err("context helper: unproved or trailing instruction region".into());
    }
    let Decision::Branch(Predicate::SelectorEquals(bypass), _, _) = &decision else {
        return Err("context helper: missing runtime selector decision".into());
    };
    // This structural equality compares decoded effects, not application byte
    // hashes/addresses. Alternative equivalent register moves remain admissible.
    let expected = Decision::Branch(
        Predicate::SelectorEquals(*bypass),
        Box::new(Decision::Return),
        Box::new(Decision::Branch(
            Predicate::EspBelowLimit,
            Box::new(Decision::FailFast13),
            Box::new(Decision::Branch(
                Predicate::EspAtMostBase,
                Box::new(Decision::Return),
                Box::new(Decision::FailFast13),
            )),
        )),
    );
    if decision != expected {
        return Err("context helper: changed selector/bounds/failure decision".into());
    }
    Ok(ContextCheckProof {
        body: format!(
            "self.preflight(owner)?;\n{}\n",
            decision.source(ContextAccess::Numeric)
        ),
        projection_body: format!(
            "self.preflight(owner)?;\n{}\n",
            decision.source(ContextAccess::OpaqueProjection)
        ),
        selector_va,
        bypass_selector: *bypass,
        temporary_bytes: proof.temporary_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const ORIGIN: u32 = 0x402877;
    const SELECTOR: u32 = 0x415128;
    fn code() -> Vec<u8> {
        vec![
            0x55, 0x8b, 0xec, 0x81, 0x3d, 0x28, 0x51, 0x41, 0, 0xf9, 0x1b, 0x40, 0, 0x74, 0x1f,
            0x64, 0x8b, 0x0d, 0x18, 0, 0, 0, 0x8b, 0x45, 8, 0x8b, 0x80, 0xc4, 0, 0, 0, 0x3b, 0x41,
            8, 0x72, 5, 0x3b, 0x41, 4, 0x76, 5, 0x6a, 13, 0x59, 0xcd, 0x29, 0x5d, 0xc3,
        ]
    }
    #[test]
    fn decoded_original_contract_and_relocated_instruction_identity() {
        let proof = prove_context_check(&code(), ORIGIN, SELECTOR).unwrap();
        assert_eq!(proof.selector_va(), SELECTOR);
        assert_eq!(proof.bypass_selector(), 0x401bf9);
        assert_eq!(proof.failure_code(), 13);
        assert!(proof.body().contains("selector==4201465u32"));
        assert!(proof.body().contains("self.captured_esp<=self.base"));
        assert_eq!(
            proof.body(),
            prove_context_check(&code(), 0x1000, SELECTOR)
                .unwrap()
                .body()
        );
        let mut alternate = code();
        alternate[1..3].copy_from_slice(&[0x89, 0xe5]);
        assert_eq!(
            proof.body(),
            prove_context_check(&alternate, ORIGIN, SELECTOR)
                .unwrap()
                .body()
        );
        let mut relocated = code();
        relocated[5..9].copy_from_slice(&0x6000u32.to_le_bytes());
        assert_eq!(
            proof.body(),
            prove_context_check(&relocated, ORIGIN, 0x6000)
                .unwrap()
                .body()
        );
    }
    #[test]
    fn changed_offsets_branches_failure_and_saved_state_reject() {
        for (at, value) in [
            (14, 30),
            (18, 4),
            (24, 12),
            (27, 0xc0),
            (33, 4),
            (35, 4),
            (38, 8),
            (39, 0x72),
            (40, 4),
            (42, 12),
            (43, 0x58),
            (45, 0x28),
            (46, 0x5b),
            (47, 0x90),
        ] {
            let mut bad = code();
            bad[at] = value;
            assert!(
                prove_context_check(&bad, ORIGIN, SELECTOR).is_err(),
                "accepted mutation{at}"
            );
        }
        for end in 0..code().len() {
            assert!(
                prove_context_check(&code()[..end], ORIGIN, SELECTOR).is_err(),
                "truncated{end}"
            );
        }
        assert!(prove_context_check(&code(), u32::MAX - 20, SELECTOR).is_err());
        assert!(prove_context_check(&code(), ORIGIN, ORIGIN + 1).is_err());
        assert!(prove_context_check(&code(), ORIGIN, SELECTOR + 4).is_err());
        for prefix in [0x66, 0x67, 0xf2, 0xf3, 0x64] {
            let mut bytes = vec![prefix];
            bytes.extend(code());
            assert!(prove_context_check(&bytes, ORIGIN, SELECTOR).is_err());
        }
        for suffix in [0x90, 0xcc, 0xc3] {
            let mut bytes = code();
            bytes.push(suffix);
            assert!(prove_context_check(&bytes, ORIGIN, SELECTOR).is_err());
        }
    }
    #[test]
    fn generated_owner_lifetime_and_complete_stack_boundaries() {
        let proof = prove_context_check(&code(), ORIGIN, SELECTOR).unwrap();
        let source = format!(
            r#"{EMITTED_TYPES}
impl ThreadContext {{fn check(&self,owner:u64,selector:u32)->Result<(),&'static str>{{{}}}}}
fn main(){{
 for esp in [0x1000,0x1001,0x1800,0x2000] {{
  let mut context=ThreadContext::new(7,0x1000,0x2000,esp).unwrap();
  for selector in [0,0x401bf9,u32::MAX] {{assert_eq!(context.check(7,selector),Ok(()));}}
  assert!(context.check(8,0x401bf9).is_err());context.invalidate();
  assert!(context.check(7,0).is_err());assert!(context.check(7,0x401bf9).is_err());
 }}
 for esp in [0,0xfff,0x2001,u32::MAX] {{assert!(ThreadContext::new(7,0x1000,0x2000,esp).is_err());}}
 for (owner,low,high,esp) in [(0,1,2,1),(7,0,2,1),(7,2,1,1),(7,1,1,1)] {{
  assert!(ThreadContext::new(owner,low,high,esp).is_err());
 }}
 let context=ThreadContext::new(7,1,u32::MAX,u32::MAX).unwrap();
 assert_eq!(context.check(7,0),Ok(()));
}}
"#,
            proof.body()
        );
        let directory =
            std::env::temp_dir().join(format!("w2l-context-boundary-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("run.rs");
        let binary = directory.join(if cfg!(windows) { "run.exe" } else { "run" });
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

    #[test]
    fn original_decision_distinguishes_selector_bypass_from_fail_fast() {
        let proof = prove_context_check(&code(), ORIGIN, SELECTOR).unwrap();
        // Exercise only the decoded decision in this test, including states
        // deliberately excluded by the production constructor/preflight. This
        // makes the stronger entry restriction visible instead of claiming the
        // original selector bypass itself rejects every invalid ESP.
        let original = proof
            .body()
            .strip_prefix("self.preflight(owner)?;\n")
            .unwrap();
        let source = format!(
            r#"{EMITTED_TYPES}
impl ThreadContext {{fn original_decision(&self,selector:u32)->Result<(),&'static str>{{{original}}}}}
fn main(){{
 for (esp,inside) in [(0,false),(0xfff,false),(0x1000,true),(0x1001,true),(0x2000,true),(0x2001,false),(u32::MAX,false)] {{
  let raw=ThreadContext{{owner:7,limit:0x1000,base:0x2000,captured_esp:esp,live:true}};
  assert_eq!(raw.original_decision(0x401bf9),Ok(()));
  for selector in [0,0x401bf8,0x401bfa,u32::MAX] {{
   let observed=raw.original_decision(selector);
   assert_eq!(observed.is_ok(),inside,"ESP={{esp:#x}}, selector={{selector:#x}}");
   if !inside {{assert!(observed.unwrap_err().contains("INT 29 with ECX=13"));}}
  }}
 }}
}}
"#
        );
        let directory = std::env::temp_dir().join(format!(
            "w2l-context-original-decision-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("run.rs");
        let binary = directory.join(if cfg!(windows) { "run.exe" } else { "run" });
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

    #[test]
    fn opaque_projection_preserves_predicate_order_and_owner_preflight() {
        let proof = prove_context_check(&code(), ORIGIN, SELECTOR).unwrap();
        let body = proof.projection_body();
        assert!(body.contains("selector==4201465u32"));
        assert!(!body.contains("captured_esp"));
        assert!(!body.contains("self.limit"));
        assert!(!body.contains("self.base"));
        // This deliberately adversarial test provider can return all four
        // predicate combinations. It is not the production capability, whose
        // constructor narrows admission to a live same-thread valid stack.
        // Independent expected truth values and access order catch accidental
        // constant folding, reversed edges and selector bypass of preflight.
        let source = format!(
            r#"
struct Opaque {{owner:u64,live:bool,below:bool,at_most:bool,fail_query:bool,reads:std::cell::RefCell<Vec<u8>>}}
impl Opaque {{
 fn preflight(&self,owner:u64)->Result<(),&'static str>{{
  self.reads.borrow_mut().push(0);
  if !self.live||owner==0||owner!=self.owner{{Err("identity")}}else{{Ok(())}}
 }}
 fn captured_below_limit(&self,_owner:u64)->Result<bool,&'static str>{{
  self.reads.borrow_mut().push(1);if self.fail_query{{Err("query")}}else{{Ok(self.below)}}
 }}
 fn captured_at_most_base(&self,_owner:u64)->Result<bool,&'static str>{{
  self.reads.borrow_mut().push(2);if self.fail_query{{Err("query")}}else{{Ok(self.at_most)}}
 }}
 fn check(&self,owner:u64,selector:u32)->Result<(),&'static str>{{{body}}}
}}
fn main(){{
 for (below,at_most,accepted,reads) in [
  (false,true,true,vec![0,1,2]),(false,false,false,vec![0,1,2]),
  (true,true,false,vec![0,1]),(true,false,false,vec![0,1])
 ] {{
  for selector in [0u32,0x401bf8,0x401bfa,u32::MAX] {{
   let p=Opaque{{owner:7,live:true,below,at_most,fail_query:false,reads:Default::default()}};
   assert_eq!(p.check(7,selector).is_ok(),accepted);assert_eq!(*p.reads.borrow(),reads);
  }}
  let p=Opaque{{owner:7,live:true,below,at_most,fail_query:false,reads:Default::default()}};
  assert_eq!(p.check(7,0x401bf9),Ok(()));assert_eq!(*p.reads.borrow(),vec![0]);
 }}
 for (owner,live) in [(0,true),(8,true),(7,false)] {{
  for selector in [0u32,0x401bf9] {{
   let p=Opaque{{owner:7,live,below:false,at_most:true,fail_query:false,reads:Default::default()}};
   assert_eq!(p.check(owner,selector),Err("identity"));assert_eq!(*p.reads.borrow(),vec![0]);
  }}
 }}
 let p=Opaque{{owner:7,live:true,below:false,at_most:true,fail_query:true,reads:Default::default()}};
 assert_eq!(p.check(7,0),Err("query"));assert_eq!(*p.reads.borrow(),vec![0,1]);
}}
"#
        );
        let directory = std::env::temp_dir().join(format!(
            "w2l-context-opaque-projection-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("run.rs");
        let binary = directory.join(if cfg!(windows) { "run.exe" } else { "run" });
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

    #[test]
    fn opaque_projection_cannot_admit_other_captured_context_fields() {
        for offset in [0u32, 0xac, 0xb0, 0xb8, 0xc0] {
            let mut bytes = code();
            // Original MOV EAX,[EAX+0xc4] is the captured ESP load. ContextFlags,
            // ECX, EAX, EIP and EFlags are not observations of the projection.
            bytes[27..31].copy_from_slice(&offset.to_le_bytes());
            assert!(
                prove_context_check(&bytes, ORIGIN, SELECTOR).is_err(),
                "unexpected captured field {offset:#x}"
            );
        }
    }
}
