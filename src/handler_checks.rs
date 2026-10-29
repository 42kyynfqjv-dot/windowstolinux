//! Instruction-derived contract for the original x86 handler prefix.
//!
//! This verifies data flow, not Windows exception delivery. Calls require the
//! separately verified cdecl helper effects. Search fallthrough reaches the
//! installer; the owned-delivery body stops at the original unwind branch.
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, OpKind, Register};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Bindings {
    pub normalizer_va: u32,
    pub guard_va: u32,
    pub context_va: u32,
    pub cookie_va: u32,
    pub installer_va: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallEffect {
    NormalizeRecordCode,
    ValidateGuards,
    ValidateContext,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CallSite {
    pub va: u32,
    pub target: u32,
    pub effect: CallEffect,
    /// Arguments in callee order, independently established from pushed tags.
    pub arguments: Vec<&'static str>,
    /// Bytes below original handler-entry ESP at callee entry (includes return).
    pub entry_depth: u32,
}
#[derive(Clone, Debug)]
pub(crate) struct PrefixProof {
    #[allow(dead_code)]
    pub(crate) front: String,
    pub(crate) caller: String,
    #[allow(dead_code)] // Owned-delivery backend is not used by legacy slice examples.
    pub(crate) unwind_caller: String,
    #[allow(dead_code)] // Owned CRT entry binding; other slice emitters use call sites.
    pub(crate) entry: u32,
    pub calls: Vec<CallSite>,
    pub exception_flags_mask: u8,
    pub exception_flags_branch: u32,
    pub installer_start: u32,
    pub end: u32,
    pub handler_allocation: u32,
    pub temporary_bytes: u32,
    pub owner_pair_offset: i32,
    pub handler_pair_offset: i32,
}
impl PrefixProof {
    #[allow(dead_code)]
    pub fn caller_body(&self) -> &str {
        &self.caller
    }
    #[allow(dead_code)]
    pub fn normalizer_front(&self) -> &str {
        &self.front
    }
    /// Full zero flags is the admitted incoming domain, even though the code
    /// tests a subset. A nonzero flag is never silently interpreted as search.
    pub fn require_search_flags(&self, flags: u32) -> Result<(), String> {
        if flags != 0 {
            return Err("handler prefix unwind/other flags outside proved domain".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Unknown,
    Saved(Register),
    EntrySp,
    Frame(i32),
    Record,
    Establisher,
    Context,
    Owner(i32),
    EncodedTable,
    Table,
    Cookie,
    Code,
    NormalizedCode,
    Level,
    Constant(u32),
}
fn register(r: Register) -> Result<usize, String> {
    match r {
        Register::EAX => Ok(0),
        Register::ECX => Ok(1),
        Register::EDX => Ok(2),
        Register::EBX => Ok(3),
        Register::ESP => Ok(4),
        Register::EBP => Ok(5),
        Register::ESI => Ok(6),
        Register::EDI => Ok(7),
        _ => Err("handler prefix unsupported register/width".into()),
    }
}
fn memory(i: &Instruction, regs: &[Value; 8]) -> Result<(Value, i32), String> {
    if i.memory_index() != Register::None || i.segment_prefix() != Register::None {
        return Err("handler prefix indexed/segmented address".into());
    }
    let offset = i.memory_displacement32() as i32;
    if i.memory_base() == Register::None {
        return Ok((Value::Constant(i.memory_displacement32()), 0));
    }
    Ok((regs[register(i.memory_base())?].clone(), offset))
}
fn read(
    i: &Instruction,
    regs: &[Value; 8],
    _locals: &BTreeMap<i32, Value>,
    cookie: u32,
) -> Result<Value, String> {
    let (base, offset) = memory(i, regs)?;
    match (base, offset) {
        (Value::Frame(0), 8) => Ok(Value::Record),
        (Value::Frame(0), 12) => Ok(Value::Establisher),
        (Value::Frame(0), 16) => Ok(Value::Context),
        (Value::Frame(0), o) if o < 0 => Err("handler prefix unsupported local read width".into()),
        (Value::Record, 0) => Ok(Value::Code),
        (Value::Establisher, 8) => Ok(Value::EncodedTable),
        (Value::Establisher, 12) => Ok(Value::Level),
        (Value::Constant(va), 0) if va == cookie => Ok(Value::Cookie),
        _ => Err("handler prefix unowned read".into()),
    }
}
/// Bounded symbolic execution of each admitted original instruction. Values
/// preserve record/context/owner identity; no numeric guest pointer substitutes
/// for a tag. The caller must execute all three proven helper effects in order.
pub(crate) fn prove_prefix(code: &[u8], origin: u32, b: &Bindings) -> Result<PrefixProof, String> {
    let end = origin
        .checked_add(u32::try_from(code.len()).map_err(|_| "prefix length")?)
        .ok_or("prefix overflow")?;
    if code.is_empty()
        || code.len() > 512
        || origin == 0
        || !(origin..end).contains(&b.installer_va)
        || [b.normalizer_va, b.guard_va, b.context_va, b.cookie_va].contains(&0)
    {
        return Err("handler prefix bindings/range".into());
    }
    let mut regs = std::array::from_fn(|n| {
        Value::Saved(
            [
                Register::EAX,
                Register::ECX,
                Register::EDX,
                Register::EBX,
                Register::ESP,
                Register::EBP,
                Register::ESI,
                Register::EDI,
            ][n],
        )
    });
    regs[4] = Value::EntrySp;
    let mut stack = BTreeMap::new();
    let mut locals = BTreeMap::new();
    let mut local_widths = BTreeMap::new();
    let mut sp = 0i32;
    let mut lowest = 0i32;
    let mut framed = false;
    let mut allocated = 0u32;
    let mut calls = Vec::new();
    let mut writeback = false;
    let mut level = false;
    let mut flag_test = false;
    let mut flag_branch = None;
    let mut pair_installed = false;
    let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
    let mut count = 0;
    let mut front = String::new();
    let mut front_end = None;
    let mut unwind_caller = None;
    while decoder.can_decode() {
        let i = decoder.decode();
        count += 1;
        if count > 96
            || i.is_invalid()
            || i.has_lock_prefix()
            || i.has_rep_prefix()
            || i.has_repne_prefix()
            || i.segment_prefix() != Register::None
        {
            return Err("handler prefix invalid/prefixed instruction".into());
        }
        if i.ip() >= u64::from(b.installer_va) && flag_branch.is_none() {
            return Err("handler installer reached without flags proof".into());
        }
        if flag_test && flag_branch.is_none() && i.code() != Code::Jne_rel8_32 {
            return Err("handler flags clobbered before branch".into());
        }
        if flag_branch.is_some()
            && !matches!(
                i.code(),
                Code::Mov_rm32_r32 | Code::Mov_r32_rm32 | Code::Lea_r32_m
            )
        {
            return Err("handler installer additional effect".into());
        }
        {
            let r = |reg| register(reg);
            let addr = || -> Result<String, String> {
                let base = if i.memory_base() == Register::None {
                    "None".into()
                } else {
                    format!("Some({})", r(i.memory_base())?)
                };
                Ok(format!(
                    "cpu.address(frame.rt,{base},None,1,{}, {})?",
                    i.memory_displacement32(),
                    if i.memory_base() == Register::None {
                        "Some(CrtRegionKind::Module)"
                    } else {
                        "None"
                    }
                ))
            };
            let statement=match i.code(){
             Code::Push_r32=>format!("cpu.push(frame.rt,cpu.r[{}])?;",r(i.op0_register())?),
             Code::Push_rm32 if i.op0_kind()==OpKind::Register=>format!("cpu.push(frame.rt,cpu.r[{}])?;",r(i.op0_register())?),
             Code::Push_rm32=>format!("let v=frame.rt.load({},32)?;cpu.push(frame.rt,v)?;",addr()?),
             Code::Mov_r32_rm32|Code::Mov_rm32_r32 if i.op0_kind()==OpKind::Register&&i.op1_kind()==OpKind::Register=>format!("cpu.r[{}]=cpu.r[{}];",r(i.op0_register())?,r(i.op1_register())?),
             Code::Sub_rm32_imm8 if i.op0_register()==Register::ESP=>format!("cpu.r[4]=CrtValue::Pointer(frame.rt.offset(CrtCpu::pointer(cpu.r[4])?,-{})?);cpu.flags=CrtFlags::unknown();",i.immediate8to32()),
             Code::Mov_r32_rm32=>format!("cpu.r[{}]=frame.rt.load({},32)?;",r(i.op0_register())?,addr()?),
             Code::Mov_rm32_r32=>format!("frame.rt.store({},32,cpu.r[{}])?;",addr()?,r(i.op1_register())?),
             Code::Mov_rm32_imm32=>format!("frame.rt.store({},32,CrtValue::scalar({}))?;",addr()?,i.immediate32()),
             Code::Mov_rm8_imm8=>format!("frame.rt.store({},8,CrtValue::scalar({}))?;",addr()?,i.immediate8()),
             Code::Call_rel32_32 if i.near_branch32()==b.normalizer_va=>format!("normalizer_prefix_call(frame,cpu,objects,{})?;",i.next_ip32()),
             Code::Call_rel32_32 if i.near_branch32()==b.guard_va=>format!("guard_prefix_call(frame,cpu,{})?;",i.next_ip32()),
             Code::Call_rel32_32 if i.near_branch32()==b.context_va=>format!("context_prefix_call(frame,cpu,objects,{})?;",i.next_ip32()),
             Code::Lea_r32_m=>format!("cpu.r[{}]=CrtValue::Pointer({});",r(i.op0_register())?,addr()?),
             Code::Xor_r32_rm32=>format!("let v=cpu.binary(frame.rt,3,cpu.r[{}],frame.rt.load({},32)?,32)?;if v.known_scalar()?!=frame.scope_address(){{return Err(\"prefix table decode provenance\");}}cpu.r[{}]=CrtValue::Pointer(frame.rt.resolve_absolute(frame.scope_address(),CrtRegionKind::Module)?);",r(i.op0_register())?,addr()?,r(i.op0_register())?),
             Code::Add_rm32_imm8 if i.op0_register()==Register::ESP=>format!("cpu.discard(frame.rt,{})?;cpu.flags=CrtFlags::unknown();",i.immediate8to32()),
             Code::Test_rm8_imm8=>format!("cpu.binary(frame.rt,8,frame.rt.load({},8)?,CrtValue::scalar({}),8)?;",addr()?,i.immediate8()),
             Code::Jne_rel8_32=>"if cpu.condition(1)?{return Err(\"prefix flags delivery outside search domain\");}".into(),
             _=>return Err("prefix live front unsupported instruction".into()),
            };
            if i.code() == Code::Jne_rel8_32 {
                unwind_caller=Some(format!("{front}if !cpu.condition(1)?{{return Err(\"prefix requires owned unwind flags\");}}return Ok({}u32);",i.near_branch32()));
            }
            front.push_str(&statement);
            front.push('\n');
        }
        match i.code() {
            Code::Push_r32 | Code::Push_rm32 => {
                let value = if i.op0_kind() == OpKind::Register {
                    regs[register(i.op0_register())?].clone()
                } else {
                    read(&i, &regs, &locals, b.cookie_va)?
                };
                if value == Value::Unknown {
                    return Err("handler prefix unknown push".into());
                }
                sp = sp.checked_sub(4).ok_or("handler stack overflow")?;
                if sp < -128 || stack.insert(sp, value).is_some() {
                    return Err("handler stack overlap/budget".into());
                }
            }
            Code::Mov_r32_rm32 | Code::Mov_rm32_r32
                if i.op0_kind() == OpKind::Register && i.op1_kind() == OpKind::Register =>
            {
                let dst = register(i.op0_register())?;
                let src = register(i.op1_register())?;
                if dst == 5
                    && src == 4
                    && !framed
                    && sp == -4
                    && stack.get(&-4) == Some(&Value::Saved(Register::EBP))
                {
                    framed = true;
                    sp = 0;
                    stack.clear();
                    stack.insert(0, Value::Saved(Register::EBP));
                    regs[5] = Value::Frame(0);
                } else {
                    if dst == 4 || dst == 5 {
                        return Err("handler frame register overwrite".into());
                    }
                    regs[dst] = regs[src].clone();
                }
            }
            Code::Sub_rm32_imm8 if i.op0_register() == Register::ESP => {
                if !framed || allocated != 0 || sp != 0 || i.immediate8to32() != 28 {
                    return Err("handler local allocation".into());
                }
                allocated = 28;
                sp = -28;
            }
            Code::Mov_r32_rm32 if i.op1_kind() == OpKind::Memory => {
                let dst = register(i.op0_register())?;
                if dst == 4 || dst == 5 {
                    return Err("handler protected register load".into());
                }
                regs[dst] = read(&i, &regs, &locals, b.cookie_va)?;
                if regs[dst] == Value::Level {
                    level = true;
                }
            }
            Code::Lea_r32_m => {
                let dst = register(i.op0_register())?;
                if dst == 4 || dst == 5 {
                    return Err("handler frame address overwrite".into());
                }
                regs[dst] = match memory(&i, &regs)? {
                    (Value::Establisher, 16) => Value::Owner(0),
                    (Value::Frame(0), -28)
                        if locals.get(&-28) == Some(&Value::Record)
                            && locals.get(&-24) == Some(&Value::Context) =>
                    {
                        Value::Frame(-28)
                    }
                    _ => return Err("handler unowned address construction".into()),
                };
            }
            Code::Xor_r32_rm32 => {
                let dst = register(i.op0_register())?;
                if regs[dst] != Value::EncodedTable
                    || read(&i, &regs, &locals, b.cookie_va)? != Value::Cookie
                {
                    return Err("handler scope decode provenance".into());
                }
                regs[dst] = Value::Table;
            }
            Code::Mov_rm32_r32 | Code::Mov_rm32_imm32 | Code::Mov_rm8_imm8
                if i.op0_kind() == OpKind::Memory =>
            {
                let width = if i.code() == Code::Mov_rm8_imm8 { 1 } else { 4 };
                let value = if i.code() == Code::Mov_rm32_r32 {
                    regs[register(i.op1_register())?].clone()
                } else if width == 1 {
                    Value::Constant(u32::from(i.immediate8()))
                } else {
                    Value::Constant(i.immediate32())
                };
                match memory(&i, &regs)? {
                    (Value::Frame(0), offset)
                        if offset >= -(allocated as i32) && offset + width <= 0 =>
                    {
                        if value == Value::Unknown
                            || local_widths
                                .iter()
                                .any(|(&a, &w)| offset < a + w && a < offset + width)
                        {
                            return Err("handler local alias/unknown write".into());
                        }
                        if i.ip() >= u64::from(b.installer_va)
                            && !matches!(
                                (offset, &value),
                                (-28, Value::Record) | (-24, Value::Context)
                            )
                        {
                            return Err("handler installer local effect".into());
                        }
                        locals.insert(offset, value);
                        local_widths.insert(offset, width);
                    }
                    (Value::Record, 0)
                        if width == 4
                            && value == Value::NormalizedCode
                            && calls.len() == 1
                            && !writeback =>
                    {
                        writeback = true;
                        front_end = Some(front.len());
                    }
                    (Value::Establisher, -4)
                        if width == 4
                            && value == Value::Frame(-28)
                            && flag_branch.is_some()
                            && !pair_installed =>
                    {
                        pair_installed = true;
                    }
                    _ => return Err("handler prefix unowned/protected write".into()),
                }
            }
            Code::Call_rel32_32 => {
                if i.ip() >= u64::from(b.installer_va) {
                    return Err("handler installer unexpected call".into());
                }
                let target = i.near_branch32();
                let (expected, effect, args) = match calls.len() {
                    0 if stack.get(&sp) == Some(&Value::Code) => (
                        b.normalizer_va,
                        CallEffect::NormalizeRecordCode,
                        vec!["record.code"],
                    ),
                    1 if writeback
                        && stack.get(&sp) == Some(&Value::Table)
                        && stack.get(&(sp + 4)) == Some(&Value::Owner(0)) =>
                    {
                        (
                            b.guard_va,
                            CallEffect::ValidateGuards,
                            vec!["decoded_table", "owner_frame"],
                        )
                    }
                    2 if stack.get(&sp) == Some(&Value::Context) => {
                        (b.context_va, CallEffect::ValidateContext, vec!["context"])
                    }
                    _ => return Err("handler call argument/order proof".into()),
                };
                if target != expected {
                    return Err("handler call target binding".into());
                }
                calls.push(CallSite {
                    va: i.ip() as u32,
                    target,
                    effect,
                    arguments: args,
                    entry_depth: u32::try_from(-(sp - 8))
                        .map_err(|_| "handler call stack depth")?,
                });
                lowest = lowest.min(sp - 8); // EBP=entry ESP-4; transient CALL return adds4.
                regs[0] = if calls.len() == 1 {
                    Value::NormalizedCode
                } else {
                    Value::Unknown
                };
                regs[1] = Value::Unknown;
                regs[2] = Value::Unknown;
            }
            Code::Add_rm32_imm8 if i.op0_register() == Register::ESP => {
                if calls.len() != 3 || i.immediate8to32() != 16 || sp != -56 {
                    return Err("handler argument cleanup".into());
                }
                for at in (sp..sp + 16).step_by(4) {
                    if stack.remove(&at).is_none() {
                        return Err("handler cleanup crosses ownership".into());
                    }
                }
                sp += 16;
            }
            Code::Test_rm8_imm8 => {
                if memory(&i, &regs)? != (Value::Record, 4)
                    || i.immediate8() != 0x66
                    || calls.len() != 3
                    || !writeback
                    || !level
                    || flag_test
                {
                    return Err("handler exception flag test".into());
                }
                flag_test = true;
            }
            Code::Jne_rel8_32 => {
                if !flag_test
                    || flag_branch.is_some()
                    || i.next_ip() != u64::from(b.installer_va)
                    || (origin..end).contains(&i.near_branch32())
                {
                    return Err("handler exception branch/installer boundary".into());
                }
                flag_branch = Some(i.near_branch32());
            }
            _ => return Err(format!("handler prefix unsupported effect {:?}", i.code())),
        }
        lowest = lowest.min(if framed { sp - 4 } else { sp });
    }
    let required = [
        (-1, Value::Constant(0)),
        (-12, Value::Constant(1)),
        (-16, Value::Owner(0)),
        (-8, Value::Table),
        (-28, Value::Record),
        (-24, Value::Context),
    ];
    if calls.len() != 3
        || !pair_installed
        || sp != -40
        || allocated != 28
        || !writeback
        || !level
        || required.iter().any(|(o, v)| locals.get(o) != Some(v))
        || locals.len() != required.len()
        || regs[0] != Value::Frame(-28)
        || regs[3] != Value::Establisher
        || regs[5] != Value::Frame(0)
        || regs[6] != Value::Owner(0)
        || regs[7] != Value::Level
        || stack.get(&0) != Some(&Value::Saved(Register::EBP))
        || stack.get(&-32) != Some(&Value::Saved(Register::EBX))
        || stack.get(&-36) != Some(&Value::Saved(Register::ESI))
        || stack.get(&-40) != Some(&Value::Saved(Register::EDI))
    {
        return Err("handler prefix incomplete saved-state/effect contract".into());
    }
    Ok(PrefixProof {
        front: front[..front_end.ok_or("prefix missing live front")?].into(),
        caller: front,
        unwind_caller: unwind_caller.ok_or("prefix missing unwind edge")?,
        entry: origin,
        calls,
        exception_flags_mask: 0x66,
        exception_flags_branch: flag_branch.ok_or("handler flags branch absent")?,
        installer_start: b.installer_va,
        end,
        handler_allocation: allocated,
        temporary_bytes: u32::try_from(-lowest).map_err(|_| "handler temporary extent")?,
        owner_pair_offset: -20,
        handler_pair_offset: -28,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Vec<u8>, Bindings) {
        // Independently specified x86 cdecl handler flow; synthetic addresses
        // avoid coupling expected tags to original PE addresses or hash.
        let mut bytes = vec![
            0x55, 0x8b, 0xec, 0x83, 0xec, 0x1c, 0x53, 0x8b, 0x5d, 8, 0x56, 0x57, 0xc6, 0x45, 0xff,
            0, 0xff, 0x33, 0xc7, 0x45, 0xf4, 1, 0, 0, 0,
        ];
        fn call(bytes: &mut Vec<u8>, target: u32) {
            let next = 0x1000 + bytes.len() as u32 + 5;
            bytes.push(0xe8);
            bytes.extend_from_slice(&target.wrapping_sub(next).to_le_bytes());
        }
        call(&mut bytes, 0x3000);
        bytes.extend_from_slice(&[
            0x89, 3, 0x8b, 0x5d, 12, 0x8b, 0x43, 8, 0x8d, 0x73, 16, 0x33, 5, 0, 0x80, 0, 0, 0x56,
            0x50, 0x89, 0x75, 0xf0, 0x89, 0x45, 0xf8,
        ]);
        call(&mut bytes, 0x4000);
        bytes.extend_from_slice(&[0xff, 0x75, 16]);
        call(&mut bytes, 0x5000);
        bytes.extend_from_slice(&[
            0x8b, 0x45, 8, 0x83, 0xc4, 16, 0x8b, 0x7b, 12, 0xf6, 0x40, 4, 0x66, 0x75, 0x5a,
        ]);
        let installer_va = 0x1000 + bytes.len() as u32;
        bytes.extend_from_slice(&[
            0x89, 0x45, 0xe4, 0x8b, 0x45, 16, 0x89, 0x45, 0xe8, 0x8d, 0x45, 0xe4, 0x89, 0x43, 0xfc,
        ]);
        (
            bytes,
            Bindings {
                normalizer_va: 0x3000,
                guard_va: 0x4000,
                context_va: 0x5000,
                cookie_va: 0x8000,
                installer_va,
            },
        )
    }
    #[test]
    fn original_flow_binds_arguments_order_and_flag_boundary() {
        let (bytes, b) = fixture();
        let p = prove_prefix(&bytes, 0x1000, &b).unwrap();
        assert_eq!(
            p.calls.iter().map(|c| c.effect).collect::<Vec<_>>(),
            vec![
                CallEffect::NormalizeRecordCode,
                CallEffect::ValidateGuards,
                CallEffect::ValidateContext
            ]
        );
        assert_eq!(p.calls[1].arguments, vec!["decoded_table", "owner_frame"]);
        assert_eq!(p.exception_flags_mask, 0x66);
        assert_eq!(p.installer_start, b.installer_va);
        assert_eq!(p.end, 0x1000 + bytes.len() as u32);
        assert_eq!(p.handler_allocation, 28);
        assert_eq!(p.temporary_bytes, 64);
        assert_eq!(
            p.calls.iter().map(|c| c.entry_depth).collect::<Vec<_>>(),
            vec![52, 60, 64]
        );
        assert_eq!((p.owner_pair_offset, p.handler_pair_offset), (-20, -28));
        assert_eq!(p.exception_flags_branch, b.installer_va + 0x5a);
        assert!(p.require_search_flags(0).is_ok());
        for flags in [1, 2, 4, 0x20, 0x40, 0x80, 0x100, u32::MAX] {
            assert!(p.require_search_flags(flags).is_err());
        }
    }
    #[test]
    fn wrong_call_cookie_and_installer_bindings_reject() {
        let (bytes, b) = fixture();
        for field in 0..5 {
            let mut bad = b;
            match field {
                0 => bad.normalizer_va += 4,
                1 => bad.guard_va += 4,
                2 => bad.context_va += 4,
                3 => bad.cookie_va += 4,
                _ => bad.installer_va += 1,
            };
            assert!(prove_prefix(&bytes, 0x1000, &bad).is_err());
        }
        for length in 0..bytes.len() {
            assert!(
                prove_prefix(&bytes[..length], 0x1000, &b).is_err(),
                "truncation {length}"
            );
        }
    }
    #[test]
    fn protected_slots_pointer_confusion_and_branch_mutations_reject() {
        let (bytes, b) = fixture();
        // Mutation offsets are instruction fields in the independent byte
        // specification, covering wrong record/context/cookie/owner relations.
        for (offset, value) in [
            (9, 12),
            (17, 0x73),
            (31, 0x0b),
            (37, 12),
            (40, 12),
            (57, 0xf4),
            (62, 12),
            (73, 12),
            (76, 8),
            (80, 0x20),
            (81, 0x74),
            (82, 0),
            (85, 0),
            (88, 8),
            (91, 0xe4),
            (94, 0xe8),
            (97, 0),
        ] {
            let mut bad = bytes.clone();
            bad[offset] = value;
            assert!(
                prove_prefix(&bad, 0x1000, &b).is_err(),
                "mutation at {offset}"
            );
        }
    }
    #[test]
    fn volatile_result_and_unknown_instruction_do_not_gain_tags() {
        let (bytes, b) = fixture();
        let mut bad = bytes.clone();
        bad[30] = 0x89;
        bad[31] = 0x0b; // write volatile ECX instead of normalized EAX
        assert!(prove_prefix(&bad, 0x1000, &b).is_err());
        let mut bad = bytes.clone();
        bad[0] = 0x90;
        assert!(prove_prefix(&bad, 0x1000, &b).is_err());
        let mut bad = bytes.clone();
        bad.extend_from_slice(&[0x90]);
        assert!(prove_prefix(&bad, 0x1000, &b).is_err());
    }
}
