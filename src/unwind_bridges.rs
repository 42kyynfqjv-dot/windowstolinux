//! Instruction-derived x86 helper bridges. These certificates do not authorize
//! guest addresses. The enclosing proof binds opaque target/frame/module tokens
//! and supplies the callee and RtlUnwind continuation contracts.
use super::graph::{self, Binary, Operand, Operation, Reg};
use iced_x86::{Code, Decoder, DecoderOptions, OpKind};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Symbol {
    EntryRegister(u8),
    StackOffset(i32),
    Argument(u8),
    Constant(u32),
    Unknown,
    CallResult(u8),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallKind {
    Filter,
    Cleanup,
    Notification,
    GlobalUnwind,
}
#[derive(Clone, Debug)]
pub(crate) struct CallEffect {
    pub kind: CallKind,
    pub target: Symbol,
    pub registers: [Symbol; 8],
    pub arguments: Vec<Symbol>,
    pub continuation: Option<u32>,
    pub entry_depth: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StoreEffect {
    pub address: u32,
    pub value: Symbol,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Exit {
    Return { cleanup: u32 },
    Jump(Symbol),
}
#[derive(Clone, Copy)]
pub(crate) struct NotificationBinding {
    pub target_word: u32,
    pub action_word: u32,
    pub frame_word: u32,
}
pub(crate) struct BridgeProof {
    pub calls: Vec<CallEffect>,
    pub stores: Vec<StoreEffect>,
    pub exit: Exit,
    pub origin: u32,
    pub registers: [Symbol; 8],
    pub temporary_bytes: u32,
    body: String,
}
impl BridgeProof {
    pub fn body(&self) -> &str {
        &self.body
    }
}

/// Generic packets contain capabilities supplied by the enclosing proof. A
/// Scalar or PrivateStack label is never a callable capability. The callback
/// must check target/frame/module identity and execute the bound original body.
/// ESP labels are relative to bridge entry, not host pointers. A normal callee
/// reply represents its completed RET; global unwind requires the specific
/// original continuation and consumed arguments. Unexpected outcomes reject.
pub(crate) const EMITTED_TYPES: &str = r#"
#[derive(Clone,Debug,PartialEq,Eq)]
enum BridgeValue<T>{Unknown,Scalar(u32),Capability(T),PrivateStack(i32)}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum BridgeCall{Filter,Cleanup,Notification,GlobalUnwind}
struct BridgeReply<T>{registers:[BridgeValue<T>;8],resume:Option<u32>}
enum BridgeExit<T>{Return{registers:[BridgeValue<T>;8],cleanup:u32},Jump{registers:[BridgeValue<T>;8],target:BridgeValue<T>}}
"#;

#[derive(Clone, Copy)]
enum Mode {
    Filter,
    Cleanup,
    Notification(NotificationBinding),
    Selected { notification: u32 },
    Global { iat: u32 },
}
fn full(r: Reg) -> Result<usize, String> {
    if r.width == 32 && r.shift == 0 {
        Ok(r.index as usize)
    } else {
        Err("bridge: partial register".into())
    }
}
struct State {
    registers: [Symbol; 8],
    stack: BTreeMap<i32, Symbol>,
    sp: i32,
    source: String,
    calls: Vec<CallEffect>,
    stores: Vec<StoreEffect>,
    depth: u32,
}
impl State {
    fn new(argument: bool) -> Self {
        let mut stack = BTreeMap::new();
        if argument {
            stack.insert(4, Symbol::Argument(0));
        }
        Self{registers:std::array::from_fn(|i|if i==4{Symbol::StackOffset(0)}else{Symbol::EntryRegister(i as u8)}),stack,sp:0,
            source:"let mut r=registers.clone();r[4]=BridgeValue::PrivateStack(0);let mut stack:std::collections::BTreeMap<i32,BridgeValue<T>>=std::collections::BTreeMap::new();\n".into(),calls:Vec::new(),stores:Vec::new(),depth:0}
    }
    fn read(&self, o: &Operand) -> Result<(Symbol, String), String> {
        match o {
            Operand::Reg(reg) => {
                let i = full(*reg)?;
                Ok((self.registers[i].clone(), format!("r[{i}].clone()")))
            }
            Operand::Immediate(n) => {
                Ok((Symbol::Constant(*n), format!("BridgeValue::Scalar({n}u32)")))
            }
            Operand::Memory(a, 32) if a.index.is_none() => {
                let Some(base) = a.base else {
                    return Err("bridge: unbound memory read".into());
                };
                let Symbol::StackOffset(offset) = self.registers[base as usize] else {
                    return Err("bridge: memory read owner".into());
                };
                let at = offset
                    .checked_add(a.displacement as i32)
                    .ok_or("bridge: stack displacement")?;
                let value = self
                    .stack
                    .get(&at)
                    .cloned()
                    .ok_or("bridge: unknown/protected stack word")?;
                let expression = if at == 4 {
                    "argument.clone()".into()
                } else {
                    format!("stack.get(&{at}).ok_or(\"bridge saved word\")?.clone()")
                };
                Ok((value, expression))
            }
            _ => Err("bridge: unsupported read".into()),
        }
    }
    fn set(&mut self, dst: &Operand, value: Symbol, expression: String) -> Result<(), String> {
        let Operand::Reg(reg) = dst else {
            return Err("bridge: destination is not register".into());
        };
        let i = full(*reg)?;
        if i == 4 {
            return Err("bridge: ESP assignment".into());
        }
        self.registers[i] = value;
        self.source.push_str(&format!("r[{i}]={expression};\n"));
        Ok(())
    }
    fn push(&mut self, o: &Operand) -> Result<(), String> {
        let (value, expr) = self.read(o)?;
        self.sp -= 4;
        if self.sp < -64 || self.stack.insert(self.sp, value).is_some() {
            return Err("bridge: stack budget/overlap".into());
        }
        self.depth = self.depth.max((-self.sp) as u32);
        self.registers[4] = Symbol::StackOffset(self.sp);
        self.source.push_str(&format!(
            "stack.insert({},{});r[4]=BridgeValue::PrivateStack({});\n",
            self.sp, expr, self.sp
        ));
        Ok(())
    }
    fn pop(&mut self, reg: Reg) -> Result<(), String> {
        let i = full(reg)?;
        if i == 4 || self.sp >= 0 {
            return Err("bridge: protected POP".into());
        }
        self.registers[i] = self
            .stack
            .remove(&self.sp)
            .ok_or("bridge: missing saved slot")?;
        self.source.push_str(&format!(
            "r[{i}]=stack.remove(&{}).ok_or(\"bridge saved slot\")?;\n",
            self.sp
        ));
        self.sp += 4;
        self.registers[4] = Symbol::StackOffset(self.sp);
        self.source
            .push_str(&format!("r[4]=BridgeValue::PrivateStack({});\n", self.sp));
        Ok(())
    }
    fn call(
        &mut self,
        kind: CallKind,
        target: Symbol,
        target_expr: String,
        argc: usize,
        continuation: Option<u32>,
    ) -> Result<(), String> {
        if !self.calls.is_empty() {
            return Err("bridge: multiple external calls".into());
        }
        let mut arguments = Vec::new();
        let mut expressions = Vec::new();
        for n in 0..argc {
            let at = self.sp + (n * 4) as i32;
            arguments.push(
                self.stack
                    .get(&at)
                    .cloned()
                    .ok_or("bridge: missing call argument")?,
            );
            expressions.push(format!(
                "stack.get(&{at}).ok_or(\"bridge argument\")?.clone()"
            ));
        }
        let entry_sp = self.sp - 4;
        self.depth = self.depth.max((-entry_sp) as u32);
        let mut call_regs = self.registers.clone();
        call_regs[4] = Symbol::StackOffset(entry_sp);
        self.calls.push(CallEffect {
            kind,
            target,
            registers: call_regs,
            arguments,
            continuation,
            entry_depth: (-entry_sp) as u32,
        });
        let cleanup = match kind {
            CallKind::Notification => 4,
            CallKind::GlobalUnwind => 16,
            _ => 0,
        };
        let return_sp = self.sp + cleanup;
        let kind_name = match kind {
            CallKind::Filter => "Filter",
            CallKind::Cleanup => "Cleanup",
            CallKind::Notification => "Notification",
            CallKind::GlobalUnwind => "GlobalUnwind",
        };
        self.source.push_str(&format!("{{let call_target={target_expr};let before=r.clone();let mut entry=r.clone();entry[4]=BridgeValue::PrivateStack({entry_sp});let reply=invoke(BridgeCall::{kind_name},&call_target,&entry,&[{}],{continuation:?})?;if reply.resume!={continuation:?}||!matches!(reply.registers[4],BridgeValue::PrivateStack(n)if n=={return_sp}){{return Err(\"bridge callee continuation/stack contract\");}}\n",expressions.join(",")));
        match kind {
            CallKind::Notification => {
                self.source.push_str("for i in [0usize,1,2,3,5,6,7]{if reply.registers[i]!=before[i]{return Err(\"notification changed register identity\");}}\n");
            }
            CallKind::GlobalUnwind => {
                self.source.push_str("if !matches!(reply.registers[0],BridgeValue::Scalar(0)){return Err(\"unwind return value contract\");}\n");
                for i in 0..8 {
                    if i != 4 {
                        self.registers[i] = Symbol::CallResult(i as u8);
                    }
                }
                self.registers[0] = Symbol::Constant(0);
            }
            _ => {
                if kind == CallKind::Filter {
                    self.source.push_str("if !matches!(reply.registers[0],BridgeValue::Scalar(_)){return Err(\"filter result type\");}\n");
                }
                for i in 0..8 {
                    if i != 4 {
                        self.registers[i] = Symbol::CallResult(i as u8);
                    }
                }
            }
        }
        self.source.push_str("r=reply.registers;}\n");
        for at in (self.sp..return_sp).step_by(4) {
            self.stack.remove(&at);
            self.source.push_str(&format!("stack.remove(&{at});\n"));
        }
        self.sp = return_sp;
        self.registers[4] = Symbol::StackOffset(self.sp);
        Ok(())
    }
}

fn prove(code: &[u8], origin: u32, mode: Mode) -> Result<BridgeProof, String> {
    if origin == 0 || code.is_empty() || code.len() > 256 {
        return Err("bridge: extent budget".into());
    }
    let end = origin
        .checked_add(code.len() as u32)
        .ok_or("bridge: code overflow")?;
    let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
    let mut state = State::new(matches!(mode, Mode::Notification(_)));
    // These tags establish no owner or target authority on their own. They
    // prevent scalar integers/unknowns from reaching the typed callback at all;
    // the enclosing proof and callback must still validate capability identity.
    let entry_check = match mode {
        Mode::Filter | Mode::Selected { .. } | Mode::Global { .. } =>
            "if !matches!(r[1],BridgeValue::Capability(_))||!matches!(r[2],BridgeValue::Capability(_)){return Err(\"bridge target/frame capability tags\");}\n",
        Mode::Cleanup =>
            "if !matches!(r[0],BridgeValue::Capability(_)){return Err(\"bridge cleanup capability tag\");}\n",
        Mode::Notification(_) =>
            "if !matches!(r[0],BridgeValue::Capability(_))||!matches!(r[5],BridgeValue::Capability(_))||!matches!(argument,BridgeValue::Scalar(_)){return Err(\"bridge notification value tags\");}\n",
    };
    state.source.push_str(entry_check);
    let mut exit = None;
    while decoder.can_decode() {
        let i = decoder.decode();
        if i.is_invalid() || exit.is_some() {
            return Err("bridge: malformed/trailing instructions".into());
        }
        let at = (i.ip32() - origin) as usize;
        let raw = &code[at..at + i.len()];
        if i.code() == Code::Call_rel32_32 && raw.len() == 5 && raw[0] == 0xe8 {
            let Mode::Selected { notification } = mode else {
                return Err("bridge: unbound direct call".into());
            };
            if i.near_branch32() != notification {
                return Err("bridge: notification binding".into());
            }
            state.call(
                CallKind::Notification,
                Symbol::Constant(notification),
                format!("BridgeValue::Scalar({notification}u32)"),
                1,
                None,
            )?;
            continue;
        }
        if i.code() == Code::Retnd_imm16 && raw == [0xc2, 4, 0] {
            if !matches!(mode, Mode::Notification(_)) {
                return Err("bridge: RET cleanup contract".into());
            }
            exit = Some(Exit::Return { cleanup: 4 });
            continue;
        }
        if i.code() == Code::Jmp_rm32
            && raw.first() == Some(&0xff)
            && raw.len() == 2
            && i.op0_kind() == OpKind::Register
        {
            if !matches!(mode, Mode::Selected { .. }) {
                return Err("bridge: indirect jump contract".into());
            }
            let index = match i.op0_register() {
                iced_x86::Register::ESI => 6,
                iced_x86::Register::EDI => 7,
                _ => return Err("bridge: selected target register".into()),
            };
            let target = state.registers[index].clone();
            state
                .source
                .push_str(&format!("let bridge_target=r[{index}].clone();\n"));
            exit = Some(Exit::Jump(target));
            continue;
        }
        match graph::normalized(&i, raw)? {
            Operation::Push(o) => state.push(&o)?,
            Operation::Pop(r) => state.pop(r)?,
            Operation::Binary(Binary::Move, Operand::Memory(address, 32), src) => {
                let Mode::Notification(binding) = mode else {
                    return Err("bridge: unbound memory store".into());
                };
                if address.index.is_some() {
                    return Err("bridge: indexed module write".into());
                }
                let base = match address.base {
                    None => 0,
                    Some(r) => match state.registers[r as usize] {
                        Symbol::Constant(n) => n,
                        _ => return Err("bridge: module base provenance".into()),
                    },
                };
                let address = base
                    .checked_add(address.displacement)
                    .ok_or("bridge: module address overflow")?;
                if !address.is_multiple_of(4)
                    || ![binding.target_word, binding.action_word, binding.frame_word]
                        .contains(&address)
                {
                    return Err("bridge: module word binding".into());
                }
                let (value, expr) = state.read(&src)?;
                state.stores.push(StoreEffect { address, value });
                state
                    .source
                    .push_str(&format!("store({address}u32,&{expr})?;\n"));
            }
            Operation::Binary(Binary::Move, dst, src) => {
                let (value, expr) = state.read(&src)?;
                state.set(&dst, value, expr)?;
            }
            Operation::Binary(Binary::Xor, dst, src) if dst == src => {
                state.set(&dst, Symbol::Constant(0), "BridgeValue::Scalar(0)".into())?;
            }
            Operation::Call(operand) => match mode {
                Mode::Filter | Mode::Cleanup => {
                    let (target, expr) = state.read(&operand)?;
                    state.call(
                        if matches!(mode, Mode::Filter) {
                            CallKind::Filter
                        } else {
                            CallKind::Cleanup
                        },
                        target,
                        expr,
                        0,
                        None,
                    )?;
                }
                Mode::Global { iat } => {
                    let Operand::Memory(a, 32) = operand else {
                        return Err("bridge: unwind IAT form".into());
                    };
                    if a.base.is_some() || a.index.is_some() || a.displacement != iat {
                        return Err("bridge: unwind IAT binding".into());
                    }
                    state.call(
                        CallKind::GlobalUnwind,
                        Symbol::Constant(iat),
                        format!("BridgeValue::Scalar({iat}u32)"),
                        4,
                        Some(i.next_ip32()),
                    )?;
                }
                _ => return Err("bridge: unexpected indirect call".into()),
            },
            Operation::Return => exit = Some(Exit::Return { cleanup: 0 }),
            Operation::Nop => {}
            _ => return Err("bridge: unsupported instruction effect".into()),
        }
    }
    let exit = exit.ok_or("bridge: missing terminal effect")?;
    if state.sp != 0 || state.stack.keys().any(|&k| k < 0) {
        return Err("bridge: unbalanced private stack".into());
    }
    match mode {
        Mode::Filter => {
            let call = state.calls.first().ok_or("bridge: missing filter call")?;
            if call.target != Symbol::EntryRegister(1)
                || call.registers[5] != Symbol::EntryRegister(2)
                || [0, 2, 3, 6, 7]
                    .iter()
                    .any(|&r| call.registers[r] != Symbol::Constant(0))
                || [3, 5, 6, 7]
                    .iter()
                    .any(|&r| state.registers[r] != Symbol::EntryRegister(r as u8))
                || exit != (Exit::Return { cleanup: 0 })
            {
                return Err("bridge: filter ABI effects".into());
            }
        }
        Mode::Cleanup => {
            let call = state.calls.first().ok_or("bridge: missing cleanup call")?;
            if call.target != Symbol::EntryRegister(0)
                || exit != (Exit::Return { cleanup: 0 })
                || (0..8).any(|r| r != 4 && call.registers[r] != Symbol::EntryRegister(r as u8))
            {
                return Err("bridge: cleanup call ABI".into());
            }
        }
        Mode::Notification(b) => {
            if [b.target_word, b.action_word, b.frame_word]
                .into_iter()
                .collect::<BTreeSet<_>>()
                .len()
                != 3
                || state.stores.len() != 3
                || exit != (Exit::Return { cleanup: 4 })
                || (0..8).any(|r| r != 4 && state.registers[r] != Symbol::EntryRegister(r as u8))
            {
                return Err("bridge: notification ABI/extent".into());
            }
            for (address, value) in [
                (b.target_word, Symbol::EntryRegister(0)),
                (b.action_word, Symbol::Argument(0)),
                (b.frame_word, Symbol::EntryRegister(5)),
            ] {
                if state
                    .stores
                    .iter()
                    .filter(|s| s.address == address && s.value == value)
                    .count()
                    != 1
                {
                    return Err("bridge: notification field effect".into());
                }
            }
        }
        Mode::Selected { .. } => {
            let call = state
                .calls
                .first()
                .ok_or("bridge: missing notification call")?;
            if call.arguments != [Symbol::Constant(1)]
                || call.registers[0] != Symbol::EntryRegister(1)
                || call.registers[5] != Symbol::EntryRegister(2)
                || exit != Exit::Jump(Symbol::EntryRegister(1))
                || state.registers[5] != Symbol::EntryRegister(2)
                || [0, 1, 2, 3, 7]
                    .iter()
                    .any(|&r| state.registers[r] != Symbol::Constant(0))
            {
                return Err("bridge: selected transfer effects".into());
            }
        }
        Mode::Global { .. } => {
            let call = state
                .calls
                .first()
                .ok_or("bridge: missing global unwind call")?;
            if call.arguments
                != [
                    Symbol::EntryRegister(1),
                    Symbol::Constant(call.continuation.unwrap()),
                    Symbol::EntryRegister(2),
                    Symbol::Constant(0),
                ]
                || [3, 5, 6, 7]
                    .iter()
                    .any(|&r| state.registers[r] != Symbol::EntryRegister(r as u8))
                || exit != (Exit::Return { cleanup: 0 })
            {
                return Err("bridge: global unwind continuation/ABI".into());
            }
        }
    }
    let _ = end;
    state.source.push_str(match exit {
        Exit::Return { cleanup: 0 } => "Ok(BridgeExit::Return{registers:r,cleanup:0})\n",
        Exit::Return { cleanup: 4 } => "Ok(BridgeExit::Return{registers:r,cleanup:4})\n",
        Exit::Jump(_) => "Ok(BridgeExit::Jump{registers:r,target:bridge_target})\n",
        _ => unreachable!(),
    });
    Ok(BridgeProof {
        calls: state.calls,
        stores: state.stores,
        exit,
        origin,
        registers: state.registers,
        temporary_bytes: state.depth,
        body: state.source,
    })
}

pub(crate) fn prove_filter(code: &[u8], origin: u32) -> Result<BridgeProof, String> {
    prove(code, origin, Mode::Filter)
}
pub(crate) fn prove_call(code: &[u8], origin: u32) -> Result<BridgeProof, String> {
    prove(code, origin, Mode::Cleanup)
}
pub(crate) fn prove_notification(
    code: &[u8],
    origin: u32,
    binding: NotificationBinding,
) -> Result<BridgeProof, String> {
    if [binding.target_word, binding.action_word, binding.frame_word]
        .iter()
        .any(|&address| {
            address == 0 || !address.is_multiple_of(4) || address.checked_add(4).is_none()
        })
    {
        return Err("bridge: complete notification word extent".into());
    }
    prove(code, origin, Mode::Notification(binding))
}
pub(crate) fn prove_selected(
    code: &[u8],
    origin: u32,
    notification: u32,
    notification_proof: &BridgeProof,
) -> Result<BridgeProof, String> {
    if notification_proof.origin != notification
        || notification_proof.exit != (Exit::Return { cleanup: 4 })
        || !notification_proof.calls.is_empty()
        || notification_proof.stores.len() != 3
    {
        return Err("bridge: notification certificate".into());
    }
    prove(code, origin, Mode::Selected { notification })
}
pub(crate) fn prove_global(code: &[u8], origin: u32, iat: u32) -> Result<BridgeProof, String> {
    if iat == 0 || !iat.is_multiple_of(4) || iat.checked_add(4).is_none() {
        return Err("bridge: unwind IAT extent".into());
    }
    prove(code, origin, Mode::Global { iat })
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOTIFY: u32 = 0x5000;
    const SELECTED: u32 = 0x6000;
    const GLOBAL: u32 = 0x7000;
    const IAT: u32 = 0x9000;
    fn bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    fn binding() -> NotificationBinding {
        NotificationBinding {
            target_word: 0x8004,
            action_word: 0x8008,
            frame_word: 0x800c,
        }
    }
    fn notification() -> Vec<u8> {
        bytes("5351bb008000008b4c240c894b08894304896b0c55515058595d595bc20400")
    }
    fn filter() -> Vec<u8> {
        bytes("555657538bea33c033db33d233f633ffffd15b5f5e5dc3")
    }
    fn selected() -> Vec<u8> {
        let mut b = bytes("8bea8bf18bc16a01e80000000033c033db33c933d233ffffe6");
        b[9..13].copy_from_slice(&NOTIFY.wrapping_sub(SELECTED + 13).to_le_bytes());
        b
    }
    fn global() -> Vec<u8> {
        let mut b = bytes("558bec5356576a0052680000000051ff15009000005f5e5b5dc3");
        b[10..14].copy_from_slice(&(GLOBAL + 21).to_le_bytes());
        b
    }
    #[test]
    fn relocated_bridges_derive_calls_stores_stack_and_continuations() {
        let n = prove_notification(&notification(), NOTIFY, binding()).unwrap();
        assert_eq!(n.temporary_bytes, 20);
        assert_eq!(
            n.stores,
            vec![
                StoreEffect {
                    address: 0x8008,
                    value: Symbol::Argument(0)
                },
                StoreEffect {
                    address: 0x8004,
                    value: Symbol::EntryRegister(0)
                },
                StoreEffect {
                    address: 0x800c,
                    value: Symbol::EntryRegister(5)
                }
            ]
        );
        let f = prove_filter(&filter(), 0x4000).unwrap();
        assert_eq!(f.temporary_bytes, 20);
        assert_eq!(f.calls[0].registers[5], Symbol::EntryRegister(2));
        let s = prove_selected(&selected(), SELECTED, NOTIFY, &n).unwrap();
        assert_eq!(s.temporary_bytes, 8);
        assert_eq!(s.exit, Exit::Jump(Symbol::EntryRegister(1)));
        let g = prove_global(&global(), GLOBAL, IAT).unwrap();
        assert_eq!(g.temporary_bytes, 36);
        assert_eq!(g.calls[0].continuation, Some(GLOBAL + 21));
        assert_eq!(
            prove_call(&[0xff, 0xd0, 0xc3], 0xa000)
                .unwrap()
                .temporary_bytes,
            4
        );
        let mut variant = filter();
        variant[..4].copy_from_slice(&[0x55, 0x57, 0x56, 0x53]);
        variant[19..22].copy_from_slice(&[0x5e, 0x5f, 0x5d]);
        assert!(prove_filter(&variant, 0x4100).is_ok());
        let mut reordered = notification();
        let first = reordered[11..14].to_vec();
        let second = reordered[14..17].to_vec();
        reordered[11..14].copy_from_slice(&second);
        reordered[14..17].copy_from_slice(&first);
        let q = prove_notification(&reordered, NOTIFY, binding()).unwrap();
        assert_eq!(q.stores[0].address, 0x8004);
    }
    #[test]
    fn wrong_targets_fields_saved_state_and_unwind_continuations_reject() {
        let n = prove_notification(&notification(), NOTIFY, binding()).unwrap();
        let mut b = filter();
        b[17] = 0xd0;
        assert!(prove_filter(&b, 0x4000).is_err());
        let mut b = filter();
        b[18] = 0x5e;
        assert!(prove_filter(&b, 0x4000).is_err());
        let mut b = notification();
        b[13] = 4;
        assert!(prove_notification(&b, NOTIFY, binding()).is_err());
        let mut b = notification();
        b[29] = 8;
        assert!(prove_notification(&b, NOTIFY, binding()).is_err());
        let mut b = selected();
        b[9] ^= 1;
        assert!(prove_selected(&b, SELECTED, NOTIFY, &n).is_err());
        assert!(prove_selected(&selected(), SELECTED, NOTIFY + 1, &n).is_err());
        let mut b = global();
        b[10] ^= 1;
        assert!(prove_global(&b, GLOBAL, IAT).is_err());
        let mut b = global();
        b[17] ^= 4;
        assert!(prove_global(&b, GLOBAL, IAT).is_err());
        assert!(prove_call(&[0xff, 0xd1, 0xc3], 0xa000).is_err());
        assert!(prove_call(&[0x66, 0xff, 0xd0, 0xc3], 0xa000).is_err());
    }
    #[test]
    fn emitted_typed_calls_preserve_stores_and_require_exact_resume() {
        let notify = prove_notification(&notification(), NOTIFY, binding()).unwrap();
        let filter = prove_filter(&filter(), 0x4000).unwrap();
        let selected = prove_selected(&selected(), SELECTED, NOTIFY, &notify).unwrap();
        let global = prove_global(&global(), GLOBAL, IAT).unwrap();
        let source = format!(
            r#"#![allow(dead_code,unused_variables,unused_mut)]
{types}
type Packet<T>=[BridgeValue<T>;8];
fn notification<T:Clone+Eq>(registers:&Packet<T>,argument:&BridgeValue<T>,mut store:impl FnMut(u32,&BridgeValue<T>)->Result<(),&'static str>)->Result<BridgeExit<T>,&'static str>{{{notify}}}
fn filter<T:Clone+Eq>(registers:&Packet<T>,mut invoke:impl FnMut(BridgeCall,&BridgeValue<T>,&Packet<T>,&[BridgeValue<T>],Option<u32>)->Result<BridgeReply<T>,&'static str>)->Result<BridgeExit<T>,&'static str>{{{filter}}}
fn selected<T:Clone+Eq>(registers:&Packet<T>,mut invoke:impl FnMut(BridgeCall,&BridgeValue<T>,&Packet<T>,&[BridgeValue<T>],Option<u32>)->Result<BridgeReply<T>,&'static str>)->Result<BridgeExit<T>,&'static str>{{{selected}}}
fn global<T:Clone+Eq>(registers:&Packet<T>,mut invoke:impl FnMut(BridgeCall,&BridgeValue<T>,&Packet<T>,&[BridgeValue<T>],Option<u32>)->Result<BridgeReply<T>,&'static str>)->Result<BridgeExit<T>,&'static str>{{{global}}}
fn main(){{
 let initial:Packet<u32>=std::array::from_fn(|i|BridgeValue::Capability(100+i as u32));let mut log=Vec::new();
 let mut scalar_target=initial.clone();scalar_target[1]=BridgeValue::Scalar(101);
 assert!(filter(&scalar_target,|_,_,_,_,_|panic!("scalar target reached callback")).is_err());
 assert!(filter(&initial,|_,_,_,_,_|Err("wrong-owner capability")).is_err());
 let BridgeExit::Jump{{registers:r,target}}=selected(&initial,|kind,target,entry,args,resume|{{
  assert_eq!(kind,BridgeCall::Notification);assert_eq!(target,&BridgeValue::Scalar(0x5000));assert_eq!(args,&[BridgeValue::Scalar(1)]);assert_eq!(resume,None);
  let BridgeExit::Return{{mut registers,cleanup}}=notification(entry,&args[0],|at,value|{{log.push((at,value.clone()));Ok(())}})? else{{return Err("notification exit")}};
  assert_eq!(cleanup,4);registers[4]=BridgeValue::PrivateStack(0);Ok(BridgeReply{{registers,resume:None}})
 }}).unwrap() else{{panic!("selected exit")}};
 assert_eq!(target,initial[1]);assert_eq!(r[5],initial[2]);
 assert_eq!(log,vec![(0x8008,BridgeValue::Scalar(1)),(0x8004,initial[1].clone()),(0x800c,initial[2].clone())]);
 for i in [0,1,2,3,7]{{assert_eq!(r[i],BridgeValue::Scalar(0));}}
 let mut partial=Vec::new();assert!(notification(&initial,&BridgeValue::Scalar(1),|at,_|{{if at==0x8004{{return Err("owned store failure");}}partial.push(at);Ok(())}}).is_err());assert_eq!(partial,vec![0x8008]);
 let BridgeExit::Return{{registers:r,..}}=filter(&initial,|kind,target,entry,args,_|{{
  assert_eq!(kind,BridgeCall::Filter);assert_eq!(target,&initial[1]);assert_eq!(entry[5],initial[2]);assert!(args.is_empty());
  let mut registers=std::array::from_fn(|_|BridgeValue::Unknown);registers[0]=BridgeValue::Scalar(u32::MAX);registers[4]=BridgeValue::PrivateStack(-16);Ok(BridgeReply{{registers,resume:None}})
 }}).unwrap() else{{panic!("filter exit")}};
 assert_eq!(r[0],BridgeValue::Scalar(u32::MAX));for i in [3,5,6,7]{{assert_eq!(r[i],initial[i]);}}
 for bad in [false,true]{{
  let result=global(&initial,|kind,target,entry,args,resume|{{
   assert_eq!(kind,BridgeCall::GlobalUnwind);assert_eq!(target,&BridgeValue::Scalar(0x9000));
   assert_eq!(args,&[initial[1].clone(),BridgeValue::Scalar(0x7015),initial[2].clone(),BridgeValue::Scalar(0)]);
   assert_eq!(entry[4],BridgeValue::PrivateStack(-36));let mut registers=std::array::from_fn(|_|BridgeValue::Unknown);
   registers[0]=BridgeValue::Scalar(0);registers[4]=BridgeValue::PrivateStack(-16);Ok(BridgeReply{{registers,resume:if bad{{None}}else{{resume}}}})
  }});
  if bad{{assert!(result.is_err());}}else{{let BridgeExit::Return{{registers,..}}=result.unwrap()else{{panic!("global exit")}};for i in [3,5,6,7]{{assert_eq!(registers[i],initial[i]);}}}}
 }}
}}
"#,
            types = EMITTED_TYPES,
            notify = notify.body(),
            filter = filter.body(),
            selected = selected.body(),
            global = global.body()
        );
        let dir = std::env::temp_dir().join(format!("w2l-unwind-bridges-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("run.rs");
        let output = dir.join(if cfg!(windows) { "run.exe" } else { "run" });
        std::fs::write(&file, source).unwrap();
        let compiled = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(&file)
            .arg("-o")
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        assert!(std::process::Command::new(output)
            .status()
            .unwrap()
            .success());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
