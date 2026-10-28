//! Instruction-derived EH4 guard checking under a valid owned-frame cut.
//! A mismatching guard is excluded before guest execution. The original failure
//! jump is retained as evidence, not replaced with a claimed Windows fail-fast.
use super::frame_proof::ProvenFrame;
use super::graph::{self, Address, Binary, Condition, Operand, Operation, Reg};
use iced_x86::{Code, Decoder, DecoderOptions};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) struct GuardProof {
    body: String,
    failure_target: u32,
    checked_offsets: Vec<i32>,
    temporary_bytes: u32,
    #[allow(dead_code)]
    header: [i32; 4],
}
impl GuardProof {
    #[allow(dead_code)] // CRT backend is not used by all slice examples.
    pub fn normal_call(&self, name: &str) -> String {
        self.emit_call(name, false, false)
    }
    #[allow(dead_code)]
    pub fn prefix_call(&self, name: &str) -> String {
        self.emit_call(name, true, false)
    }
    #[allow(dead_code)] // Owned CRT backend, not every standalone slice.
    pub fn owned_prefix_call(&self, name: &str) -> String {
        self.emit_call(name, true, true)
    }
    fn emit_call(&self, name: &str, deferred: bool, owned: bool) -> String {
        let (frame_type, guard_type) = if owned {
            ("CrtOwnedFrameView<'_>", "CrtOwnedGuardView")
        } else {
            ("CrtLiveFrame<'_,'_>", "CrtGuardView")
        };
        let arguments = if deferred {
            "if frame.rt.load(CrtCpu::pointer(cpu.r[4])?,32)?!=CrtValue::Pointer(table)||frame.rt.load(frame.rt.offset(CrtCpu::pointer(cpu.r[4])?,4)?,32)?!=CrtValue::Pointer(frame.owner_frame()?){return Err(\"guard prefix arguments\");}"
        } else {
            "cpu.push(frame.rt,CrtValue::Pointer(frame.owner_frame()?))?;cpu.push(frame.rt,CrtValue::Pointer(table))?;"
        };
        let cleanup = if deferred {
            ""
        } else {
            "cpu.discard(frame.rt,8)?;cpu.flags=CrtFlags::unknown();"
        };
        let header = self.header;
        let checks=header.iter().enumerate().map(|(i,n)|format!("if frame.rt.load(frame.rt.offset(table,{})?,32)?.known_scalar()? != {}u32{{return Err(\"live guard header changed\");}}",i*4,*n as u32)).collect::<String>();
        format!(
            r#"fn {name}(frame:&mut {frame_type},cpu:&mut CrtCpu,continuation:u32)->RegistryResult<()>{{
 frame.validate()?;let table=frame.rt.resolve_absolute(frame.scope_address(),CrtRegionKind::Module)?;
 frame.rt.valid(table,16)?;{checks}
 let cookie=frame.rt.load(frame.rt.resolve_absolute(frame.cookie_address(),CrtRegionKind::Module)?,32)?.known_scalar()?;
 let sp=CrtCpu::pointer(cpu.r[4])?;let low=frame.rt.offset(sp,-{depth})?;frame.rt.valid(low,{depth})?;
 frame.stack_range(low.address(),u64::from(sp.address()))?;
 if frame.rt.overlapping_tags(low.address(),{depth}).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)|CrtValue::OpaqueSaved(_))){{return Err("guard temporary protected overlap");}}
 {arguments}
 frame.call(cpu,continuation,|f,child|{{let bp=f.owner_frame()?.address();let memory=&{guard_type}{{owner:f.rt.owner,frame:f,bp}};(||{{{body}}})()?;child.clobber(CrtValue::Scalar{{bits:0,known:0}});child.finish(f.rt)}})?;
 {cleanup}Ok(())
}}"#,
            depth = self.temporary_bytes + 12,
            body = self.body
        )
    }
    pub fn body(&self) -> &str {
        &self.body
    }
    pub fn failure_target(&self) -> u32 {
        self.failure_target
    }
    pub fn checked_offsets(&self) -> &[i32] {
        &self.checked_offsets
    }
    /// Maximum bytes below helper-entry ESP, including nested CALL return.
    pub fn temporary_bytes(&self) -> u32 {
        self.temporary_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Initial(u8),
    Stack(i32),
    Table(i32),
    Frame(i32),
    Scalar(u32),
    Guard(i32),
    CheckedCookie(i32),
    Return,
}
#[derive(Clone)]
enum Op {
    Ordinary(Operation),
    Call(u32),
}
struct Node {
    end: u32,
    op: Op,
}

fn decode(code: &[u8], origin: u32) -> Result<BTreeMap<u32, Node>, String> {
    if origin == 0 || code.is_empty() || code.len() > 1024 {
        return Err("guard: code extent".into());
    }
    origin
        .checked_add(code.len() as u32)
        .ok_or("guard: code overflow")?;
    let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
    let mut nodes = BTreeMap::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        if i.is_invalid() || nodes.len() == 128 {
            return Err("guard: decode budget/form".into());
        }
        let pc = i.ip() as u32;
        let start = (pc - origin) as usize;
        let bytes = &code[start..start + i.len()];
        let op = if i.code() == Code::Call_rel32_32 && bytes.len() == 5 && bytes[0] == 0xe8 {
            Op::Call(i.near_branch32())
        } else {
            Op::Ordinary(graph::normalized(&i, bytes)?)
        };
        nodes.insert(
            pc,
            Node {
                end: pc
                    .checked_add(i.len() as u32)
                    .ok_or("guard: end overflow")?,
                op,
            },
        );
    }
    Ok(nodes)
}
fn full(reg: Reg) -> Result<usize, String> {
    if reg.width != 32 || reg.shift != 0 {
        return Err("guard: partial register".into());
    }
    Ok(reg.index as usize)
}
fn security_failure(code: &[u8], origin: u32, cookie_va: u32) -> Result<u32, String> {
    let nodes = decode(code, origin)?;
    if cookie_va == 0 || !cookie_va.is_multiple_of(4) || nodes.len() != 4 {
        return Err("guard: security checker shape".into());
    }
    let rows: Vec<_> = nodes.iter().collect();
    let Op::Ordinary(Operation::Binary(
        Binary::Compare,
        Operand::Reg(reg),
        Operand::Memory(address, 32),
    )) = &rows[0].1.op
    else {
        return Err("guard: security cookie comparison".into());
    };
    if full(*reg)? != 1
        || address.base.is_some()
        || address.index.is_some()
        || address.displacement != cookie_va
    {
        return Err("guard: security cookie binding".into());
    }
    if !matches!(&rows[1].1.op,Op::Ordinary(Operation::Branch(Condition::NotEqual,target)) if *target==*rows[3].0)
        || !matches!(&rows[2].1.op, Op::Ordinary(Operation::Return))
    {
        return Err("guard: security success/failure branch".into());
    }
    let Op::Ordinary(Operation::Jump(failure)) = rows[3].1.op else {
        return Err("guard: missing failure tail".into());
    };
    let end = origin + code.len() as u32;
    if failure == 0 || (origin..end).contains(&failure) {
        return Err("guard: failure edge not external".into());
    }
    Ok(failure)
}
struct State<'a> {
    regs: [Value; 8],
    stack: BTreeMap<i32, Value>,
    sp: i32,
    header: [i32; 4],
    guards: &'a [i32],
    equal: Option<bool>,
    checked: Vec<i32>,
}
impl State<'_> {
    fn address(&self, a: &Address) -> Result<Value, String> {
        if a.scale != 1 {
            return Err("guard: scaled address".into());
        }
        let mut parts = Vec::new();
        if let Some(r) = a.base {
            parts.push(self.regs[r as usize].clone());
        }
        if let Some(r) = a.index {
            parts.push(self.regs[r as usize].clone());
        }
        let mut scalar = a.displacement as i32;
        let mut pointer = None;
        for value in parts {
            match value {
                Value::Scalar(n) => {
                    scalar = scalar
                        .checked_add(n as i32)
                        .ok_or("guard: displacement overflow")?
                }
                Value::Stack(n) | Value::Table(n) | Value::Frame(n) => {
                    if pointer.is_some() {
                        return Err("guard: pointer addition".into());
                    }
                    pointer = Some(match value {
                        Value::Stack(_) => Value::Stack(n),
                        Value::Table(_) => Value::Table(n),
                        _ => Value::Frame(n),
                    });
                }
                _ => return Err("guard: address provenance".into()),
            }
        }
        match pointer {
            Some(Value::Stack(n)) => Ok(Value::Stack(
                n.checked_add(scalar).ok_or("guard: stack offset")?,
            )),
            Some(Value::Table(n)) => Ok(Value::Table(
                n.checked_add(scalar).ok_or("guard: table offset")?,
            )),
            Some(Value::Frame(n)) => Ok(Value::Frame(
                n.checked_add(scalar).ok_or("guard: frame offset")?,
            )),
            _ => Err("guard: missing pointer".into()),
        }
    }
    fn read(&self, o: &Operand) -> Result<Value, String> {
        match o {
            Operand::Immediate(n) => Ok(Value::Scalar(*n)),
            Operand::Reg(reg) => Ok(self.regs[full(*reg)?].clone()),
            Operand::Memory(a, 32) => match self.address(a)? {
                Value::Stack(offset) => self
                    .stack
                    .get(&offset)
                    .cloned()
                    .ok_or("guard: unowned stack word".into()),
                Value::Table(offset) if (0..16).contains(&offset) && offset % 4 == 0 => {
                    Ok(Value::Scalar(self.header[offset as usize / 4] as u32))
                }
                Value::Frame(offset) if self.guards.contains(&offset) => Ok(Value::Guard(offset)),
                _ => Err("guard: unknown or non-guard memory".into()),
            },
            _ => Err("guard: unsupported read".into()),
        }
    }
    fn write_register(&mut self, o: &Operand, value: Value) -> Result<(), String> {
        let Operand::Reg(reg) = o else {
            return Err("guard: memory write unsupported".into());
        };
        let index = full(*reg)?;
        if index == 4 {
            return Err("guard: arbitrary ESP assignment".into());
        }
        self.regs[index] = value;
        Ok(())
    }
    fn check(&mut self) -> Result<(), String> {
        let Value::CheckedCookie(offset) = self.regs[1] else {
            return Err("guard: unproved security argument".into());
        };
        self.checked.push(offset);
        // The original checker executes CMP and returns only on equality.
        self.equal = Some(true);
        Ok(())
    }
    fn balanced(&self) -> bool {
        self.sp == 0
            && self.stack.len() == 3
            && [3, 5, 6, 7]
                .into_iter()
                .all(|r| self.regs[r] == Value::Initial(r as u8))
    }
}

/// The frame/header/cookie are bound by the caller to one live module/frame.
/// The emitted body requires `memory: &FrameMemory<P>` and `cookie: u32`.
/// It preserves memory; register/flag results are not advertised by this API.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_guard(
    code: &[u8],
    origin: u32,
    security_code: &[u8],
    security_origin: u32,
    cookie_va: u32,
    header: [i32; 4],
    frame: &ProvenFrame,
) -> Result<GuardProof, String> {
    frame.validate_eh4_header(header)?;
    prove_guard_offsets(
        code,
        origin,
        security_code,
        security_origin,
        cookie_va,
        header,
        frame.guard_offsets(),
    )
}
/// Offsets must be derived from a checked original prolog, not guest input.
pub(crate) fn prove_guard_offsets(
    code: &[u8],
    origin: u32,
    security_code: &[u8],
    security_origin: u32,
    cookie_va: u32,
    header: [i32; 4],
    guards: &[i32],
) -> Result<GuardProof, String> {
    if header[1] != 0
        || header[3] != 0
        || !guards.contains(&header[2])
        || (header[0] != -2 && !guards.contains(&header[0]))
    {
        return Err("guard header/prolog layout disagreement".into());
    }
    let failure_target = security_failure(security_code, security_origin, cookie_va)?;
    let nodes = decode(code, origin)?;
    let end = origin + code.len() as u32;
    let security_end = security_origin
        .checked_add(security_code.len() as u32)
        .ok_or("guard: checker extent")?;
    if origin < security_end && security_origin < end {
        return Err("guard: overlapping instruction owners".into());
    }
    for node in nodes.values() {
        match &node.op {
            Op::Call(target) if *target != security_origin => {
                return Err("guard: unbound direct call".into())
            }
            Op::Ordinary(Operation::Jump(target))
                if *target != security_origin && !nodes.contains_key(target) =>
            {
                return Err("guard: unbound jump".into())
            }
            Op::Ordinary(Operation::Branch(_, target)) if !nodes.contains_key(target) => {
                return Err("guard: branch boundary".into())
            }
            _ => {}
        }
    }
    let mut state = State {
        regs: std::array::from_fn(|i| {
            if i == 4 {
                Value::Stack(0)
            } else {
                Value::Initial(i as u8)
            }
        }),
        stack: BTreeMap::from([
            (0, Value::Return),
            (4, Value::Table(0)),
            (8, Value::Frame(0)),
        ]),
        sp: 0,
        header,
        guards,
        equal: None,
        checked: Vec::new(),
    };
    let mut pc = origin;
    let mut visited = BTreeSet::new();
    let mut temporary_bytes = 0;
    loop {
        if !visited.insert(pc) {
            return Err("guard: cyclic helper".into());
        }
        let node = nodes.get(&pc).ok_or("guard: incomplete execution path")?;
        let mut next = node.end;
        match &node.op {
            Op::Call(target) => {
                if *target != security_origin {
                    return Err("guard: call identity".into());
                }
                temporary_bytes = temporary_bytes.max((-state.sp) as u32 + 4);
                state.check()?;
            }
            Op::Ordinary(op) => match op {
                Operation::Push(operand) => {
                    let value = state.read(operand)?;
                    if value == Value::Return {
                        return Err("guard: return address read".into());
                    }
                    state.sp = state.sp.checked_sub(4).ok_or("guard: stack overflow")?;
                    if state.sp < -128 || state.stack.insert(state.sp, value).is_some() {
                        return Err("guard: stack budget/overlap".into());
                    }
                    state.regs[4] = Value::Stack(state.sp);
                    temporary_bytes = temporary_bytes.max((-state.sp) as u32);
                }
                Operation::Pop(reg) => {
                    let index = full(*reg)?;
                    if index == 4 || state.sp >= 0 {
                        return Err("guard: protected stack pop".into());
                    }
                    let value = state
                        .stack
                        .remove(&state.sp)
                        .ok_or("guard: missing saved word")?;
                    state.regs[index] = value;
                    state.sp += 4;
                    state.regs[4] = Value::Stack(state.sp);
                }
                Operation::Binary(Binary::Move, dst, src) => {
                    let value = state.read(src)?;
                    if value == Value::Return {
                        return Err("guard: protected return read".into());
                    }
                    state.write_register(dst, value)?;
                }
                Operation::Binary(Binary::Compare, a, b) => {
                    let (Value::Scalar(a), Value::Scalar(b)) = (state.read(a)?, state.read(b)?)
                    else {
                        return Err("guard: unknown comparison".into());
                    };
                    state.equal = Some(a == b);
                }
                Operation::Binary(Binary::Add, dst, src) => {
                    let (left, right) = (state.read(dst)?, state.read(src)?);
                    let value = match (left, right) {
                        (Value::Scalar(n), Value::Frame(offset))
                        | (Value::Frame(offset), Value::Scalar(n)) => Value::Frame(
                            offset
                                .checked_add(n as i32)
                                .ok_or("guard: frame addition")?,
                        ),
                        _ => return Err("guard: unproved arithmetic".into()),
                    };
                    state.write_register(dst, value)?;
                    state.equal = None;
                }
                Operation::Binary(Binary::Xor, dst, src) => {
                    let (left, right) = (state.read(dst)?, state.read(src)?);
                    let value = match (left, right) {
                        (Value::Frame(0), Value::Guard(offset))
                        | (Value::Guard(offset), Value::Frame(0)) => Value::CheckedCookie(offset),
                        _ => return Err("guard: encoded guard identity".into()),
                    };
                    state.write_register(dst, value)?;
                    state.equal = None;
                }
                Operation::Branch(condition, target) => {
                    let equal = state.equal.ok_or("guard: unknown flags")?;
                    let take = match condition {
                        Condition::Equal => equal,
                        Condition::NotEqual => !equal,
                        _ => return Err("guard: branch condition".into()),
                    };
                    if take {
                        next = *target;
                    }
                }
                Operation::Jump(target) if *target == security_origin => {
                    if !state.balanced() {
                        return Err("guard: tail transfer loses saved state".into());
                    }
                    state.check()?;
                    break;
                }
                Operation::Jump(target) => next = *target,
                Operation::Return => {
                    if !state.balanced() {
                        return Err("guard: unbalanced return".into());
                    }
                    break;
                }
                Operation::Nop => {}
                _ => return Err("guard: unsupported instruction effect".into()),
            },
        }
        pc = next;
    }
    let expected: Vec<_> = if header[0] == -2 {
        vec![header[2]]
    } else {
        vec![header[0], header[2]]
    };
    if state.checked != expected {
        return Err("guard: missing/reordered required checks".into());
    }
    let mut body = String::from("if memory.owner==0 {return Err(\"guard owner\");}\n");
    for &offset in &state.checked {
        body.push_str(&format!("{{let(frame,identity,bits)=memory.read_guard({offset})?;if frame!=memory.frame_pointer()||identity!=cookie||bits^frame!=cookie{{return Err(\"guard mismatch outside admitted entry domain\");}}}}\n"));
    }
    body.push_str("Ok(())\n");
    Ok(GuardProof {
        body,
        failure_target,
        checked_offsets: state.checked,
        temporary_bytes,
        header,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const ORIGIN: u32 = 0x8000;
    const SECURITY: u32 = 0xa000;
    const COOKIE: u32 = 0x6000;
    fn bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    fn helper() -> Vec<u8> {
        // Independently relocated original instruction forms. Addresses/names
        // are deliberately unrelated to the retained Windows executable.
        let mut b=bytes("558bec568b7508578b7d0c8b0683f8fe740d8b4e0403cf330c38e8000000008b46088b4e0c03cf330c385f5e5de900000000");
        b[27..31].copy_from_slice(&SECURITY.wrapping_sub(ORIGIN + 31).to_le_bytes());
        b[46..50].copy_from_slice(&SECURITY.wrapping_sub(ORIGIN + 50).to_le_bytes());
        b
    }
    fn security() -> Vec<u8> {
        let mut b = bytes("3b0d000000007501c3e900000000");
        b[2..6].copy_from_slice(&COOKIE.to_le_bytes());
        b[10..14].copy_from_slice(&0xb000u32.wrapping_sub(SECURITY + 14).to_le_bytes());
        b
    }
    fn frame() -> ProvenFrame {
        // A complete original-style prolog with one guarded owned frame word.
        let b=bytes("558bec6afe6800500000680070000064a1000000005083ec20535657a1006000003145f833c5508d45f064a300000000");
        super::super::frame_proof::prove_frame(
            &b,
            0x1000,
            COOKIE,
            &BTreeSet::from([0x5000]),
            &BTreeSet::from([0x7000]),
        )
        .unwrap()
    }
    fn proof(code: &[u8], check: &[u8], header: [i32; 4]) -> Result<GuardProof, String> {
        prove_guard(code, ORIGIN, check, SECURITY, COOKIE, header, &frame())
    }
    #[test]
    fn instruction_operands_bind_optional_and_required_guard_checks() {
        let p = proof(&helper(), &security(), [-2, 0, -64, 0]).unwrap();
        assert_eq!(p.checked_offsets(), &[-64]);
        assert_eq!(p.failure_target(), 0xb000);
        assert_eq!(p.temporary_bytes(), 12);
        let p = proof(&helper(), &security(), [-64, 0, -64, 0]).unwrap();
        assert_eq!(p.checked_offsets(), &[-64, -64]);
        assert_eq!(p.temporary_bytes(), 16);
        // Permute ESI/EDI consistently in saves, table/frame loads and addresses.
        let mut permuted = helper();
        for (index, byte) in [
            (3, 0x57),
            (5, 0x7d),
            (7, 0x56),
            (9, 0x75),
            (12, 0x07),
            (19, 0x4f),
            (22, 0xce),
            (25, 0x30),
            (32, 0x47),
            (35, 0x4f),
            (38, 0xce),
            (41, 0x30),
            (42, 0x5e),
            (43, 0x5f),
        ] {
            permuted[index] = byte;
        }
        assert!(proof(&permuted, &security(), [-2, 0, -64, 0]).is_ok());
    }
    #[test]
    fn altered_cookie_branch_calls_and_unproved_guard_forms_reject() {
        let mut bad = security();
        bad[2] ^= 4;
        assert!(proof(&helper(), &bad, [-2, 0, -64, 0]).is_err());
        let mut bad = security();
        bad[6] = 0x74;
        assert!(proof(&helper(), &bad, [-2, 0, -64, 0]).is_err());
        let mut bad = security();
        bad[10..14].copy_from_slice(&(-14i32).to_le_bytes());
        assert!(proof(&helper(), &bad, [-2, 0, -64, 0]).is_err());
        assert!(proof(&helper(), &[0xc3], [-2, 0, -64, 0]).is_err());
        let mut bad = helper();
        bad[27] ^= 1;
        assert!(proof(&bad, &security(), [-2, 0, -64, 0]).is_err());
        let mut bad = helper();
        bad[46] ^= 1;
        assert!(proof(&bad, &security(), [-2, 0, -64, 0]).is_err());
        let mut bad = helper();
        bad[41] = 0x39;
        assert!(proof(&bad, &security(), [-2, 0, -64, 0]).is_err());
        let mut bad = helper();
        bad[42] = 0x5e;
        assert!(proof(&bad, &security(), [-2, 0, -64, 0]).is_err());
        let mut bad = helper();
        bad[17] = 0x0c;
        assert!(proof(&bad, &security(), [-2, 0, -64, 0]).is_err());
        let mut bad = helper();
        bad.insert(0, 0x66);
        assert!(proof(&bad, &security(), [-2, 0, -64, 0]).is_err());
        for header in [
            [-2, 0, -20, 0],
            [-2, 0, -64, 4],
            [-64, 4, -64, 0],
            [-3, 0, -64, 0],
        ] {
            assert!(proof(&helper(), &security(), header).is_err());
        }
    }
    #[test]
    fn unknown_values_cycles_and_extent_limits_fail_closed() {
        let mut bad = helper();
        // Unknown entry EDX cannot be treated as the header's known sentinel.
        bad[11..13].copy_from_slice(&[0x8b, 0xc2]);
        assert!(proof(&bad, &security(), [-2, 0, -64, 0]).is_err());
        let mut bad = helper();
        bad[17] = 0xfe; // Taken equality edge back to this same JE.
        assert!(proof(&bad, &security(), [-2, 0, -64, 0]).is_err());
        let mut bad = helper();
        bad[6] = 0x10; // Unowned fourth helper argument, not header pointer.
        assert!(proof(&bad, &security(), [-2, 0, -64, 0]).is_err());
        assert!(proof(&helper()[..49], &security(), [-2, 0, -64, 0]).is_err());
        assert!(proof(&vec![0x90; 1025], &security(), [-2, 0, -64, 0]).is_err());
        assert!(prove_guard(
            &helper(),
            u32::MAX - 10,
            &security(),
            SECURITY,
            COOKIE,
            [-2, 0, -64, 0],
            &frame()
        )
        .is_err());
    }
    #[test]
    fn emitted_checks_reject_corrupt_unknown_and_foreign_guard_identities() {
        let p = proof(&helper(), &security(), [-2, 0, -64, 0]).unwrap();
        let initializer = frame();
        let source = format!(
            r#"#![allow(dead_code)]
{}
{}
fn initialize<P:Clone>(entry_sp:u32,cookie:u32,saved:[Option<u32>;8],predecessor:P)->Result<FrameImage<P>,&'static str>{{ {} }}
fn validate<P>(memory:&FrameMemory<'_,P>,cookie:u32)->Result<(),&'static str>{{ {} }}
fn main(){{
 let cookie=0x12345678;
 for case in 0..7 {{
  let mut image=initialize(0x10000,cookie,[None;8],()).unwrap();
  let key=-68;let bp=image.ebp;
  match case {{
   1=>{{image.words.insert(key,FrameWord::Unknown);}},
   2=>{{image.words.insert(key,FrameWord::Scalar(bp^cookie));}},
   3=>{{image.words.insert(key,FrameWord::Guard{{frame:bp-4,cookie,bits:(bp-4)^cookie}});}},
   4=>{{image.words.insert(key,FrameWord::Guard{{frame:bp,cookie:cookie^1,bits:bp^cookie^1}});}},
   5=>{{image.words.insert(key,FrameWord::Guard{{frame:bp,cookie,bits:(bp^cookie)^1}});}},
   _=>{{}},
  }}
  let mut memory=FrameMemory::new(&mut image,7,&[]).unwrap();
  if case==6 {{memory.owner=0;}}
  assert_eq!(validate(&memory,cookie).is_ok(),case==0,"case {{case}}");
 }}
}}
"#,
            super::super::frame_proof::EMITTED_TYPES,
            super::super::frame_memory::EMITTED_TYPES,
            initializer.initializer_body(),
            p.body()
        );
        let dir = std::env::temp_dir().join(format!("w2l-handler-guard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("guard.rs");
        let binary = dir.join(if cfg!(windows) { "guard.exe" } else { "guard" });
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
        std::fs::remove_dir_all(dir).unwrap();
    }
}
