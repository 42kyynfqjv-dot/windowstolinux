//! Compile original dispatcher instructions with typed local stack and bound data.
//! Entry is a helper ABI cut, not Windows handler selection or whole-PE admission.
use super::graph::{self, Address, Binary, Condition, Operand, Operation, Reg};
use iced_x86::{Decoder, DecoderOptions};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Unknown,
    Scalar {
        expression: String,
        known: Option<u32>,
    },
    Stack(i32),
    Cursor,
    Local,
    Saved(u8),
    Return,
    Function(usize),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Local,
    Argument,
    Save(u8),
    Protected,
}
struct Slot {
    value: Value,
    kind: Kind,
}
enum Place {
    Stack(i32),
    Cursor,
    Local,
    Trace,
    Table(usize, bool),
}
struct State<'a> {
    registers: [Value; 8],
    stack: BTreeMap<i32, Slot>,
    sp: i32,
    cursor: i32,
    cursor_writes: usize,
    calls: Vec<usize>,
    temporary_bytes: u32,
    cleanup_entry_depth: Option<u32>,
    flags: Option<(bool, bool)>,
    source: String,
    live_source: String,
    serial: usize,
    table_va: u32,
    trace_va: u32,
    rows: &'a [(i32, u32)],
    bindings: &'a BTreeMap<u32, usize>,
}
pub(crate) struct ProvenDispatch {
    pub source: String,
    /// Checked live effects, emitted by the same original-instruction proof walk.
    #[allow(dead_code)] // Legacy slice entry points use the array-backed emitter.
    pub live_source: String,
    pub parent: i32,
    pub action: usize,
    /// Own maximum bytes below entry ESP, including nested CALL's return word
    /// but excluding the callee's body. Caller owns the entry return/arguments.
    pub temporary_bytes: u32,
    /// Depth of the unique cleanup's entry ESP, derived before the original CALL.
    pub cleanup_entry_depth: u32,
}
impl ProvenDispatch {
    pub fn with_cleanup_depth(&self, cleanup_temporary_bytes: u32) -> Result<u32, String> {
        Ok(self.temporary_bytes.max(
            self.cleanup_entry_depth
                .checked_add(cleanup_temporary_bytes)
                .ok_or("dispatch: nested temporary stack overflow")?,
        ))
    }
}
fn scalar(value: &Value) -> Result<(String, Option<u32>), String> {
    if let Value::Scalar { expression, known } = value {
        Ok((expression.clone(), *known))
    } else {
        Err("dispatch: non-scalar value".into())
    }
}
fn full(reg: Reg) -> Result<usize, String> {
    if reg.width == 32 && reg.shift == 0 {
        Ok(reg.index as usize)
    } else {
        Err("dispatch: partial register".into())
    }
}
impl State<'_> {
    fn snapshot(&mut self, expression: String, known: Option<u32>) -> Value {
        self.snapshot_live(expression.clone(), expression, known)
    }
    fn snapshot_live(&mut self, expression: String, live: String, known: Option<u32>) -> Value {
        let name = format!("v{}", self.serial);
        self.serial += 1;
        self.source
            .push_str(&format!("let {name}:u32={expression};\n"));
        self.live_source
            .push_str(&format!("let {name}:u32={live};\n"));
        Value::Scalar {
            expression: name,
            known,
        }
    }
    fn address(&self, a: &Address) -> Result<Place, String> {
        let index = if let Some(reg) = a.index {
            let (_, known) = scalar(&self.registers[reg as usize])?;
            known
                .ok_or("dispatch: unknown indexed address")?
                .checked_mul(a.scale)
                .ok_or("dispatch: index overflow")?
        } else {
            0
        };
        if let Some(base) = a.base {
            match self.registers[base as usize] {
                Value::Stack(offset) if a.index.is_none() => {
                    let offset = offset
                        .checked_add(a.displacement as i32)
                        .ok_or("dispatch: stack address overflow")?;
                    if offset % 4 != 0 || !self.stack.contains_key(&offset) {
                        return Err("dispatch: complete stack word bounds".into());
                    }
                    Ok(Place::Stack(offset))
                }
                Value::Cursor if a.index.is_none() && a.displacement == 0 => Ok(Place::Cursor),
                Value::Local if a.index.is_none() && a.displacement == 0 => Ok(Place::Local),
                _ => Err("dispatch: pointer ownership/address form".into()),
            }
        } else {
            let address = a
                .displacement
                .checked_add(index)
                .ok_or("dispatch: address overflow")?;
            if address == self.trace_va && a.index.is_none() {
                return Ok(Place::Trace);
            }
            let offset = address
                .checked_sub(self.table_va)
                .ok_or("dispatch: unbound image address")?;
            if offset % 4 != 0 || offset as usize >= self.rows.len() * 8 {
                return Err("dispatch: table bounds".into());
            }
            Ok(Place::Table(offset as usize / 8, offset % 8 == 4))
        }
    }
    fn read(&mut self, operand: &Operand) -> Result<Value, String> {
        Ok(match operand {
            Operand::Immediate(n) => Value::Scalar {
                expression: format!("{n}u32"),
                known: Some(*n),
            },
            Operand::Reg(reg) => self.registers[full(*reg)?].clone(),
            Operand::Memory(a, 32) => match self.address(a)? {
                Place::Stack(at) => self.stack[&at].value.clone(),
                Place::Cursor => self.snapshot_live(
                    "*cursor as u32".into(),
                    "effects.read_cursor()? as u32".into(),
                    Some(self.cursor as u32),
                ),
                Place::Local => {
                    self.snapshot_live("cells[1]".into(), "effects.read_cell(1)?".into(), None)
                }
                Place::Trace => {
                    self.snapshot_live("cells[0]".into(), "effects.read_cell(0)?".into(), None)
                }
                Place::Table(index, false) => {
                    let n = self.rows[index].0 as u32;
                    Value::Scalar {
                        expression: format!("{n}u32"),
                        known: Some(n),
                    }
                }
                Place::Table(index, true) => Value::Function(
                    *self
                        .bindings
                        .get(&self.rows[index].1)
                        .ok_or("dispatch: unbound cleanup target")?,
                ),
            },
            _ => return Err("dispatch: read form".into()),
        })
    }
    fn write(&mut self, operand: &Operand, value: Value) -> Result<(), String> {
        match operand {
            Operand::Reg(reg) => {
                let i = full(*reg)?;
                if i == 4 {
                    return Err("dispatch: unproved ESP assignment".into());
                }
                self.registers[i] = value;
            }
            Operand::Memory(a, 32) => match self.address(a)? {
                Place::Stack(at) => {
                    if self.stack[&at].kind != Kind::Local {
                        return Err("dispatch: protected stack write".into());
                    }
                    scalar(&value)?;
                    self.stack.get_mut(&at).unwrap().value = value;
                }
                Place::Cursor => {
                    let (expression, known) = scalar(&value)?;
                    let n = known.ok_or("dispatch: unknown parent cursor")?;
                    self.cursor = n as i32;
                    self.cursor_writes += 1;
                    self.source
                        .push_str(&format!("*cursor={expression} as i32;\n"));
                    self.live_source
                        .push_str(&format!("effects.write_cursor({expression} as i32)?;\n"));
                }
                Place::Local | Place::Trace => {
                    let (expression, _) = scalar(&value)?;
                    let index = if matches!(self.address(a)?, Place::Trace) {
                        0
                    } else {
                        1
                    };
                    self.source
                        .push_str(&format!("cells[{index}]={expression};\n"));
                    self.live_source
                        .push_str(&format!("effects.write_cell({index},{expression})?;\n"));
                }
                Place::Table(..) => return Err("dispatch: immutable table write".into()),
            },
            _ => return Err("dispatch: write form".into()),
        }
        Ok(())
    }
    fn adjust(&mut self, amount: i32) -> Result<(), String> {
        if amount % 4 != 0 {
            return Err("dispatch: unaligned stack adjustment".into());
        }
        let next = self
            .sp
            .checked_add(amount)
            .ok_or("dispatch: stack overflow")?;
        if !(-256..=0).contains(&next) {
            return Err("dispatch: stack budget/boundary".into());
        }
        if next < self.sp {
            for at in (next..self.sp).step_by(4) {
                if self.stack.contains_key(&at) {
                    return Err("dispatch: overlapping allocation".into());
                }
                self.stack.insert(
                    at,
                    Slot {
                        value: Value::Unknown,
                        kind: Kind::Local,
                    },
                );
            }
        } else {
            for at in (self.sp..next).step_by(4) {
                let slot = self.stack.get(&at).ok_or("dispatch: absent stack slot")?;
                if !matches!(slot.kind, Kind::Local | Kind::Argument) {
                    return Err("dispatch: cleanup crosses saved/return slot".into());
                }
            }
            for at in (self.sp..next).step_by(4) {
                self.stack.remove(&at);
            }
        }
        self.sp = next;
        self.temporary_bytes = self.temporary_bytes.max(next.unsigned_abs());
        self.registers[4] = Value::Stack(next);
        self.flags = None;
        Ok(())
    }
    fn call(&mut self, operand: &Operand) -> Result<(), String> {
        let Value::Function(action) = self.read(operand)? else {
            return Err("dispatch: unbound call".into());
        };
        if !self.calls.is_empty() {
            return Err("dispatch: multiple cleanup calls".into());
        }
        let entry_depth = self
            .sp
            .unsigned_abs()
            .checked_add(4)
            .ok_or("dispatch: cleanup CALL stack overflow")?;
        let argument = self
            .stack
            .get(&self.sp)
            .ok_or("dispatch: missing cleanup argument")?;
        if argument.kind != Kind::Argument {
            return Err("dispatch: protected cleanup argument".into());
        }
        let Value::Stack(start) = argument.value else {
            return Err("dispatch: cleanup pointer provenance".into());
        };
        let second = start
            .checked_add(4)
            .ok_or("dispatch: cleanup range overflow")?;
        let mut values = Vec::new();
        for at in [start, second] {
            let slot = self
                .stack
                .get(&at)
                .ok_or("dispatch: incomplete cleanup cells")?;
            if slot.kind != Kind::Local {
                return Err("dispatch: cleanup aliases protected metadata".into());
            }
            values.push(scalar(&slot.value)?.0);
        }
        let name = format!("call{}", self.serial);
        self.serial += 1;
        self.source.push_str(&format!(
            "let mut {name}=[{},{}];\ncleanup_{action}(&mut {name})?;\n",
            values[0], values[1]
        ));
        self.live_source.push_str(&format!(
            "let mut {name}=[{},{}];\neffects.cleanup({action},&mut {name})?;\n",
            values[0], values[1]
        ));
        for (index, at) in [start, second].into_iter().enumerate() {
            let v = self.snapshot(format!("{name}[{index}]"), None);
            self.stack.get_mut(&at).unwrap().value = v;
        }
        for i in [0, 1, 2] {
            self.registers[i] = Value::Unknown;
        }
        self.flags = None;
        self.calls.push(action);
        self.cleanup_entry_depth = Some(entry_depth);
        self.temporary_bytes = self.temporary_bytes.max(entry_depth);
        Ok(())
    }
}

/// ABI: valid helper stack with protected return, cursor pointer at ESP+4 and
/// local pointer at ESP+8. Trace/local/cursor are distinct owned scalar cells.
/// The metadata and callback bodies must already be bound to original image data.
pub(crate) fn prove_dispatch(
    code: &[u8],
    origin: u32,
    table_va: u32,
    rows: &[(i32, u32)],
    trace_va: u32,
    bindings: &BTreeMap<u32, usize>,
    entry: i32,
) -> Result<ProvenDispatch, String> {
    if code.is_empty()
        || code.len() > 1024
        || rows.is_empty()
        || rows.len() > 32
        || entry < 0
        || entry as usize >= rows.len()
    {
        return Err("dispatch: entry/resource bounds".into());
    }
    let end = origin
        .checked_add(code.len() as u32)
        .ok_or("dispatch: code overflow")?;
    let table_end = table_va
        .checked_add((rows.len() * 8) as u32)
        .ok_or("dispatch: table overflow")?;
    let trace_end = trace_va.checked_add(4).ok_or("dispatch: trace overflow")?;
    if table_va < trace_end && trace_va < table_end {
        return Err("dispatch: trace/table alias".into());
    }
    let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
    let mut instructions = BTreeMap::new();
    while decoder.can_decode() {
        let i = decoder.decode();
        if i.is_invalid() {
            return Err("dispatch: malformed instruction boundary".into());
        }
        instructions.insert(i.ip() as u32, i);
    }
    let mut registers = std::array::from_fn(|i| {
        if [3, 5, 6, 7].contains(&i) {
            Value::Saved(i as u8)
        } else {
            Value::Unknown
        }
    });
    registers[4] = Value::Stack(0);
    let stack = BTreeMap::from([
        (
            0,
            Slot {
                value: Value::Return,
                kind: Kind::Protected,
            },
        ),
        (
            4,
            Slot {
                value: Value::Cursor,
                kind: Kind::Protected,
            },
        ),
        (
            8,
            Slot {
                value: Value::Local,
                kind: Kind::Protected,
            },
        ),
    ]);
    let mut s = State {
        registers,
        stack,
        sp: 0,
        cursor: entry,
        cursor_writes: 0,
        calls: Vec::new(),
        temporary_bytes: 0,
        cleanup_entry_depth: None,
        flags: None,
        source: format!("if *cursor!={entry}i32 {{return Err(Error::Order);}}\n"),
        live_source: format!("effects.require_cursor({entry})?;\n"),
        serial: 0,
        table_va,
        trace_va,
        rows,
        bindings,
    };
    let mut pc = origin;
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(pc) || visited.len() > 128 {
            return Err("dispatch: cycle/instruction budget".into());
        }
        let i = instructions
            .get(&pc)
            .ok_or("dispatch: target not instruction boundary")?;
        let next = pc
            .checked_add(i.len() as u32)
            .ok_or("dispatch: IP overflow")?;
        let operation =
            graph::normalized(i, &code[(pc - origin) as usize..(next - origin) as usize])?;
        let mut successor = next;
        match operation {
            Operation::Binary(Binary::Move, dst, src) => {
                let value = s.read(&src)?;
                if value == Value::Unknown || value == Value::Return {
                    return Err("dispatch: unknown/protected value read".into());
                }
                s.write(&dst, value)?;
            }
            Operation::Binary(op, Operand::Reg(reg), Operand::Immediate(n))
                if reg.index == 4 && reg.width == 32 && matches!(op, Binary::Add | Binary::Sub) =>
            {
                let n = i32::try_from(n).map_err(|_| "dispatch: stack adjustment amount")?;
                s.adjust(if op == Binary::Add { n } else { -n })?;
            }
            Operation::Binary(Binary::Compare, left, right) => {
                let (_, a) = scalar(&s.read(&left)?)?;
                let (_, b) = scalar(&s.read(&right)?)?;
                s.flags = a.zip(b).map(|(a, b)| (a < b, a == b));
            }
            Operation::Push(operand) => {
                let value = s.read(&operand)?;
                if value == Value::Unknown || value == Value::Return {
                    return Err("dispatch: unknown/protected push".into());
                }
                let kind = if let Value::Saved(reg) = value {
                    Kind::Save(reg)
                } else {
                    Kind::Argument
                };
                let next = s.sp.checked_sub(4).ok_or("dispatch: push overflow")?;
                if next < -256 || s.stack.contains_key(&next) {
                    return Err("dispatch: push ownership/budget".into());
                }
                s.stack.insert(next, Slot { value, kind });
                s.sp = next;
                s.temporary_bytes = s.temporary_bytes.max(next.unsigned_abs());
                s.registers[4] = Value::Stack(next);
            }
            Operation::Pop(reg) => {
                let index = full(reg)?;
                if index == 4 {
                    return Err("dispatch: POP ESP outside policy".into());
                }
                let slot = s.stack.remove(&s.sp).ok_or("dispatch: absent pop slot")?;
                if matches!(slot.kind, Kind::Protected | Kind::Local)
                    || matches!(slot.kind,Kind::Save(original) if original!=reg.index)
                {
                    return Err("dispatch: protected/mismatched pop".into());
                }
                s.registers[index] = slot.value;
                s.sp += 4;
                s.registers[4] = Value::Stack(s.sp);
            }
            Operation::Address(reg, a) => {
                let index = full(reg)?;
                if index == 4 {
                    return Err("dispatch: LEA ESP outside policy".into());
                }
                let Place::Stack(offset) = s.address(&a)? else {
                    return Err("dispatch: non-stack LEA".into());
                };
                s.registers[index] = Value::Stack(offset);
            }
            Operation::Call(operand) => s.call(&operand)?,
            Operation::Branch(condition, target) => {
                let (carry, zero) = s.flags.ok_or("dispatch: unknown branch flags")?;
                let taken = match condition {
                    Condition::Equal => zero,
                    Condition::NotEqual => !zero,
                    Condition::Below => carry,
                    Condition::Above => !carry && !zero,
                    Condition::BelowEqual => carry || zero,
                    Condition::AboveEqual => !carry,
                };
                if !instructions.contains_key(&target) {
                    return Err("dispatch: branch target boundary".into());
                }
                if taken {
                    successor = target;
                }
            }
            Operation::Jump(target) => successor = target,
            Operation::Return => {
                if s.sp != 0
                    || s.stack.len() != 3
                    || s.calls.len() != 1
                    || s.cursor_writes != 1
                    || s.cursor != rows[entry as usize].0
                    || [3, 5, 6, 7]
                        .iter()
                        .any(|&r| s.registers[r] != Value::Saved(r as u8))
                {
                    return Err("dispatch: return ownership/cursor/call proof".into());
                }
                s.source.push_str("Ok(())\n");
                s.live_source.push_str("Ok(())\n");
                return Ok(ProvenDispatch {
                    source: s.source,
                    live_source: s.live_source,
                    parent: s.cursor,
                    action: s.calls[0],
                    temporary_bytes: s.temporary_bytes,
                    cleanup_entry_depth: s
                        .cleanup_entry_depth
                        .ok_or("dispatch: missing cleanup depth")?,
                });
            }
            Operation::Nop => {}
            _ => return Err("dispatch: unsupported reachable effect".into()),
        }
        if successor < origin || successor >= end {
            return Err("dispatch: successor bounds".into());
        }
        pc = successor;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const TABLE: u32 = 0x5000;
    const TRACE: u32 = 0x6000;
    fn bindings() -> BTreeMap<u32, usize> {
        BTreeMap::from([(0x7000, 0), (0x7100, 1), (0x7200, 2)])
    }
    fn rows() -> [(i32, u32); 3] {
        [(1, 0x7000), (-1, 0x7100), (-1, 0x7200)]
    }
    // Independently authored ESI/EDI layout, different from MSVC's EBX/EDI/ESI
    // layout. Local scalar snapshots cross an indirect call and original stores.
    fn code() -> Vec<u8> {
        let mut b = vec![
            0x83, 0xec, 8, 0x56, 0x57, 0x8b, 0x74, 0x24, 20, 0x8b, 0x7c, 0x24, 24, 0x8b, 6, 0x83,
            0xf8, 2, 0x77, 0,
        ];
        b.extend([0x8b, 0x0d]);
        b.extend(TRACE.to_le_bytes());
        b.extend([
            0x89, 0x4c, 0x24, 8, 0x8b, 0x0f, 0x89, 0x4c, 0x24, 12, 0x8d, 0x4c, 0x24, 8, 0x51, 0x8b,
            4, 0xc5,
        ]);
        b.extend((TABLE + 4).to_le_bytes());
        b.extend([0xff, 0xd0, 0x83, 0xc4, 4, 0x8b, 0x4c, 0x24, 8, 0x89, 0x0d]);
        b.extend(TRACE.to_le_bytes());
        b.extend([0x8b, 0x4c, 0x24, 12, 0x89, 0x0f, 0x8b, 6, 0x8b, 4, 0xc5]);
        b.extend(TABLE.to_le_bytes());
        b.extend([0x89, 6, 0x5f, 0x5e, 0x83, 0xc4, 8, 0xc3]);
        b[19] = (b.len() - 20) as u8;
        b.push(0xcc);
        b
    }
    fn proof(bytes: &[u8], entry: i32) -> Result<ProvenDispatch, String> {
        prove_dispatch(bytes, 0x1000, TABLE, &rows(), TRACE, &bindings(), entry)
    }
    fn replace(bytes: &mut [u8], from: &[u8], to: &[u8]) {
        assert_eq!(from.len(), to.len());
        let at = bytes.windows(from.len()).position(|x| x == from).unwrap();
        bytes[at..at + to.len()].copy_from_slice(to);
    }
    #[test]
    fn temporary_stack_depth_tracks_allocations_saves_arguments_and_call_return() {
        for allocation in [8u8, 12, 28] {
            let mut bytes = code();
            bytes[2] = allocation;
            replace(
                &mut bytes,
                &[0x8b, 0x74, 0x24, 20],
                &[0x8b, 0x74, 0x24, allocation + 12],
            );
            replace(
                &mut bytes,
                &[0x8b, 0x7c, 0x24, 24],
                &[0x8b, 0x7c, 0x24, allocation + 16],
            );
            replace(
                &mut bytes,
                &[0x83, 0xc4, 8, 0xc3],
                &[0x83, 0xc4, allocation, 0xc3],
            );
            let proof = proof(&bytes, 0).unwrap();
            // Two saved registers (8), one argument (4), CALL return (4).
            let expected = u32::from(allocation) + 16;
            assert_eq!(proof.temporary_bytes, expected);
            assert_eq!(proof.cleanup_entry_depth, expected);
            assert_eq!(proof.with_cleanup_depth(0).unwrap(), expected);
            assert_eq!(proof.with_cleanup_depth(20).unwrap(), expected + 20);
            assert!(proof.with_cleanup_depth(u32::MAX).is_err());
        }
        // A deeper owned allocation, released before CALL, remains part of the
        // required temporary extent even when the later call is shallower.
        let mut bytes = code();
        bytes.splice(0..0, [0x83, 0xec, 60, 0x83, 0xc4, 60]);
        let proof = proof(&bytes, 0).unwrap();
        assert_eq!(proof.temporary_bytes, 60);
        assert_eq!(proof.cleanup_entry_depth, 24);
        assert_eq!(proof.with_cleanup_depth(20).unwrap(), 60);
        assert_eq!(proof.with_cleanup_depth(40).unwrap(), 64);
    }
    #[test]
    fn independent_stack_layout_keeps_runtime_values_and_original_cursor_effects() {
        for entry in 0..3 {
            let p = proof(&code(), entry).unwrap();
            assert_eq!(p.parent, rows()[entry as usize].0);
            assert_eq!(p.action, entry as usize);
            assert_eq!(p.source, proof(&code(), entry).unwrap().source);
        }
        let mut source = String::from("#[derive(Debug)] enum Error {Order}\n");
        for (i, delta) in [7u32, 11, 13].into_iter().enumerate() {
            source.push_str(&format!("fn cleanup_{i}(cells:&mut[u32;2])->Result<(),Error>{{cells[0]=cells[0].wrapping_mul(16).wrapping_add({}u32);cells[1]=cells[1].wrapping_add({delta});Ok(())}}\n",i+1));
        }
        for i in 0..3 {
            source.push_str(&format!(
                "fn dispatch_{i}(cells:&mut[u32;2],cursor:&mut i32)->Result<(),Error>{{{}}}\n",
                proof(&code(), i).unwrap().source
            ));
        }
        source.push_str("fn main(){let mut c=[0,100];let mut k=0;dispatch_0(&mut c,&mut k).unwrap();assert_eq!(c,[1,107]);assert_eq!(k,1);dispatch_1(&mut c,&mut k).unwrap();assert_eq!(c,[18,118]);assert_eq!(k,-1);c=[18,200];k=2;dispatch_2(&mut c,&mut k).unwrap();assert_eq!(c,[291,213]);assert_eq!(k,-1);c=[u32::MAX,u32::MAX];k=0;dispatch_0(&mut c,&mut k).unwrap();assert_eq!(c,[0xfffffff1,6]);let before=c;k=1;assert!(dispatch_0(&mut c,&mut k).is_err());assert_eq!(c,before);assert_eq!(k,1);}");
        let dir = std::env::temp_dir().join(format!("w2l-dispatch-native-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("test.rs");
        let bin = dir.join(if cfg!(windows) { "test.exe" } else { "test" });
        std::fs::write(&file, source).unwrap();
        let out = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(&file)
            .arg("-o")
            .arg(&bin)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(std::process::Command::new(&bin).status().unwrap().success());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn live_effects_preserve_original_store_order_and_private_failure_boundary() {
        let p = proof(&code(), 0).unwrap();
        let source = format!(
            r#"
        #[derive(Debug,PartialEq)]struct Failure;
        struct Effects{{cells:[u32;2],cursor:i32,fail:u8,private:Option<[u32;2]>}}
        impl Effects{{
         fn require_cursor(&mut self,n:i32)->Result<(),Failure>{{if self.cursor==n{{Ok(())}}else{{Err(Failure)}}}}
         fn read_cursor(&mut self)->Result<i32,Failure>{{Ok(self.cursor)}}
         fn read_cell(&mut self,i:usize)->Result<u32,Failure>{{Ok(self.cells[i])}}
         fn write_cell(&mut self,i:usize,v:u32)->Result<(),Failure>{{if self.fail==i as u8+2{{return Err(Failure)}}self.cells[i]=v;Ok(())}}
         fn write_cursor(&mut self,v:i32)->Result<(),Failure>{{if self.fail==4{{return Err(Failure)}}self.cursor=v;Ok(())}}
         fn cleanup(&mut self,a:usize,c:&mut[u32;2])->Result<(),Failure>{{assert_eq!(a,0);c[0]=c[0].wrapping_mul(16).wrapping_add(1);c[1]=c[1].wrapping_add(7);self.private=Some(*c);if self.fail==1{{Err(Failure)}}else{{Ok(())}}}}
        }}
        fn run(effects:&mut Effects)->Result<(),Failure>{{{}}}
        fn main(){{
         for (fail,expected,cursor) in [(0,[49,107],1),(1,[3,100],0),(2,[3,100],0),(3,[49,100],0),(4,[49,107],0)]{{
          let mut e=Effects{{cells:[3,100],cursor:0,fail,private:None}};assert_eq!(run(&mut e).is_ok(),fail==0);assert_eq!(e.cells,expected);assert_eq!(e.cursor,cursor);assert_eq!(e.private,Some([49,107]));
         }}
         let mut e=Effects{{cells:[u32::MAX,u32::MAX],cursor:0,fail:0,private:None}};run(&mut e).unwrap();assert_eq!(e.cells,[0xfffffff1,6]);
         e.cursor=2;let before=e.cells;assert!(run(&mut e).is_err());assert_eq!(e.cells,before);
        }}"#,
            p.live_source
        );
        let dir = std::env::temp_dir().join(format!("w2l-dispatch-live-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("test.rs");
        let bin = dir.join(if cfg!(windows) { "test.exe" } else { "test" });
        std::fs::write(&file, source).unwrap();
        let out = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(&file)
            .arg("-o")
            .arg(&bin)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(std::process::Command::new(&bin).status().unwrap().success());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn guarded_failure_unknown_cursor_and_protected_slot_mutations_reject() {
        let changes: &[(&[u8], &[u8])] = &[
            (&[0x8b, 0x74, 0x24, 20], &[0x8b, 0x74, 0x24, 24]),
            (&[0x8b, 0x7c, 0x24, 24], &[0x8b, 0x7c, 0x24, 20]),
            (&[0x83, 0xf8, 2], &[0x83, 0xf8, 1]),
            (&[0x5f, 0x5e], &[0x5c, 0x5e]),
            (&[0x5f, 0x5e], &[0x5e, 0x5f]),
            (&[0x83, 0xc4, 4], &[0x83, 0xc4, 8]),
            (&[0x89, 0x4c, 0x24, 8], &[0x89, 0x4c, 0x24, 0]),
            (&[0x8d, 0x4c, 0x24, 8], &[0x8d, 0x4c, 0x24, 4]),
            (&[0x89, 6, 0x5f], &[0x89, 7, 0x5f]),
        ];
        for (old, new) in changes {
            let mut b = code();
            replace(&mut b, old, new);
            assert!(proof(&b, 2).is_err(), "accepted mutation {new:02x?}");
        }
        let mut guard = code();
        guard[18] = 0x72;
        assert!(proof(&guard, 0).is_err());
        let mut target = code();
        replace(
            &mut target,
            &(TABLE + 4).to_le_bytes(),
            &TABLE.to_le_bytes(),
        );
        assert!(proof(&target, 0).is_err());
        assert!(proof(&code(), -1).is_err());
        assert!(proof(&code(), 3).is_err());
    }
    #[test]
    fn metadata_alias_truncation_and_proof_resources_reject() {
        assert!(
            prove_dispatch(&code(), 0x1000, TABLE, &rows(), TABLE + 4, &bindings(), 0).is_err()
        );
        let mut missing = bindings();
        missing.remove(&0x7000);
        assert!(prove_dispatch(&code(), 0x1000, TABLE, &rows(), TRACE, &missing, 0).is_err());
        let bytes = code();
        for end in 0..bytes.len() - 1 {
            assert!(proof(&bytes[..end], 0).is_err(), "accepted truncated {end}");
        }
        let mut over = [0x90].repeat(129);
        over.extend(code());
        assert!(proof(&over, 0).is_err());
        assert!(
            prove_dispatch(&code(), u32::MAX - 4, TABLE, &rows(), TRACE, &bindings(), 0).is_err()
        );
    }
}
