//! Private whole-graph frame-shape proof. Scalar bounds and initialization are
//! deliberately separate obligations: a Frame value is provenance, not access.
use super::{graph::*, Bound, Function};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Value {
    Unknown,
    Entry(u8),
    Scalar,
    Constant(u32),
    Frame(Option<i32>),
    Handle(u32),
    Boolean,
    Error,
    ErrorAffine(u32, u32),
    Function(Function),
}
impl Value {
    fn join(self, rhs: Self) -> Self {
        if self == rhs {
            return self;
        }
        match (self, rhs) {
            (Self::Constant(_) | Self::Scalar, Self::Constant(_) | Self::Scalar) => Self::Scalar,
            (Self::Frame(_), Self::Frame(_)) => Self::Frame(None),
            _ => Self::Unknown,
        }
    }
    fn affine(self) -> Option<(u32, u32)> {
        match self {
            Self::Error => Some((1, 0)),
            Self::ErrorAffine(a, b) => Some((a, b)),
            _ => None,
        }
    }
    fn error_zero_safe(self) -> bool {
        self.affine()
            .is_some_and(|(a, b)| a.wrapping_mul(109).wrapping_add(b) == 0)
    }
    pub(super) fn scalar(self) -> bool {
        matches!(self, Self::Scalar | Self::Constant(_))
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Slot {
    Saved(u8),
    Argument(Value),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct State {
    pub(super) registers: [Value; 8],
    pub(super) finite: BTreeMap<i32, BTreeSet<u32>>,
    pub(super) sp: i32,
    pub(super) known: [u8; 8],
    pub(super) initialized: std::collections::BTreeSet<i32>,
    pub(super) argument_known: BTreeMap<i32, u8>,
    pub(super) cf_known: bool,
    pub(super) zf_known: bool,
    pub(super) local_values: BTreeMap<i32, Value>,
    pub(super) locals: BTreeMap<i32, i32>,
    pub(super) slots: BTreeMap<i32, Slot>,
}
#[derive(Debug)]
pub(super) struct Frames {
    pub(super) states: BTreeMap<u32, State>,
}
fn require(ok: bool, text: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(format!("stream frame: {text}"))
    }
}
impl State {
    fn entry() -> Self {
        let mut registers = std::array::from_fn(|i| Value::Entry(i as u8));
        registers[4] = Value::Frame(Some(0));
        Self {
            registers,
            finite: BTreeMap::new(),
            sp: 0,
            known: [0, 0, 0, 0, 32, 0, 0, 0],
            initialized: Default::default(),
            argument_known: Default::default(),
            cf_known: false,
            zf_known: false,
            local_values: BTreeMap::new(),
            locals: BTreeMap::new(),
            slots: BTreeMap::new(),
        }
    }
    fn set_sp(&mut self, sp: i32) -> Result<(), String> {
        require(
            (-4096..=0).contains(&sp) && sp % 4 == 0,
            "stack coordinate/budget",
        )?;
        self.sp = sp;
        self.registers[4] = Value::Frame(Some(sp));
        Ok(())
    }
    pub(super) fn region(&self, at: i32, bytes: i32) -> bool {
        bytes >= 0
            && self
                .locals
                .iter()
                .any(|(&lo, &hi)| at >= lo && at.checked_add(bytes).is_some_and(|end| end <= hi))
    }
    pub(super) fn address(&self, a: &Address) -> Result<Value, String> {
        let b = a
            .base
            .map(|i| self.registers[i as usize])
            .ok_or("stream frame: address lacks owner")?;
        let Value::Frame(offset) = b else {
            return Err("stream frame: address base lacks frame provenance".into());
        };
        let mut offset = offset.map(|x| i64::from(x) + i64::from(a.displacement as i32));
        if let Some(i) = a.index {
            offset = match self.registers[i as usize] {
                Value::Constant(v) => offset.map(|x| x + i64::from(v) * i64::from(a.scale)),
                Value::Scalar => None,
                _ => return Err("stream frame: index is not scalar".into()),
            };
        }
        let offset = offset
            .map(i32::try_from)
            .transpose()
            .map_err(|_| "stream frame: address offset overflow")?;
        Ok(Value::Frame(offset))
    }
    pub(super) fn operand(&self, o: &Operand, load: Option<Function>) -> Result<Value, String> {
        Ok(match o {
            Operand::Immediate(n) => Value::Constant(*n),
            Operand::Reg(r) if r.width == 32 => self.registers[r.index as usize],
            // Unknown upper bits are not made known here. Scalar knowledge and
            // width masks must be proved separately before any actual read.
            Operand::Reg(r) => {
                require(
                    matches!(
                        self.registers[r.index as usize],
                        Value::Scalar | Value::Constant(_) | Value::Entry(_) | Value::Unknown
                    ),
                    "partial read of opaque value",
                )?;
                Value::Scalar
            }
            Operand::Memory(a, _) if a.base.is_none() && a.index.is_none() => {
                Value::Function(load.ok_or("stream frame: unbound IAT load")?)
            }
            Operand::Memory(a, width) => {
                if let Value::Frame(Some(at)) = self.address(a)? {
                    require(
                        self.region(at, i32::from(*width / 8)),
                        "load crosses local/protected boundary",
                    )?;
                }
                if *width == 32 {
                    if let Value::Frame(Some(at)) = self.address(a)? {
                        return Ok(*self.local_values.get(&at).unwrap_or(&Value::Scalar));
                    }
                }
                Value::Scalar
            }
        })
    }
    fn put(&mut self, dst: &Operand, value: Value) -> Result<(), String> {
        match dst {
            Operand::Reg(r) => {
                require(r.index != 4, "unsupported direct ESP assignment")?;
                self.registers[r.index as usize] =
                    if r.width == 32 { value } else { Value::Scalar };
            }
            Operand::Memory(a, width) => {
                require(
                    value.scalar() || (*width == 32 && matches!(value, Value::Handle(_))),
                    "non-scalar local store",
                )?;
                if let Value::Frame(Some(at)) = self.address(a)? {
                    require(
                        self.region(at, i32::from(*width / 8)),
                        "store crosses local/protected boundary",
                    )?;
                    if *width == 32 {
                        require(at % 4 == 0, "local word alignment")?;
                        self.local_values.insert(at, value);
                    }
                }
            }
            _ => return Err("stream frame: destination".into()),
        }
        Ok(())
    }
    fn push(&mut self, value: Value) -> Result<(), String> {
        self.set_sp(
            self.sp
                .checked_sub(4)
                .ok_or("stream frame: push overflow")?,
        )?;
        require(
            !self.region(self.sp, 4) && !self.slots.contains_key(&self.sp),
            "push overlaps live storage",
        )?;
        let slot = match value {
            Value::Entry(i) if [3, 5, 6, 7].contains(&i) => Slot::Saved(i),
            _ => Slot::Argument(value),
        };
        self.slots.insert(self.sp, slot);
        Ok(())
    }
    fn pop(&mut self, register: u8) -> Result<(), String> {
        let slot = self
            .slots
            .remove(&self.sp)
            .ok_or("stream frame: pop local/return/unowned word")?;
        self.registers[register as usize] = match slot {
            Slot::Saved(i) => {
                require(register == i, "saved register owner mismatch")?;
                Value::Entry(i)
            }
            Slot::Argument(v) => v,
        };
        self.set_sp(self.sp + 4)
    }
    fn allocate(&mut self, bytes: u32) -> Result<(), String> {
        require(
            bytes != 0 && bytes <= 4096 && bytes.is_multiple_of(4),
            "local allocation size",
        )?;
        let hi = self.sp;
        let lo = hi - bytes as i32;
        require(
            !self.locals.iter().any(|(&a, &b)| lo < b && a < hi)
                && !self.slots.range(lo..hi).any(|_| true),
            "allocation overlap",
        )?;
        self.set_sp(lo)?;
        self.locals.insert(lo, hi);
        Ok(())
    }
    fn deallocate(&mut self, bytes: u32) -> Result<(), String> {
        require(bytes <= 4096, "cleanup size")?;
        let hi = self.sp + bytes as i32;
        require(
            self.locals.get(&self.sp) == Some(&hi),
            "cleanup is not exactly one owned local allocation",
        )?;
        self.local_values.retain(|at, _| *at < self.sp || *at >= hi);
        self.locals.remove(&self.sp);
        self.set_sp(hi)
    }
    pub(super) fn arguments(&self, n: usize) -> Result<Vec<Value>, String> {
        (0..n)
            .map(|i| match self.slots.get(&(self.sp + i as i32 * 4)) {
                Some(Slot::Argument(v)) => Ok(*v),
                _ => Err("stream frame: call consumes protected/unowned argument".into()),
            })
            .collect()
    }
    fn call(&mut self, f: Function) -> Result<(), String> {
        let n = match f {
            Function::Read | Function::Write => 5,
            Function::StandardHandle => 1,
            Function::LastError => 0,
        };
        let args = self.arguments(n)?;
        let ret = match f {
            Function::StandardHandle => {
                require(
                    matches!(args[0], Value::Constant(0xfffffff6 | 0xfffffff5)),
                    "standard handle selector",
                )?;
                let Value::Constant(k) = args[0] else {
                    unreachable!()
                };
                Value::Handle(k)
            }
            Function::Read | Function::Write => {
                let selector = if f == Function::Read {
                    0xfffffff6
                } else {
                    0xfffffff5
                };
                require(args[0] == Value::Handle(selector), "I/O handle provenance")?;
                require(
                    matches!(args[1], Value::Frame(_)) && args[2].scalar(),
                    "I/O buffer/count provenance",
                )?;
                let Value::Frame(Some(at)) = args[3] else {
                    return Err("stream frame: count-cell address must be fixed".into());
                };
                require(at % 4 == 0 && self.region(at, 4), "count-cell full range")?;
                require(args[4] == Value::Constant(0), "overlapped I/O unsupported")?;
                Value::Boolean
            }
            Function::LastError => Value::Error,
        };
        for i in 0..n {
            self.slots.remove(&(self.sp + i as i32 * 4));
        }
        self.set_sp(self.sp + n as i32 * 4)?;
        self.registers[0] = ret;
        self.registers[1] = Value::Unknown;
        self.registers[2] = Value::Unknown;
        Ok(())
    }
    fn join(&mut self, rhs: &Self) -> Result<bool, String> {
        require(
            self.sp == rhs.sp
                && self.locals == rhs.locals
                && self.slots.keys().eq(rhs.slots.keys()),
            "incompatible frame shapes at join",
        )?;
        let old = self.clone();
        self.finite.retain(|key, values| {
            let Some(other) = rhs.finite.get(key) else {
                return false;
            };
            values.extend(other);
            values.len() <= 8
        });
        for (a, b) in self.known.iter_mut().zip(rhs.known) {
            *a = (*a).min(b);
        }
        self.initialized.retain(|at| rhs.initialized.contains(at));
        let keys: std::collections::BTreeSet<_> = self
            .local_values
            .keys()
            .chain(rhs.local_values.keys())
            .copied()
            .collect();
        for at in keys {
            let v = self
                .local_values
                .get(&at)
                .copied()
                .unwrap_or(Value::Unknown)
                .join(rhs.local_values.get(&at).copied().unwrap_or(Value::Unknown));
            self.local_values.insert(at, v);
            if v == Value::Unknown {
                self.initialized.remove(&at);
            }
        }
        self.argument_known.retain(|at, k| {
            *k = (*k).min(*rhs.argument_known.get(at).unwrap_or(&0));
            true
        });
        self.cf_known &= rhs.cf_known;
        self.zf_known &= rhs.zf_known;
        for (a, b) in self.registers.iter_mut().zip(rhs.registers) {
            *a = a.join(b);
        }
        for (offset, slot) in &mut self.slots {
            match (slot, &rhs.slots[offset]) {
                (Slot::Saved(a), Slot::Saved(b)) => require(a == b, "saved owner join")?,
                (Slot::Argument(a), Slot::Argument(b)) => *a = a.join(*b),
                _ => return Err("stream frame: protected/argument join".into()),
            }
        }
        for i in 0..8 {
            if matches!(self.registers[i], Value::Unknown | Value::Entry(_)) {
                self.known[i] = 0;
            }
        }
        Ok(*self != old)
    }
    fn bits(&self, o: &Operand) -> u8 {
        match o {
            Operand::Immediate(_) => 32,
            Operand::Reg(r) => self.known[r.index as usize],
            Operand::Memory(a, _) if a.base.is_none() && a.index.is_none() => 32,
            Operand::Memory(_, 8) => 8, // Conditional on mandatory SMT prefix proof.
            Operand::Memory(a, 32) => match self.address(a) {
                Ok(Value::Frame(Some(at))) if self.initialized.contains(&at) => 32,
                _ => 0,
            },
            _ => 0,
        }
    }
    fn finite_operand(&self, o: &Operand) -> Option<BTreeSet<u32>> {
        match o {
            Operand::Immediate(n) => Some(BTreeSet::from([*n])),
            Operand::Reg(Reg { index, width: 32 }) => self.finite.get(&i32::from(*index)).cloned(),
            Operand::Memory(a, 32) => match self.address(a).ok()? {
                Value::Frame(Some(at)) => self.finite.get(&at).cloned(),
                _ => None,
            },
            _ => None,
        }
    }
    fn finite_step(&mut self, before: &Self, op: &Operation, call: Option<Function>) {
        let assign = |state: &mut Self, key: i32, values: Option<BTreeSet<u32>>| {
            if let Some(v) = values.filter(|v| v.len() <= 8) {
                state.finite.insert(key, v);
            } else {
                state.finite.remove(&key);
            }
        };
        match op {
            Operation::Binary(op, dst, src) if !matches!(op, Binary::Compare | Binary::Test) => {
                let values = if *op == Binary::Move {
                    before.finite_operand(src)
                } else if *op == Binary::Xor && dst == src {
                    Some(BTreeSet::from([0]))
                } else {
                    before
                        .finite_operand(dst)
                        .zip(before.finite_operand(src))
                        .and_then(|(a, b)| {
                            let mut values = BTreeSet::new();
                            for a in a {
                                for &b in &b {
                                    values.insert(match op {
                                        Binary::Add => a.wrapping_add(b),
                                        Binary::Sub => a.wrapping_sub(b),
                                        Binary::And => a & b,
                                        Binary::Xor => a ^ b,
                                        _ => return None,
                                    });
                                }
                            }
                            Some(values)
                        })
                };
                match dst {
                    Operand::Reg(r) => assign(
                        self,
                        i32::from(r.index),
                        if r.width == 32 { values } else { None },
                    ),
                    Operand::Memory(a, 32) => {
                        if let Ok(Value::Frame(Some(at))) = before.address(a) {
                            assign(self, at, values);
                        }
                    }
                    // Byte regions are disjoint from all tracked words in the mandatory layout proof.
                    _ => (),
                }
            }
            Operation::ZeroExtend(dst, src) => {
                let values = before
                    .finite
                    .get(&i32::from(src.index))
                    .map(|v| v.iter().map(|x| x & 255).collect());
                assign(self, i32::from(dst.index), values);
            }
            Operation::ConditionalMove(_, dst, src) => {
                let values = before
                    .finite_operand(&Operand::Reg(*dst))
                    .zip(before.finite_operand(&Operand::Reg(*src)))
                    .map(|(mut a, b)| {
                        a.extend(b);
                        a
                    });
                assign(self, i32::from(dst.index), values);
            }
            Operation::Increment(r) | Operation::Decrement(r) | Operation::Negate(r) => {
                let values = before.finite_operand(&Operand::Reg(*r)).map(|v| {
                    v.into_iter()
                        .map(|v| match op {
                            Operation::Increment(_) => v.wrapping_add(1),
                            Operation::Decrement(_) => v.wrapping_sub(1),
                            _ => v.wrapping_neg(),
                        })
                        .collect()
                });
                assign(self, i32::from(r.index), values);
            }
            Operation::Address(r, _) => assign(self, i32::from(r.index), None),
            Operation::Push(o) => assign(self, self.sp, before.finite_operand(o)),
            Operation::Pop(r) => {
                assign(
                    self,
                    i32::from(r.index),
                    before.finite.get(&before.sp).cloned(),
                );
                self.finite.remove(&before.sp);
            }
            Operation::Leave => {
                self.finite.remove(&5);
                self.finite.retain(|k, _| *k >= 0);
            }
            Operation::Call(_) => {
                for r in 0..3 {
                    self.finite.remove(&r);
                }
                if matches!(call, Some(Function::Read | Function::Write)) {
                    self.finite.insert(0, BTreeSet::from([0, 1]));
                    if let Ok(args) = before.arguments(5) {
                        if let Value::Frame(Some(at)) = args[3] {
                            self.finite.remove(&at);
                        }
                    }
                }
                self.finite.retain(|k, _| *k >= 0 || *k >= self.sp);
            }
            _ => (),
        }
        if self.sp != before.sp && matches!(op, Operation::Binary(..)) {
            let lo = self.sp.min(before.sp);
            let hi = self.sp.max(before.sp);
            self.finite
                .retain(|k, _| *k >= 0 || *k + 4 <= lo || *k >= hi);
        }
    }
    fn step(
        &mut self,
        op: &Operation,
        call: Option<Function>,
        load: Option<Function>,
    ) -> Result<(), String> {
        let before = self.clone();
        self.type_step(op, call, load)?;
        self.finite_step(&before, op, call);
        match op {
            Operation::Push(o) => {
                self.argument_known.insert(self.sp, before.bits(o));
            }
            Operation::Pop(r) => {
                self.known[r.index as usize] = *before.argument_known.get(&before.sp).unwrap_or(&0);
                self.argument_known.remove(&before.sp);
            }
            Operation::Leave => {
                self.known[5] = 0;
                self.argument_known.retain(|at, _| *at >= self.sp);
                self.initialized.clear();
            }
            Operation::ZeroExtend(dst, src) => {
                self.known[dst.index as usize] = if before.known[src.index as usize] >= 8 {
                    32
                } else {
                    0
                };
            }
            Operation::ConditionalMove(_, dst, src) => {
                self.known[dst.index as usize] =
                    before.known[dst.index as usize].min(before.known[src.index as usize]);
            }
            Operation::Address(r, a) => {
                self.known[r.index as usize] = [a.base, a.index]
                    .into_iter()
                    .flatten()
                    .map(|i| before.known[i as usize])
                    .min()
                    .unwrap_or(32);
            }
            Operation::Increment(r) | Operation::Decrement(r) => {
                self.zf_known = before.known[r.index as usize] >= 32;
            }
            Operation::Negate(r) => {
                let v = before.registers[r.index as usize];
                self.cf_known =
                    before.known[r.index as usize] >= 32 && (v.scalar() || v.error_zero_safe());
                self.zf_known = self.cf_known;
            }
            Operation::Binary(op, dst, src) => {
                let width = match dst {
                    Operand::Reg(r) => r.width,
                    Operand::Memory(_, w) => *w,
                    _ => 0,
                };
                let bits = if *op == Binary::Move {
                    before.bits(src).min(width)
                } else if (*op == Binary::Xor && dst == src)
                    || (before.bits(dst) >= width && before.bits(src) >= width)
                {
                    width
                } else {
                    0
                };
                let bits = if *op == Binary::Sbb && !before.cf_known {
                    0
                } else {
                    bits
                };
                if !matches!(op, Binary::Compare | Binary::Test) {
                    match dst {
                        Operand::Reg(r) => self.known[r.index as usize] = bits,
                        Operand::Memory(a, 32) => {
                            if let Ok(Value::Frame(Some(at))) = before.address(a) {
                                if bits == 32 {
                                    self.initialized.insert(at);
                                } else {
                                    self.initialized.remove(&at);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if *op != Binary::Move {
                    let pointer = matches!(dst,Operand::Reg(r) if matches!(before.registers[r.index as usize],Value::Frame(_)));
                    let error = matches!(dst,Operand::Reg(r) if before.registers[r.index as usize].affine().is_some());
                    self.zf_known = bits >= width && !pointer && !error;
                    self.cf_known = self.zf_known && !error;
                    if error
                        && *op == Binary::Compare
                        && matches!(src, Operand::Immediate(109))
                        && matches!(dst,Operand::Reg(r) if before.registers[r.index as usize]==Value::Error)
                    {
                        self.zf_known = bits >= width;
                    }
                }
                if matches!(
                    dst,
                    Operand::Reg(Reg {
                        index: 4,
                        width: 32
                    })
                ) && matches!(op, Binary::Add | Binary::Sub)
                {
                    let lo = self.sp.min(before.sp);
                    let hi = self.sp.max(before.sp);
                    self.initialized.retain(|at| *at + 4 <= lo || *at >= hi);
                }
            }
            Operation::Call(_) => {
                let f = call.unwrap();
                let n = match f {
                    Function::Read | Function::Write => 5,
                    Function::StandardHandle => 1,
                    Function::LastError => 0,
                };
                for i in 0..n {
                    self.argument_known.remove(&(before.sp + i * 4));
                }
                if matches!(f, Function::Read | Function::Write) {
                    if let Value::Frame(Some(at)) = before.arguments(5)?[3] {
                        self.initialized.insert(at);
                        self.local_values.insert(at, Value::Scalar);
                    }
                }
                self.known[0] = 32;
                self.known[1] = 0;
                self.known[2] = 0;
                self.cf_known = false;
                self.zf_known = false;
            }
            _ => {}
        }
        for i in 0..8 {
            if matches!(self.registers[i], Value::Unknown | Value::Entry(_)) {
                self.known[i] = 0;
            }
        }
        self.known[4] = 32;
        Ok(())
    }
    fn type_step(
        &mut self,
        op: &Operation,
        call: Option<Function>,
        load: Option<Function>,
    ) -> Result<(), String> {
        match op {
            Operation::Push(o) => self.push(self.operand(o, load)?)?,
            Operation::Pop(r) => self.pop(r.index)?,
            Operation::Leave => {
                let Value::Frame(Some(bp)) = self.registers[5] else {
                    return Err("stream frame: leave owner".into());
                };
                require(bp >= self.sp, "leave direction")?;
                if bp != self.sp {
                    self.deallocate((bp - self.sp) as u32)?;
                }
                self.pop(5)?;
            }
            Operation::Binary(
                op,
                Operand::Reg(Reg {
                    index: 4,
                    width: 32,
                }),
                Operand::Immediate(n),
            ) if matches!(op, Binary::Sub | Binary::Add) => {
                if *op == Binary::Sub {
                    self.allocate(*n)?;
                } else {
                    self.deallocate(*n)?;
                }
            }
            Operation::Binary(op, dst, src) => {
                if *op == Binary::Sbb {
                    require(self.cf_known, "SBB reads unknown/opaque carry")?;
                }
                if matches!(op, Binary::Compare | Binary::Test) {
                    let a = self.operand(dst, None)?;
                    let b = self.operand(src, None)?;
                    let test = *op == Binary::Test && dst == src;
                    let supported = match (a, b) {
                        (Value::Handle(_), Value::Constant(0 | 0xffffffff))
                        | (Value::Boolean, Value::Constant(0)) => *op == Binary::Compare,
                        (Value::Error, Value::Constant(109)) => *op == Binary::Compare,
                        (Value::Handle(_), Value::Handle(_)) | (Value::Boolean, Value::Boolean) => {
                            test
                        }
                        (a, b) => {
                            matches!(
                                a,
                                Value::Scalar
                                    | Value::Constant(_)
                                    | Value::Unknown
                                    | Value::Entry(_)
                            ) && matches!(
                                b,
                                Value::Scalar
                                    | Value::Constant(_)
                                    | Value::Unknown
                                    | Value::Entry(_)
                            )
                        }
                    };
                    require(
                        supported,
                        "opaque predicate outside reviewed observation contract",
                    )?;
                    return Ok(());
                }
                let rhs = self.operand(src, load)?;
                let result = if *op == Binary::Move {
                    rhs
                } else if *op == Binary::Xor && dst == src {
                    Value::Constant(0)
                } else if *op == Binary::Sbb && dst == src {
                    require(self.cf_known, "SBB observes unknown/opaque carry")?;
                    Value::Scalar
                } else {
                    let lhs = self.operand(dst, None)?;
                    match (op, lhs, rhs) {
                        (Binary::Add | Binary::Sub, Value::Frame(at), Value::Constant(n)) => {
                            let n = i64::from(n as i32) * if *op == Binary::Add { 1 } else { -1 };
                            Value::Frame(
                                at.map(|x| i32::try_from(i64::from(x) + n))
                                    .transpose()
                                    .map_err(|_| "stream frame: pointer offset overflow")?,
                            )
                        }
                        (Binary::Add | Binary::Sub, Value::Frame(_), Value::Scalar) => {
                            Value::Frame(None)
                        }
                        (Binary::Add | Binary::Sub, a, Value::Constant(n))
                            if a.affine().is_some() =>
                        {
                            let (scale, offset) = a.affine().unwrap();
                            Value::ErrorAffine(
                                scale,
                                if *op == Binary::Add {
                                    offset.wrapping_add(n)
                                } else {
                                    offset.wrapping_sub(n)
                                },
                            )
                        }
                        (_, a, b) if a.scalar() && b.scalar() => Value::Scalar,
                        _ => return Err("stream frame: arithmetic loses typed provenance".into()),
                    }
                };
                self.put(dst, result)?;
            }
            Operation::ZeroExtend(dst, src) => {
                let value = self.registers[src.index as usize];
                require(value.scalar(), "zero extension requires scalar source")?;
                self.put(
                    &Operand::Reg(*dst),
                    match value {
                        Value::Constant(n) => Value::Constant(n & 255),
                        _ => Value::Scalar,
                    },
                )?;
            }
            Operation::ConditionalMove(cond, dst, src) => {
                require(self.zf_known, "conditional move reads unknown ZF")?;
                require(
                    *cond == Condition::Equal || self.cf_known,
                    "conditional move reads unknown CF",
                )?;
                let a = self.registers[dst.index as usize];
                let b = self.registers[src.index as usize];
                require(
                    a.scalar() && b.scalar(),
                    "conditional move requires scalar values",
                )?;
                self.put(&Operand::Reg(*dst), a.join(b))?;
            }
            Operation::Address(r, a) => {
                let v = if a
                    .base
                    .is_some_and(|i| matches!(self.registers[i as usize], Value::Frame(_)))
                {
                    self.address(a)?
                } else {
                    require(
                        [a.base, a.index].into_iter().flatten().all(|i| {
                            matches!(
                                self.registers[i as usize],
                                Value::Scalar
                                    | Value::Constant(_)
                                    | Value::Unknown
                                    | Value::Entry(_)
                            )
                        }),
                        "scalar LEA opaque input",
                    )?;
                    Value::Scalar
                };
                self.put(&Operand::Reg(*r), v)?;
            }
            Operation::Increment(r) | Operation::Decrement(r) => {
                require(
                    self.registers[r.index as usize].scalar(),
                    "INC of non-scalar",
                )?;
                self.registers[r.index as usize] = Value::Scalar;
            }
            Operation::Negate(r) => {
                let v = self.registers[r.index as usize];
                self.registers[r.index as usize] = if let Some((a, b)) = v.affine() {
                    Value::ErrorAffine(a.wrapping_neg(), b.wrapping_neg())
                } else {
                    require(v.scalar(), "NEG non-scalar")?;
                    Value::Scalar
                };
            }
            Operation::Call(_) => self.call(call.ok_or("stream frame: missing call binding")?)?,
            Operation::Return => {
                require(
                    self.sp == 0 && self.slots.is_empty() && self.locals.is_empty(),
                    "unbalanced terminal frame",
                )?;
                for r in [3, 5, 6, 7] {
                    require(
                        self.registers[r] == Value::Entry(r as u8),
                        "nonvolatile register not restored",
                    )?;
                }
                require(self.registers[0].scalar(), "exit lacks scalar provenance")?;
            }
            _ => {}
        }
        Ok(())
    }
}
pub(super) fn prove(bound: &Bound) -> Result<Frames, String> {
    let mut states = BTreeMap::from([(bound.graph.entry, State::entry())]);
    let mut work = VecDeque::from([bound.graph.entry]);
    let mut visits = 0;
    while let Some(pc) = work.pop_front() {
        visits += 1;
        require(visits <= 100_000, "fixed-point budget")?;
        let mut state = states[&pc].clone();
        let node = &bound.graph.nodes[&pc];
        state
            .step(
                &node.operation,
                bound.calls.get(&pc).copied(),
                bound.loads.get(&pc).copied(),
            )
            .map_err(|e| format!("{e} at {pc:#x}"))?;
        for &next in &node.successors {
            if let Some(old) = states.get_mut(&next) {
                if old
                    .join(&state)
                    .map_err(|e| format!("{e} at join {next:#x}"))?
                {
                    work.push_back(next);
                }
            } else {
                states.insert(next, state.clone());
                work.push_back(next);
            }
        }
    }
    Ok(Frames { states })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn code(bytes: &[u8]) -> Result<Frames, String> {
        let bound = Bound {
            calls: BTreeMap::new(),
            loads: BTreeMap::new(),
            graph: super::super::graph::decode(bytes, 0x1000, 0x1000)?,
        };
        prove(&bound)
    }
    #[test]
    fn extension_definedness_provenance_and_unsigned_flags() {
        let dst = Reg {
            index: 0,
            width: 32,
        };
        let src = Reg { index: 1, width: 8 };
        for known in [0, 7, 8, 16, 32] {
            let mut s = State::entry();
            s.registers[1] = Value::Scalar;
            s.known[1] = known;
            s.cf_known = true;
            s.zf_known = true;
            s.step(&Operation::ZeroExtend(dst, src), None, None)
                .unwrap();
            assert_eq!(s.known[0], if known >= 8 { 32 } else { 0 });
            assert!(s.cf_known && s.zf_known);
        }
        for value in [
            Value::Frame(Some(-4)),
            Value::Handle(1),
            Value::Function(Function::Read),
            Value::Error,
            Value::Entry(1),
        ] {
            let mut s = State::entry();
            s.registers[1] = value;
            s.known[1] = 32;
            assert!(s
                .step(&Operation::ZeroExtend(dst, src), None, None)
                .is_err());
        }
        for (cf, zf, ok) in [
            (false, false, false),
            (false, true, false),
            (true, false, false),
            (true, true, true),
        ] {
            let mut s = State::entry();
            s.registers[0] = Value::Constant(7);
            s.registers[1] = Value::Constant(42);
            s.known[0] = 32;
            s.known[1] = 32;
            s.cf_known = cf;
            s.zf_known = zf;
            assert_eq!(
                s.step(
                    &Operation::ConditionalMove(Condition::Above, dst, Reg { width: 32, ..src }),
                    None,
                    None
                )
                .is_ok(),
                ok
            );
        }
    }
    #[test]
    fn conditional_selection_requires_known_scalar_state_and_preserves_flags() {
        let dst = Reg {
            index: 0,
            width: 32,
        };
        let src = Reg {
            index: 1,
            width: 32,
        };
        for (a, b) in [(0, 1), (7, 42), (u32::MAX, 0x80000000)] {
            let mut state = State::entry();
            state.registers[0] = Value::Constant(a);
            state.registers[1] = Value::Constant(b);
            state.known[0] = 32;
            state.known[1] = 32;
            state.zf_known = true;
            state.cf_known = true;
            state
                .step(
                    &Operation::ConditionalMove(Condition::Equal, dst, src),
                    None,
                    None,
                )
                .unwrap();
            assert_eq!(state.known[0], 32);
            assert!(state.zf_known && state.cf_known);
            assert!(state.registers[0].scalar());
        }
        let mut state = State::entry();
        state.registers[0] = Value::Constant(0);
        state.registers[1] = Value::Constant(1);
        assert!(state
            .step(
                &Operation::ConditionalMove(Condition::Equal, dst, src),
                None,
                None
            )
            .is_err());
        state.zf_known = true;
        state.registers[1] = Value::Frame(Some(-4));
        assert!(state
            .step(
                &Operation::ConditionalMove(Condition::Equal, dst, src),
                None,
                None
            )
            .is_err());
    }
    #[test]
    fn finite_facts_union_then_forget_and_wrap_independently() {
        let mut a = State::entry();
        a.finite.insert(0, BTreeSet::from([0]));
        let mut b = a.clone();
        b.finite.insert(0, BTreeSet::from([1]));
        a.join(&b).unwrap();
        assert_eq!(a.finite[&0], BTreeSet::from([0, 1]));
        for value in 2..=8 {
            b.finite.insert(0, BTreeSet::from([value]));
            a.join(&b).unwrap();
        }
        assert!(!a.finite.contains_key(&0));
        let mut s = State::entry();
        s.registers[0] = Value::Constant(u32::MAX);
        s.known[0] = 32;
        s.finite.insert(0, BTreeSet::from([u32::MAX]));
        s.step(
            &Operation::Increment(Reg {
                index: 0,
                width: 32,
            }),
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.finite[&0], BTreeSet::from([0]));
        let b = State::entry();
        a.join(&b).unwrap();
        assert!(a.finite.is_empty());
    }
    #[test]
    fn ebp_and_esp_frames_restore_owned_saves() {
        assert!(code(&[0x55, 0x89, 0xe5, 0x83, 0xec, 8, 0x31, 0xc0, 0xc9, 0xc3]).is_ok());
        assert!(code(&[0x83, 0xec, 8, 0x53, 0x31, 0xc0, 0x5b, 0x83, 0xc4, 8, 0xc3]).is_ok());
    }
    #[test]
    fn protected_slots_and_mixed_cleanup_reject() {
        for bytes in [
            vec![0x53, 0x5e, 0x31, 0xc0, 0xc3],
            vec![0x83, 0xec, 8, 0x53, 0x83, 0xc4, 8, 0x31, 0xc0, 0xc3],
            vec![0x83, 0xec, 8, 0x31, 0xc0, 0xc3],
            vec![
                0x55, 0x89, 0xe5, 0xc7, 0x45, 0, 0, 0, 0, 0, 0x31, 0xc0, 0xc9, 0xc3,
            ],
        ] {
            assert!(code(&bytes).is_err());
        }
    }
    #[test]
    fn joins_preserve_exact_layout_and_saved_identity() {
        let mut a = State::entry();
        a.allocate(16).unwrap();
        a.push(Value::Entry(3)).unwrap();
        let mut b = a.clone();
        b.registers[0] = Value::Constant(1);
        assert!(a.join(&b).unwrap());
        let mut b = a.clone();
        b.slots.insert(b.sp, Slot::Argument(Value::Constant(0)));
        assert!(a.join(&b).is_err());
        let mut b = State::entry();
        b.allocate(20).unwrap();
        assert!(a.join(&b).is_err());
    }
    #[test]
    fn call_cannot_consume_a_saved_word_and_requires_owned_count() {
        let mut s = State::entry();
        s.allocate(16).unwrap();
        s.push(Value::Entry(3)).unwrap();
        assert!(s.call(Function::StandardHandle).is_err());
        let mut s = State::entry();
        s.allocate(16).unwrap();
        for v in [
            Value::Constant(0),
            Value::Frame(Some(0)),
            Value::Constant(8),
            Value::Frame(Some(-16)),
            Value::Handle(0xfffffff6),
        ] {
            s.push(v).unwrap();
        }
        assert!(s.call(Function::Read).is_err());
    }
    #[test]
    fn opaque_join_loses_defined_scalar_authority_and_stack_flags_stay_unknown() {
        let mut a = State::entry();
        a.registers[0] = Value::Handle(0xfffffff6);
        a.known[0] = 32;
        let mut b = a.clone();
        b.registers[0] = Value::Constant(42);
        a.join(&b).unwrap();
        assert_eq!(a.registers[0], Value::Unknown);
        assert_eq!(a.known[0], 0);
        a.step(
            &Operation::Binary(
                Binary::Sub,
                Operand::Reg(Reg {
                    index: 4,
                    width: 32,
                }),
                Operand::Immediate(8),
            ),
            None,
            None,
        )
        .unwrap();
        assert!(!a.cf_known && !a.zf_known);
        a.step(
            &Operation::Binary(
                Binary::Move,
                Operand::Reg(Reg {
                    index: 0,
                    width: 32,
                }),
                Operand::Immediate(1),
            ),
            None,
            None,
        )
        .unwrap();
        assert!(!a.cf_known && !a.zf_known);
    }
    #[test]
    fn opaque_api_values_are_not_arithmetic_or_byte_data() {
        let mut s = State::entry();
        s.registers[0] = Value::Handle(0xfffffff6);
        let r = Operand::Reg(Reg {
            index: 0,
            width: 32,
        });
        assert!(s
            .step(
                &Operation::Binary(Binary::Add, r.clone(), Operand::Immediate(1)),
                None,
                None
            )
            .is_err());
        assert!(s
            .operand(&Operand::Reg(Reg { index: 0, width: 8 }), None)
            .is_err());
        s.registers[0] = Value::Error;
        assert!(s
            .step(
                &Operation::Binary(Binary::Compare, r.clone(), Operand::Immediate(5)),
                None,
                None
            )
            .is_err());
        assert!(s
            .step(
                &Operation::Binary(Binary::Compare, r, Operand::Immediate(109)),
                None,
                None
            )
            .is_ok());
    }
    #[test]
    fn affine_errors_only_expose_supported_zero_class() {
        for index in [0, 1, 2, 3, 6, 7] {
            for offset in [0u32, 108, 109, 110, u32::MAX] {
                let mut s = State::entry();
                s.registers[index] = Value::Error;
                s.known[index] = 32;
                let r = Reg {
                    index: index as u8,
                    width: 32,
                };
                let o = Operand::Reg(r);
                s.step(
                    &Operation::Binary(Binary::Sub, o.clone(), Operand::Immediate(offset)),
                    None,
                    None,
                )
                .unwrap();
                assert!(!s.cf_known && !s.zf_known);
                assert!(!s.registers[index].scalar());
                s.step(&Operation::Negate(r), None, None).unwrap();
                assert_eq!(s.cf_known, offset == 109);
                assert_eq!(s.zf_known, offset == 109);
                let result = s.step(&Operation::Binary(Binary::Sbb, o.clone(), o), None, None);
                assert_eq!(result.is_ok(), offset == 109);
            }
        }
    }
    #[test]
    fn typed_local_joins_cannot_launder_handle_as_scalar() {
        let mut a = State::entry();
        a.allocate(8).unwrap();
        a.initialized.insert(-8);
        a.local_values.insert(-8, Value::Handle(0xfffffff5));
        let mut b = a.clone();
        b.local_values.insert(-8, Value::Scalar);
        a.join(&b).unwrap();
        assert!(!a.initialized.contains(&-8));
        assert_eq!(a.local_values[&-8], Value::Unknown);
        let mut c = b.clone();
        c.local_values.clear();
        b.join(&c).unwrap();
        assert!(!b.initialized.contains(&-8));
    }
    #[test]
    fn decrement_preserves_carry_and_byte_sbb_requires_it() {
        let mut s = State::entry();
        s.registers[0] = Value::Scalar;
        s.known[0] = 32;
        let r = Reg {
            index: 0,
            width: 32,
        };
        s.cf_known = true;
        s.step(&Operation::Decrement(r), None, None).unwrap();
        assert!(s.cf_known && s.zf_known);
        let r = Operand::Reg(Reg { index: 0, width: 8 });
        s.cf_known = false;
        assert!(s
            .step(&Operation::Binary(Binary::Sbb, r.clone(), r), None, None)
            .is_err());
    }
}
