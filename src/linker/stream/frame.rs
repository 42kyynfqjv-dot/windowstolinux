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
    HeapHandle,
    Heap(u32, Option<i32>),
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
            (Self::Heap(a, _), Self::Heap(b, _)) if a == b => Self::Heap(a, None),
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
    pub(super) known: [u32; 8],
    pub(super) local_known: BTreeMap<i32, u32>,
    pub(super) initialized: std::collections::BTreeSet<i32>,
    pub(super) argument_known: BTreeMap<i32, u32>,
    pub(super) zero_test: Option<Value>,
    handle_test: Option<(u32, u32)>,
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
            known: [0, 0, 0, 0, u32::MAX, 0, 0, 0],
            initialized: Default::default(),
            local_known: Default::default(),
            argument_known: Default::default(),
            zero_test: None,
            handle_test: None,
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
        let mut heap = None;
        for (reg, scale) in [(a.base, 1), (a.index, a.scale)] {
            if let Some(reg) = reg {
                if let Value::Heap(site, _) = self.registers[reg as usize] {
                    require(
                        scale == 1 && heap.is_none(),
                        "heap address has multiple/scaled owners",
                    )?;
                    heap = Some(site);
                } else {
                    require(
                        self.registers[reg as usize].scalar()
                            || matches!(self.registers[reg as usize], Value::Frame(_)),
                        "address lacks scalar index",
                    )?;
                }
            }
        }
        if let Some(site) = heap {
            let mut offset = Some(i64::from(a.displacement as i32));
            for (reg, scale) in [(a.base, 1), (a.index, a.scale)] {
                if let Some(reg) = reg {
                    offset = match self.registers[reg as usize] {
                        Value::Heap(_, at) => offset.zip(at).map(|(n, at)| n + i64::from(at)),
                        Value::Constant(v) => offset.map(|n| n + i64::from(v) * i64::from(scale)),
                        Value::Scalar => None,
                        _ => return Err("stream frame: heap address mixes owners".into()),
                    };
                }
            }
            return Ok(Value::Heap(
                site,
                offset
                    .map(i32::try_from)
                    .transpose()
                    .map_err(|_| "stream frame: heap offset overflow")?,
            ));
        }
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
                        Value::Scalar
                            | Value::Constant(_)
                            | Value::Entry(_)
                            | Value::Unknown
                            | Value::Heap(_, _)
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
                if *width == 8 {
                    if let Value::Frame(Some(at)) = self.address(a)? {
                        if let Some((&base, v)) = self.local_values.range(..=at).next_back() {
                            if at < base + 4 {
                                require(v.scalar(), "partial local read of opaque value")?;
                            }
                        }
                    }
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
                if matches!(self.address(a)?, Value::Heap(_, _)) {
                    require(
                        value.scalar(),
                        "heap fields cannot store opaque pointers or handles",
                    )?;
                }
                require(
                    value.scalar()
                        || (*width == 32
                            && matches!(
                                value,
                                Value::Handle(_) | Value::HeapHandle | Value::Heap(_, _)
                            )),
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
    fn call(&mut self, pc: u32, f: Function) -> Result<(), String> {
        let n = f.arity();
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
                    matches!(args[1], Value::Frame(_) | Value::Heap(_, _)) && args[2].scalar(),
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
            Function::ProcessHeap => Value::HeapHandle,
            Function::HeapAlloc | Function::HeapReAlloc | Function::HeapFree => {
                require(args[0] == Value::HeapHandle, "heap handle provenance")?;
                require(
                    matches!(args[1], Value::Constant(0 | 8)),
                    "heap flags must be exact supported constant",
                )?;
                if f == Function::HeapFree {
                    require(args[1] == Value::Constant(0), "free flags")?;
                }
                if f != Function::HeapAlloc {
                    require(
                        matches!(args[2], Value::Heap(_, Some(0))),
                        "heap operation requires allocation base",
                    )?;
                }
                if f == Function::HeapFree {
                    Value::Scalar
                } else {
                    require(args[n - 1].scalar(), "heap size must be scalar")?;
                    Value::Heap(pc, Some(0))
                }
            }
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
        if self.zero_test != rhs.zero_test {
            self.zero_test = None;
        }
        if self.handle_test != rhs.handle_test {
            self.handle_test = None;
        }
        self.finite.retain(|key, values| {
            let Some(other) = rhs.finite.get(key) else {
                return false;
            };
            values.extend(other);
            values.len() <= 8
        });
        for (a, b) in self.known.iter_mut().zip(rhs.known) {
            *a &= b;
        }
        self.initialized.retain(|at| rhs.initialized.contains(at));
        self.local_known.retain(|at, k| {
            *k &= rhs.local_known.get(at).copied().unwrap_or(0);
            *k != 0
        });
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
                self.local_known.remove(&at);
            }
        }
        self.argument_known.retain(|at, k| {
            *k &= rhs.argument_known.get(at).copied().unwrap_or(0);
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
    pub(super) fn mask(&self, o: &Operand) -> u32 {
        match o {
            Operand::Immediate(_) => u32::MAX,
            Operand::Reg(r) => {
                let mask = if r.width != 32
                    && matches!(self.registers[r.index as usize], Value::Heap(_, _))
                {
                    7
                } else {
                    self.known[r.index as usize]
                };
                (mask >> r.shift) & if r.width == 8 { 255 } else { u32::MAX }
            }
            Operand::Memory(a, _) if a.base.is_none() && a.index.is_none() => u32::MAX,
            Operand::Memory(_, 8) => 255, // Requires mandatory SMT initialized-prefix proof.
            Operand::Memory(a, 32) => match self.address(a) {
                Ok(Value::Frame(Some(at))) => self.local_known.get(&at).copied().unwrap_or(0),
                Ok(Value::Heap(_, _)) => u32::MAX, // Mandatory full-range initialized-word proof.
                _ => 0,
            },
            _ => 0,
        }
    }
    pub(super) fn bits(&self, o: &Operand) -> u8 {
        self.mask(o).trailing_ones() as u8
    }
    fn set_mask(&mut self, r: Reg, mask: u32) {
        let lane = if r.width == 8 { 255 } else { u32::MAX };
        self.known[r.index as usize] =
            (self.known[r.index as usize] & !(lane << r.shift)) | ((mask & lane) << r.shift);
    }
    fn finite_operand(&self, o: &Operand) -> Option<BTreeSet<u32>> {
        match o {
            Operand::Immediate(n) => Some(BTreeSet::from([*n])),
            Operand::Reg(Reg {
                shift: 0,
                index,
                width: 32,
            }) => self.finite.get(&i32::from(*index)).cloned(),
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
                                        Binary::Or => a | b,
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
                    .finite_operand(src)
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
            Operation::Increment(r)
            | Operation::Decrement(r)
            | Operation::Negate(r)
            | Operation::Not(r) => {
                let values = before.finite_operand(&Operand::Reg(*r)).map(|v| {
                    v.into_iter()
                        .map(|v| match op {
                            Operation::Increment(_) => v.wrapping_add(1),
                            Operation::Decrement(_) => v.wrapping_sub(1),
                            Operation::Not(_) => !v,
                            _ => v.wrapping_neg(),
                        })
                        .collect()
                });
                assign(self, i32::from(r.index), values);
            }
            Operation::Shift { dst, count, .. } => {
                if *count != 0 {
                    assign(self, i32::from(dst.index), None);
                }
            }
            Operation::Address(r, _) | Operation::Set(_, r) => {
                assign(self, i32::from(r.index), None)
            }
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
    #[cfg(test)]
    fn step(
        &mut self,
        op: &Operation,
        call: Option<Function>,
        load: Option<Function>,
    ) -> Result<(), String> {
        self.step_at(0, op, call, load)
    }
    fn step_at(
        &mut self,
        pc: u32,
        op: &Operation,
        call: Option<Function>,
        load: Option<Function>,
    ) -> Result<(), String> {
        let before = self.clone();
        self.type_step(pc, op, call, load)?;
        if matches!(
            op,
            Operation::Call(_)
                | Operation::Binary(
                    Binary::Add
                        | Binary::Sub
                        | Binary::Or
                        | Binary::And
                        | Binary::Xor
                        | Binary::Sbb
                        | Binary::Test
                        | Binary::Compare,
                    _,
                    _
                )
                | Operation::Increment(_)
                | Operation::Decrement(_)
                | Operation::Negate(_)
        ) || matches!(op, Operation::Shift { count, .. } if *count != 0)
        {
            self.handle_test = match op {
                Operation::Binary(Binary::Test, a, b) if a == b => {
                    if let Ok(Value::Handle(selector)) = before.operand(a, None) {
                        Some((selector, 0))
                    } else {
                        None
                    }
                }
                Operation::Binary(Binary::Compare, a, Operand::Immediate(v))
                    if matches!(*v, 0 | u32::MAX) =>
                {
                    if let Ok(Value::Handle(selector)) = before.operand(a, None) {
                        Some((selector, *v))
                    } else {
                        None
                    }
                }
                _ => None,
            };
            self.zero_test = match op {
                Operation::Binary(Binary::Test, a, b) if a == b => before
                    .operand(a, None)
                    .ok()
                    .filter(|v| matches!(v, Value::Heap(_, Some(0)) | Value::HeapHandle)),
                Operation::Binary(Binary::Compare, a, Operand::Immediate(0)) => before
                    .operand(a, None)
                    .ok()
                    .filter(|v| matches!(v, Value::Heap(_, Some(0)) | Value::HeapHandle)),
                _ => None,
            };
        }
        self.finite_step(&before, op, call);
        match op {
            Operation::Push(o) => {
                self.argument_known.insert(self.sp, before.mask(o));
            }
            Operation::Pop(r) => {
                self.known[r.index as usize] = *before.argument_known.get(&before.sp).unwrap_or(&0);
                self.argument_known.remove(&before.sp);
            }
            Operation::Leave => {
                self.known[5] = 0;
                self.argument_known.retain(|at, _| *at >= self.sp);
                self.initialized.clear();
                self.local_known.clear();
            }
            Operation::ZeroExtend(dst, src) => {
                self.known[dst.index as usize] = before.mask(src) | !255;
            }
            Operation::Set(_, dst) => {
                if !before.registers[dst.index as usize].scalar() {
                    self.known[dst.index as usize] = 0;
                }
                self.set_mask(*dst, if before.zf_known { 255 } else { 0 });
            }
            Operation::Shift { dst, count, .. } => {
                if *count != 0 {
                    let mask = if dst.width == 32 { u32::MAX } else { 255 };
                    let known = before.mask(&Operand::Reg(*dst)) == mask;
                    self.set_mask(*dst, if known { mask } else { 0 });
                    // CF is undefined when the masked count is >= operand width.
                    self.cf_known = known && *count < dst.width;
                    self.zf_known = known;
                }
            }
            Operation::Not(_) => {}
            Operation::ConditionalMove(_, dst, src) => {
                self.known[dst.index as usize] =
                    before.known[dst.index as usize] & before.known[src.index as usize];
            }
            Operation::Address(r, a) => {
                self.known[r.index as usize] = [a.base, a.index]
                    .into_iter()
                    .flatten()
                    .map(|i| before.known[i as usize].trailing_ones())
                    .min()
                    .map(|n| if n == 32 { u32::MAX } else { (1u32 << n) - 1 })
                    .unwrap_or(u32::MAX);
            }
            Operation::Increment(r) | Operation::Decrement(r) => {
                self.zf_known = before.known[r.index as usize] == u32::MAX;
            }
            Operation::Negate(r) => {
                let v = before.registers[r.index as usize];
                self.cf_known = before.known[r.index as usize] == u32::MAX
                    && (v.scalar() || v.error_zero_safe());
                self.zf_known = self.cf_known;
            }
            Operation::Binary(op, dst, src) => {
                let width = match dst {
                    Operand::Reg(r) => r.width,
                    Operand::Memory(_, w) => *w,
                    _ => 0,
                };
                let heap_or = *op == Binary::Or
                    && matches!(before.operand(dst, None), Ok(Value::Heap(_, Some(0))))
                    && matches!(before.operand(src, None), Ok(Value::Heap(_, Some(0))));
                let bits = if heap_or {
                    3
                } else if *op == Binary::Move {
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
                        Operand::Reg(r) => {
                            if r.width != 32 && !before.registers[r.index as usize].scalar() {
                                self.known[r.index as usize] = 0;
                            }
                            self.set_mask(
                                *r,
                                if *op == Binary::Move {
                                    before.mask(src)
                                } else if bits == 32 {
                                    u32::MAX
                                } else {
                                    (1u32 << bits) - 1
                                },
                            );
                        }
                        Operand::Memory(a, 32) => {
                            if let Ok(Value::Frame(Some(at))) = before.address(a) {
                                let mask = if *op == Binary::Move {
                                    before.mask(src)
                                } else if bits == 32 {
                                    u32::MAX
                                } else {
                                    (1u32 << bits) - 1
                                };
                                self.local_known.insert(at, mask);
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
                if *op == Binary::Test {
                    if let Operand::Immediate(mask) = src {
                        if before.mask(dst) & mask == *mask {
                            self.cf_known = true;
                            self.zf_known = true;
                            return Ok(());
                        }
                    }
                }
                if *op != Binary::Move {
                    let pointer = matches!(op, Binary::Add | Binary::Sub)
                        && matches!(dst,Operand::Reg(r) if matches!(before.registers[r.index as usize],Value::Frame(_) | Value::Heap(_, _)));
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
                        shift: 0,
                        index: 4,
                        width: 32
                    })
                ) && matches!(op, Binary::Add | Binary::Sub)
                {
                    let lo = self.sp.min(before.sp);
                    let hi = self.sp.max(before.sp);
                    self.initialized.retain(|at| *at + 4 <= lo || *at >= hi);
                    self.local_known.retain(|at, _| *at + 4 <= lo || *at >= hi);
                }
            }
            Operation::Call(_) => {
                let f = call.unwrap();
                let n = f.arity() as i32;
                for i in 0..n {
                    self.argument_known.remove(&(before.sp + i * 4));
                }
                if matches!(f, Function::Read | Function::Write) {
                    if let Value::Frame(Some(at)) = before.arguments(5)?[3] {
                        self.initialized.insert(at);
                        self.local_known.insert(at, u32::MAX);
                        self.local_values.insert(at, Value::Scalar);
                    }
                }
                self.known[0] = u32::MAX;
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
        self.known[4] = u32::MAX;
        Ok(())
    }
    fn type_step(
        &mut self,
        pc: u32,
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
                    shift: 0,
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
                        (Value::Heap(_, Some(0)), Value::Constant(0)) => *op == Binary::Compare,
                        (Value::HeapHandle, Value::Constant(0)) => *op == Binary::Compare,
                        (Value::HeapHandle, Value::HeapHandle) => test || *op == Binary::Compare,
                        (Value::Heap(a, Some(0)), Value::Heap(b, Some(0))) => test && a == b,
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
                        (Binary::Add | Binary::Sub, Value::Heap(site, at), Value::Constant(n)) => {
                            let n = i64::from(n as i32) * if *op == Binary::Add { 1 } else { -1 };
                            Value::Heap(
                                site,
                                at.map(|x| i32::try_from(i64::from(x) + n))
                                    .transpose()
                                    .map_err(|_| "stream frame: heap offset overflow")?,
                            )
                        }
                        (Binary::Add | Binary::Sub, Value::Heap(site, _), Value::Scalar) => {
                            Value::Heap(site, None)
                        }
                        (Binary::Or, Value::Heap(_, Some(0)), Value::Heap(_, Some(0))) => {
                            Value::Scalar
                        }
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
                let value = self.operand(src, None)?;
                require(
                    value.scalar()
                        && !matches!(src, Operand::Reg(r) if !self.registers[r.index as usize].scalar()),
                    "zero extension requires scalar source",
                )?;
                self.put(&Operand::Reg(*dst), Value::Scalar)?;
            }
            Operation::Set(_, dst) => {
                require(self.zf_known, "SETNE reads unknown ZF")?;
                self.put(&Operand::Reg(*dst), Value::Scalar)?;
            }
            Operation::Shift { dst, count, .. } => {
                if *count != 0 {
                    require(
                        self.registers[dst.index as usize].scalar(),
                        "shift of opaque value",
                    )?;
                    self.put(&Operand::Reg(*dst), Value::Scalar)?;
                }
            }
            Operation::Not(r) => {
                require(self.registers[r.index as usize].scalar(), "NOT non-scalar")?;
                self.registers[r.index as usize] = Value::Scalar;
            }
            Operation::ConditionalMove(cond, dst, src) => {
                require(
                    *cond == Condition::AboveEqual || self.zf_known,
                    "conditional move reads unknown ZF",
                )?;
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
                let v = if a.base.is_some_and(|i| {
                    matches!(
                        self.registers[i as usize],
                        Value::Frame(_) | Value::Heap(_, _)
                    )
                }) || a
                    .index
                    .is_some_and(|i| matches!(self.registers[i as usize], Value::Heap(_, _)))
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
            Operation::Call(_) => {
                self.call(pc, call.ok_or("stream frame: missing call binding")?)?
            }
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
            .step_at(
                pc,
                &node.operation,
                bound.calls.get(&pc).copied(),
                bound.loads.get(&pc).copied(),
            )
            .map_err(|e| format!("{e} at {pc:#x}"))?;
        for &next in &node.successors {
            let mut state = state.clone();
            if let Operation::Branch(cond, target) = node.operation {
                if matches!(cond, Condition::Equal | Condition::NotEqual)
                    && node.successors.len() == 2
                {
                    if let Some((selector, tested)) = state.handle_test {
                        let equal = (next == target) == (cond == Condition::Equal);
                        let kind = if selector == 0xfffffff6 { 1 } else { 2 };
                        let keys: Vec<_> = state
                            .registers
                            .iter()
                            .enumerate()
                            .filter_map(|(i, v)| {
                                (*v == Value::Handle(selector)).then_some(i as i32)
                            })
                            .chain(state.local_values.iter().filter_map(|(&at, v)| {
                                (*v == Value::Handle(selector)).then_some(at)
                            }))
                            .chain(state.slots.iter().filter_map(|(&at, v)| {
                                matches!(v,Slot::Argument(Value::Handle(s)) if *s==selector)
                                    .then_some(at)
                            }))
                            .collect();
                        for key in keys {
                            let values = state
                                .finite
                                .entry(key)
                                .or_insert_with(|| BTreeSet::from([0, u32::MAX, kind]));
                            values.retain(|v| (*v == tested) == equal);
                        }
                    }
                }
                if matches!(cond, Condition::Equal | Condition::NotEqual)
                    && ((next == target) == (cond == Condition::Equal))
                    && node.successors.len() == 2
                {
                    if let Some(tested) = state.zero_test {
                        for v in state
                            .registers
                            .iter_mut()
                            .chain(state.local_values.values_mut())
                        {
                            if *v == tested {
                                *v = Value::Constant(0);
                            }
                        }
                        for slot in state.slots.values_mut() {
                            if let Slot::Argument(v) = slot {
                                if *v == tested {
                                    *v = Value::Constant(0);
                                }
                            }
                        }
                    }
                }
            }
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
    fn partial_masks_aliases_spills_and_opaque_boundaries() {
        let lo = Reg {
            index: 2,
            width: 8,
            shift: 0,
        };
        let hi = Reg {
            index: 2,
            width: 8,
            shift: 8,
        };
        let full = Reg {
            index: 2,
            width: 32,
            shift: 0,
        };
        let mut state = State::entry();
        state
            .step(
                &Operation::Binary(Binary::Move, Operand::Reg(hi), Operand::Immediate(0x81)),
                None,
                None,
            )
            .unwrap();
        assert_eq!(state.known[2], 0xff00);
        assert_eq!(state.bits(&Operand::Reg(lo)), 0);
        assert_eq!(state.bits(&Operand::Reg(hi)), 8);
        state
            .step(
                &Operation::Binary(Binary::Move, Operand::Reg(lo), Operand::Immediate(7)),
                None,
                None,
            )
            .unwrap();
        assert_eq!(state.known[2], 0xffff);
        state.allocate(8).unwrap();
        let cell = Operand::Memory(
            Address {
                base: Some(4),
                index: None,
                scale: 1,
                displacement: 0,
            },
            32,
        );
        state
            .step(
                &Operation::Binary(Binary::Move, cell.clone(), Operand::Reg(full)),
                None,
                None,
            )
            .unwrap();
        assert_eq!(state.local_known[&-8], 0xffff);
        assert!(!state.initialized.contains(&-8));
        state
            .step(
                &Operation::Binary(Binary::Move, Operand::Reg(Reg { index: 1, ..full }), cell),
                None,
                None,
            )
            .unwrap();
        assert_eq!(state.known[1], 0xffff);
        let mut other = state.clone();
        other.known[2] = 0xff00;
        state.join(&other).unwrap();
        assert_eq!(state.known[2], 0xff00);
        for v in [
            Value::Frame(Some(-8)),
            Value::Handle(1),
            Value::Error,
            Value::Function(Function::Read),
        ] {
            let mut s = State::entry();
            s.registers[2] = v;
            s.known[2] = u32::MAX;
            s.step(
                &Operation::Binary(Binary::Move, Operand::Reg(hi), Operand::Immediate(1)),
                None,
                None,
            )
            .unwrap();
            assert_eq!(s.known[2], 0xff00); // Original opaque upper bits remain unobservable.
            assert_eq!(s.bits(&Operand::Reg(full)), 0);
        }
        let mut s = State::entry();
        assert!(s
            .step(&Operation::Set(Condition::NotEqual, lo), None, None)
            .is_err());
        s.zf_known = true;
        s.step(&Operation::Set(Condition::NotEqual, hi), None, None)
            .unwrap();
        assert_eq!(s.known[2], 0xff00);
        assert!(s.zf_known);
        assert!(!s.cf_known);
    }
    #[test]
    fn extension_definedness_provenance_and_unsigned_flags() {
        let dst = Reg {
            shift: 0,
            index: 0,
            width: 32,
        };
        let src = Reg {
            shift: 0,
            index: 1,
            width: 8,
        };
        for known in [0, 7, 8, 16, 32] {
            let mut s = State::entry();
            s.registers[1] = Value::Scalar;
            s.known[1] = if known == 32 {
                u32::MAX
            } else {
                (1u32 << known) - 1
            };
            s.cf_known = true;
            s.zf_known = true;
            s.step(&Operation::ZeroExtend(dst, Operand::Reg(src)), None, None)
                .unwrap();
            assert_eq!(
                s.known[0],
                (!255u32) | if known >= 8 { 255 } else { (1u32 << known) - 1 }
            );
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
            s.known[1] = u32::MAX;
            assert!(s
                .step(&Operation::ZeroExtend(dst, Operand::Reg(src)), None, None)
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
            s.known[0] = u32::MAX;
            s.known[1] = u32::MAX;
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
            shift: 0,
            index: 0,
            width: 32,
        };
        let src = Reg {
            shift: 0,
            index: 1,
            width: 32,
        };
        for (a, b) in [(0, 1), (7, 42), (u32::MAX, 0x80000000)] {
            let mut state = State::entry();
            state.registers[0] = Value::Constant(a);
            state.registers[1] = Value::Constant(b);
            state.known[0] = u32::MAX;
            state.known[1] = u32::MAX;
            state.zf_known = true;
            state.cf_known = true;
            state
                .step(
                    &Operation::ConditionalMove(Condition::Equal, dst, src),
                    None,
                    None,
                )
                .unwrap();
            assert_eq!(state.known[0], u32::MAX);
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
        s.known[0] = u32::MAX;
        s.finite.insert(0, BTreeSet::from([u32::MAX]));
        s.step(
            &Operation::Increment(Reg {
                shift: 0,
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
        assert!(s.call(0, Function::StandardHandle).is_err());
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
        assert!(s.call(0, Function::Read).is_err());
    }
    #[test]
    fn opaque_join_loses_defined_scalar_authority_and_stack_flags_stay_unknown() {
        let mut a = State::entry();
        a.registers[0] = Value::Handle(0xfffffff6);
        a.known[0] = u32::MAX;
        let mut b = a.clone();
        b.registers[0] = Value::Constant(42);
        a.join(&b).unwrap();
        assert_eq!(a.registers[0], Value::Unknown);
        assert_eq!(a.known[0], 0);
        a.step(
            &Operation::Binary(
                Binary::Sub,
                Operand::Reg(Reg {
                    shift: 0,
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
                    shift: 0,
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
            shift: 0,
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
            .operand(
                &Operand::Reg(Reg {
                    shift: 0,
                    index: 0,
                    width: 8
                }),
                None
            )
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
                s.known[index] = u32::MAX;
                let r = Reg {
                    shift: 0,
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
        s.known[0] = u32::MAX;
        let r = Reg {
            shift: 0,
            index: 0,
            width: 32,
        };
        s.cf_known = true;
        s.step(&Operation::Decrement(r), None, None).unwrap();
        assert!(s.cf_known && s.zf_known);
        let r = Operand::Reg(Reg {
            shift: 0,
            index: 0,
            width: 8,
        });
        s.cf_known = false;
        assert!(s
            .step(&Operation::Binary(Binary::Sbb, r.clone(), r), None, None)
            .is_err());
    }
    #[test]
    fn heap_api_types_preserve_identity_and_reject_unowned_arguments() {
        let mut s = State::entry();
        s.call(10, Function::ProcessHeap).unwrap();
        assert_eq!(s.registers[0], Value::HeapHandle);
        for v in [Value::Constant(7), Value::Constant(0), Value::HeapHandle] {
            s.push(v).unwrap();
        }
        s.call(20, Function::HeapAlloc).unwrap();
        assert_eq!(s.sp, 0);
        assert_eq!(s.registers[0], Value::Heap(20, Some(0)));
        let old = s.registers[0];
        for v in [
            Value::Constant(9),
            old,
            Value::Constant(8),
            Value::HeapHandle,
        ] {
            s.push(v).unwrap();
        }
        s.call(30, Function::HeapReAlloc).unwrap();
        assert_eq!(s.registers[0], Value::Heap(30, Some(0)));
        // Shape analysis preserves both identities; liveness is a conditional
        // SMT obligation, never inferred merely from presence of either token.
        for bad in [
            Value::Constant(0),
            Value::Frame(Some(-8)),
            Value::Heap(20, Some(1)),
        ] {
            let mut s = State::entry();
            for v in [bad, Value::Constant(0), Value::HeapHandle] {
                s.push(v).unwrap();
            }
            assert!(s.call(40, Function::HeapFree).is_err());
        }
        let mut s = State::entry();
        for v in [Value::Constant(7), Value::Constant(0), Value::Handle(3)] {
            s.push(v).unwrap();
        }
        assert!(s.call(20, Function::HeapAlloc).is_err());
    }
    #[test]
    fn heap_layout_is_not_scalar_knowledge() {
        let mut s = State::entry();
        let eax = Reg {
            index: 0,
            width: 32,
            shift: 0,
        };
        let al = Reg { width: 8, ..eax };
        let ah = Reg { shift: 8, ..al };
        for offset in [Some(0), Some(5), None] {
            s.registers[0] = Value::Heap(10, offset);
            s.known[0] = u32::MAX;
            assert_eq!(s.mask(&Operand::Reg(al)), 7);
            assert_eq!(s.mask(&Operand::Reg(ah)), 0);
            assert!(s
                .clone()
                .step(&Operation::ZeroExtend(eax, Operand::Reg(al)), None, None)
                .is_err());
        }
        s.registers[0] = Value::Heap(10, Some(0));
        s.registers[1] = Value::Heap(20, Some(0));
        s.known[1] = u32::MAX;
        s.step(
            &Operation::Binary(
                Binary::Or,
                Operand::Reg(eax),
                Operand::Reg(Reg { index: 1, ..eax }),
            ),
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.known[0], 7);
        s.step(
            &Operation::Binary(Binary::Test, Operand::Reg(al), Operand::Immediate(7)),
            None,
            None,
        )
        .unwrap();
        assert!(s.zf_known);
        s.step(
            &Operation::Binary(Binary::Test, Operand::Reg(al), Operand::Immediate(255)),
            None,
            None,
        )
        .unwrap();
        assert!(!s.zf_known);
    }
    #[test]
    fn shift_knowledge_and_zero_predicate_lifetime() {
        let mut s = State::entry();
        let eax = Reg {
            index: 0,
            width: 32,
            shift: 0,
        };
        let al = Reg { width: 8, ..eax };
        s.registers[0] = Value::Heap(10, Some(0));
        s.known[0] = u32::MAX;
        s.step(
            &Operation::Binary(Binary::Test, Operand::Reg(eax), Operand::Reg(eax)),
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.zero_test, Some(Value::Heap(10, Some(0))));
        s.step(
            &Operation::Shift {
                left: true,
                dst: eax,
                count: 0,
            },
            None,
            None,
        )
        .unwrap();
        assert!(s.zero_test.is_some());
        assert!(s
            .clone()
            .step(
                &Operation::Shift {
                    left: false,
                    dst: eax,
                    count: 1
                },
                None,
                None
            )
            .is_err());
        s.step(
            &Operation::Binary(Binary::Move, Operand::Reg(eax), Operand::Immediate(0x81)),
            None,
            None,
        )
        .unwrap();
        s.step(
            &Operation::Shift {
                left: true,
                dst: al,
                count: 8,
            },
            None,
            None,
        )
        .unwrap();
        assert!(!s.cf_known && s.zf_known && s.zero_test.is_none());
        s.known[0] = 7;
        s.step(
            &Operation::Shift {
                left: false,
                dst: al,
                count: 1,
            },
            None,
            None,
        )
        .unwrap();
        assert!(!s.cf_known && !s.zf_known);
    }
    #[test]
    fn checked_handle_branches_refine_finite_outcomes_without_assuming_validity() {
        // Independently assembled get-handle / reject-null / reject-invalid CFG.
        // Both failing edges remain present, and the failure join includes both
        // invalid outcomes. The SMT encoder checks these finite facts on edges.
        let mut code = vec![
            0x53, 0x6a, 0xf6, 0xff, 0x15, 0, 0x20, 0, 0, 0x89, 0xc3, 0x85, 0xdb, 0x74, 0, 0x83,
            0xfb, 0xff, 0x74, 0,
        ];
        let accepted = code.len() as u32;
        code.extend([0xb8, 0, 0, 0, 0, 0x5b, 0xc3]);
        let rejected = code.len() as u32;
        code.extend([0xb8, 10, 0, 0, 0, 0x5b, 0xc3]);
        code[14] = (rejected - 15) as u8;
        code[19] = (rejected - 20) as u8;
        let bound = Bound {
            graph: super::super::graph::decode(&code, 0, 0).unwrap(),
            calls: BTreeMap::from([(3, Function::StandardHandle)]),
            loads: BTreeMap::from([(3, Function::StandardHandle)]),
        };
        let frames = prove(&bound).unwrap();
        assert_eq!(frames.states[&accepted].finite[&3], BTreeSet::from([1]));
        assert_eq!(
            frames.states[&rejected].finite[&3],
            BTreeSet::from([0, u32::MAX])
        );
        // A flag overwrite destroys the predicate; it cannot certify a handle.
        let mut state = State::entry();
        state.registers[3] = Value::Handle(0xfffffff6);
        state.known[3] = u32::MAX;
        let r = Operand::Reg(Reg {
            index: 3,
            width: 32,
            shift: 0,
        });
        state
            .step(&Operation::Binary(Binary::Test, r.clone(), r), None, None)
            .unwrap();
        assert_eq!(state.handle_test, Some((0xfffffff6, 0)));
        state.registers[0] = Value::Constant(0);
        state.known[0] = u32::MAX;
        state
            .step(
                &Operation::Increment(Reg {
                    index: 0,
                    width: 32,
                    shift: 0,
                }),
                None,
                None,
            )
            .unwrap();
        assert_eq!(state.handle_test, None);
    }
    #[test]
    fn heap_scalar_fields_reject_opaque_values_and_mixed_owners() {
        let mut s = State::entry();
        s.registers[0] = Value::Heap(10, Some(0));
        s.known[0] = u32::MAX;
        let address = Address {
            base: Some(0),
            index: None,
            scale: 1,
            displacement: 4,
        };
        let dst = Operand::Memory(address.clone(), 32);
        for value in [
            Value::Heap(20, Some(0)),
            Value::HeapHandle,
            Value::Handle(0xfffffff5),
            Value::Frame(Some(-4)),
        ] {
            assert!(s.put(&dst, value).is_err());
        }
        s.put(&dst, Value::Constant(0x04030201)).unwrap();
        assert_eq!(s.operand(&dst, None).unwrap(), Value::Scalar);
        s.registers[1] = Value::Heap(20, Some(0));
        let mixed = Address {
            index: Some(1),
            ..address
        };
        assert!(s.address(&mixed).is_err());
    }
}
