use super::*;
fn unit_index(offset: u8) -> usize {
    let i = usize::from(offset / 2);
    if i < 2 {
        i
    } else {
        i + 1
    }
}
/// Affine bit-vector over four unknown UTF16 units and unknown API length.
/// Coefficients and constants are modulo 2^32; no sampled input is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Expr {
    c: u32,
    a: [u32; 5],
}
impl Expr {
    fn constant(c: u32) -> Self {
        Self { c, a: [0; 5] }
    }
    fn variable(i: usize) -> Self {
        let mut e = Self::constant(0);
        e.a[i] = 1;
        e
    }
    fn add(self, b: Self, k: u32, c: u32) -> Self {
        Self {
            c: self.c.wrapping_add(b.c.wrapping_mul(k)).wrapping_add(c),
            a: std::array::from_fn(|i| self.a[i].wrapping_add(b.a[i].wrapping_mul(k))),
        }
    }
    fn bounds(self, ranges: &[(u32, u32); 5]) -> (u32, u32) {
        self.width_bounds(ranges, 32)
    }
    fn width_bounds(self, ranges: &[(u32, u32); 5], width: u8) -> (u32, u32) {
        // Integer affine bounds, then modular projection. Wrap crossing loses precision.
        let (mut lo, mut hi) = (i128::from(self.c as i32), i128::from(self.c as i32));
        for (a, (l, h)) in self.a.into_iter().zip(ranges) {
            let k = i128::from(a as i32);
            let (l, h) = (i128::from(*l), i128::from(*h));
            lo += k * if k >= 0 { l } else { h };
            hi += k * if k >= 0 { h } else { l };
        }
        let m = 1i128 << width;
        if lo.div_euclid(m) != hi.div_euclid(m) {
            (0, (m - 1) as u32)
        } else {
            (lo.rem_euclid(m) as u32, hi.rem_euclid(m) as u32)
        }
    }
    fn low16(self) -> Result<Self, String> {
        let e = Self {
            c: self.c & 65535,
            a: self.a.map(|a| a & 65535),
        };
        need(
            e.c == 0 && e.a[2] == 0 && e.a.iter().sum::<u32>() == 1,
            "input: unproved zero extension",
        )?;
        Ok(e)
    }
}
// Immutable bounded analysis DAG. Counts expanded occurrences, including aliases.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Scalar {
    Affine(Expr),
    Node(std::rc::Rc<ScalarNode>),
}
#[derive(Debug, PartialEq, Eq)]
struct ScalarNode {
    left: Scalar,
    right: Scalar,
    multiply: bool,
    size: u16,
    depth: u8,
}
impl Scalar {
    fn cost(&self) -> (u16, u8) {
        match self {
            Self::Affine(_) => (1, 1),
            Self::Node(n) => (n.size, n.depth),
        }
    }
    fn binary(self, right: Self, multiply: bool) -> Result<Self, String> {
        let (a, ad) = self.cost();
        let (b, bd) = right.cost();
        let size = 1 + a + b;
        let depth = 1 + ad.max(bd);
        need(size <= 63 && depth <= 12, "input: expression resource cap")?;
        Ok(Self::Node(std::rc::Rc::new(ScalarNode {
            left: self,
            right,
            multiply,
            size,
            depth,
        })))
    }
    fn bounds(&self, ranges: &[(u32, u32); 5]) -> (u32, u32) {
        match self {
            Self::Affine(e) => e.bounds(ranges),
            Self::Node(n) => {
                let (a, b) = n.left.bounds(ranges);
                let (c, d) = n.right.bounds(ranges);
                let (a, b, c, d) = (u64::from(a), u64::from(b), u64::from(c), u64::from(d));
                let (lo, hi) = if n.multiply {
                    (a * c, b * d)
                } else {
                    (a + c, b + d)
                };
                if lo >> 32 == hi >> 32 {
                    (lo as u32, hi as u32)
                } else {
                    (0, u32::MAX)
                }
            }
        }
    }
    fn value(self) -> Value {
        match self {
            Self::Affine(e) => Value::Scalar(e),
            n => Value::Nonlinear(n),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Unknown,
    Scalar(Expr),
    Nonlinear(Scalar),
    Buffer,
    BufferOffset(u8),
    Anchor(usize),
    Original(usize),
    Name,
    OriginalEsi,
}
impl Value {
    fn expression(&self) -> Result<Scalar, String> {
        match self {
            Self::Scalar(e) => Ok(Scalar::Affine(*e)),
            Self::Nonlinear(e) => Ok(e.clone()),
            _ => Err("input: unknown or pointer used as scalar".into()),
        }
    }

    fn scalar(&self) -> Result<Expr, String> {
        if let Self::Scalar(e) = self {
            Ok(*e)
        } else {
            Err("input: unknown or pointer used as scalar".into())
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Word {
    Return,
    InternalReturn(u32),
    Local(u8),
    SavedReg(usize, Value),
    Arg(Value),
}
impl Word {
    fn argument_value(&self) -> Option<&Value> {
        match self {
            Self::Arg(v) => Some(v),
            Self::SavedReg(
                _,
                v @ (Value::Scalar(_)
                | Value::Nonlinear(_)
                | Value::Buffer
                | Value::BufferOffset(_)),
            ) => Some(v),
            _ => None,
        }
    }
}
#[derive(Clone)]
struct Frame {
    target: u32,
    next: u32,
    stack: Vec<Word>,
    saved: [Value; 3],
    args: usize,
    borrowed: bool,
}
#[derive(Clone)]
struct State {
    regs: [Value; 6],
    frames: Vec<Frame>,
    stack: Vec<Word>,
    allocated: bool,
    local_size: u8,
    owner_floor: usize,
    calls: u8,
    initialized: u8,
    ranges: [(u32, u32); 5],
    flags: Option<(Expr, u8, u32)>,
}
impl State {
    fn new() -> Self {
        Self {
            frames: Vec::new(),
            regs: [
                Value::Unknown,
                Value::Unknown,
                Value::Unknown,
                Value::OriginalEsi,
                Value::Original(4),
                Value::Original(5),
            ],
            stack: vec![Word::Return],
            allocated: false,
            local_size: 0,
            owner_floor: 1,
            calls: 0,
            initialized: 0,
            ranges: [
                (0, 65535),
                (0, 65535),
                (0, u32::MAX),
                (0, 65535),
                (0, 65535),
            ],
            flags: None,
        }
    }
    fn argument(&self, off: u8) -> Result<Value, String> {
        let f = self.frames.last().ok_or("input: no argument context")?;
        need(off.is_multiple_of(4), "input: argument alignment")?;
        let at = self
            .stack
            .len()
            .checked_sub(1 + usize::from(off / 4))
            .ok_or("input: argument bounds")?;
        need(
            at >= f.stack.len() - f.args
                && at < f.stack.len()
                && self.stack.get(f.stack.len()) == Some(&Word::InternalReturn(f.next)),
            "input: argument bounds/return",
        )?;
        self.stack[at]
            .argument_value()
            .cloned()
            .ok_or("input: protected argument".into())
    }
    fn stack_offset(&self, frame: bool, off: i32) -> Result<u8, String> {
        let base = if frame {
            match self.regs[5] {
                Value::Anchor(n) => n,
                _ => return Err("input: unknown frame anchor".into()),
            }
        } else {
            self.stack.len()
        };
        let o = (self.stack.len() as i64 - base as i64) * 4 + i64::from(off);
        u8::try_from(o).map_err(|_| "input: stack address bounds".into())
    }
    fn live(&self) -> bool {
        self.local_size > 0
            && (0..self.local_size / 4).all(|i| {
                self.stack.get(self.owner_floor + usize::from(i))
                    == Some(&Word::Local(self.local_size - 4 - i * 4))
            })
    }
    fn allocate(&mut self, n: u8) -> Result<(), String> {
        need(
            self.frames.is_empty()
                && self.calls == 0
                && n > 0
                && n <= 12
                && n.is_multiple_of(4)
                && self.local_size.checked_add(n).is_some_and(|v| v <= 12),
            "input: allocation lifetime/size",
        )?;
        need(
            !self
                .regs
                .iter()
                .any(|v| matches!(v, Value::Buffer | Value::BufferOffset(_))),
            "input: allocation after alias",
        )?;
        if self.local_size == 0 {
            need(
                self.stack == [Word::Return]
                    || self.stack == [Word::Return, Word::SavedReg(5, Value::Original(5))],
                "input: allocation owner",
            )?;
            self.owner_floor = self.stack.len();
        } else {
            need(
                self.live()
                    && self.stack.len() == self.owner_floor + usize::from(self.local_size / 4),
                "input: allocation stack shape",
            )?;
        }
        for w in &mut self.stack[self.owner_floor..] {
            if let Word::Local(b) = w {
                *b += n;
            }
        }
        for b in (0..n / 4).rev() {
            self.stack.push(Word::Local(b * 4));
        }
        self.local_size += n;
        self.allocated = true;
        Ok(())
    }
    fn cleanup(&mut self, n: u8) -> Result<(), String> {
        need(n > 0 && n.is_multiple_of(4), "input: cleanup size")?;
        let count = usize::from(n / 4);
        let floor = self
            .frames
            .last()
            .map_or(self.owner_floor, |f| f.stack.len() + 1);
        let start = self
            .stack
            .len()
            .checked_sub(count)
            .ok_or("input: cleanup underflow")?;
        need(start >= floor, "input: protected cleanup")?;
        if self.stack[start..]
            .iter()
            .all(|w| w.argument_value().is_some())
        {
            self.stack.truncate(start);
        } else {
            need(
                self.frames.is_empty()
                    && self.live()
                    && n == self.local_size
                    && start == self.owner_floor,
                "input: mixed/local cleanup ownership",
            )?;
            self.stack.truncate(start);
            self.local_size = 0;
            self.initialized = 0;
        }
        self.flags = None;
        Ok(())
    }
    fn push_reg(&mut self, r: usize) -> Result<(), String> {
        if r >= 3 {
            self.stack.push(Word::SavedReg(r, self.regs[r].clone()));
        } else if r == 1 && self.calls == 0 && self.frames.is_empty() {
            self.allocate(4)?;
        } else {
            self.stack.push(Word::Arg(self.regs[r].clone()));
        }
        Ok(())
    }
    fn pop_reg(&mut self, r: usize) -> Result<(), String> {
        let floor = self.frames.last().map_or(1, |f| f.stack.len() + 1);
        need(
            self.stack.len() > floor,
            "input: pop protected return/argument",
        )?;
        self.regs[r] = match self.stack.pop() {
            Some(Word::SavedReg(owner, v)) if owner == r => v,
            Some(w) if r < 3 && w.argument_value().is_some() => w.argument_value().unwrap().clone(),
            _ => return Err("input: protected saved slot".into()),
        };
        Ok(())
    }
    fn content(&self, offset: u8, width: u8) -> Result<Expr, String> {
        need(
            matches!(width, 2 | 4)
                && offset.is_multiple_of(2)
                && offset
                    .checked_add(width)
                    .is_some_and(|e| e <= self.initialized),
            "input: initialized content bounds",
        )?;
        let unit = |o: u8| -> Result<Expr, String> {
            if o < 8 {
                Ok(Expr::variable(unit_index(o)))
            } else {
                need(o == 8 && self.initialized == 10, "input: terminator bounds")?;
                Ok(Expr::constant(0))
            }
        };
        let lo = unit(offset)?;
        Ok(if width == 4 {
            lo.add(unit(offset + 2)?, 65536, 0)
        } else {
            lo
        })
    }
    fn local(&self, offset: u8, width: u8) -> Result<u8, String> {
        let mut first = None;
        for i in 0..width {
            let byte = usize::from(offset) + usize::from(i);
            let word = self
                .stack
                .len()
                .checked_sub(byte / 4 + 1)
                .and_then(|j| self.stack.get(j));
            let Some(Word::Local(base)) = word else {
                return Err("input: protected/outside local byte".into());
            };
            let actual = *base + (byte % 4) as u8;
            if let Some(start) = first {
                need(actual == start + i, "input: discontiguous ownership")?;
            } else {
                first = Some(actual);
            }
        }
        first.ok_or("input: empty local range".into())
    }
}
pub(super) struct Proven {
    pub(super) graph: Graph,
    pub(super) entry: u32,
    pub(super) loads: BTreeMap<u32, u8>,
    pub(super) addresses: BTreeMap<u32, u8>,
    pub(super) capacity: u32,
    pub(super) stack_reads: BTreeMap<u32, Option<u8>>,
}
/// Intersect a symbol with the exact preimage of an unsigned modular comparison.
/// Splitting retains disjunctions instead of merging initialized and failed API paths.
fn refine(state: &State, condition: Condition, taken: bool) -> Result<Vec<State>, String> {
    if matches!(condition, Condition::Eq) {
        return refine(state, Condition::Ne, !taken);
    }
    let (expr, width, k) = state.flags.ok_or("input: branch consumes unknown flags")?;
    need(matches!(width, 16 | 32), "input: comparison width")?;
    let m = 1u64 << width;
    need(u64::from(k) < m, "input: comparison immediate width")?;
    if matches!(condition, Condition::B) {
        if k == 0 {
            return Ok(if taken { vec![] } else { vec![state.clone()] });
        }
        let mut copy = state.clone();
        copy.flags = Some((expr, width, k - 1));
        let mut forks = refine(&copy, Condition::Be, taken)?;
        for fork in &mut forks {
            fork.flags = state.flags;
        }
        return Ok(forks);
    }
    let (lo, hi) = expr.width_bounds(&state.ranges, width);
    let outcome = match condition {
        Condition::Ne if k < lo || k > hi => Some(true),
        Condition::Ne if lo == hi && lo == k => Some(false),
        Condition::Be if hi <= k => Some(true),
        Condition::Be if lo > k => Some(false),
        Condition::A if lo > k => Some(true),
        Condition::A if hi <= k => Some(false),
        _ => None,
    };
    if let Some(value) = outcome {
        return Ok(if value == taken {
            vec![state.clone()]
        } else {
            vec![]
        });
    }
    let mask = (m - 1) as u32;
    let coefficients = expr.a.map(|a| a & mask);
    let variables: Vec<_> = coefficients
        .iter()
        .enumerate()
        .filter(|(_, a)| **a != 0)
        .collect();
    need(
        variables.len() == 1 && *variables[0].1 == 1,
        "input: unsupported symbolic predicate",
    )?;
    let index = variables[0].0;
    need(
        u64::from(state.ranges[index].1) < m,
        "input: predicate truncates unconstrained variable",
    )?;
    let k = u64::from(k);
    need(k < m, "input: comparison width")?;
    let desired: Vec<(u64, u64)> = match (condition, taken) {
        (Condition::Ne, false) => vec![(k, k)],
        (Condition::Ne, true) => {
            let mut v = vec![];
            if k > 0 {
                v.push((0, k - 1));
            }
            if k + 1 < m {
                v.push((k + 1, m - 1));
            }
            v
        }
        (Condition::Be, true) | (Condition::A, false) => vec![(0, k)],
        _ => {
            if k + 1 < m {
                vec![(k + 1, m - 1)]
            } else {
                vec![]
            }
        }
    };
    let c = u64::from(expr.c & mask);
    let mut out = vec![];
    for (lo, hi) in desired {
        let start = (lo + m - c) % m;
        let stop = (hi + m - c) % m;
        let spans = if start <= stop {
            vec![(start, stop)]
        } else {
            vec![(0, stop), (start, m - 1)]
        };
        for (lo, hi) in spans {
            let lo = (lo as u32).max(state.ranges[index].0);
            let hi = (hi as u32).min(state.ranges[index].1);
            if lo <= hi {
                let mut s = state.clone();
                s.ranges[index] = (lo, hi);
                out.push(s);
            }
        }
    }
    Ok(out)
}
pub(super) fn prove(graph: Graph, entry: u32) -> Result<Proven, String> {
    validate_calls(&graph, entry)?;
    let mut pending = vec![(entry, State::new())];
    let mut loads = BTreeMap::new();
    let mut addresses = BTreeMap::new();
    let mut stack_reads = BTreeMap::new();
    let mut steps = 0;
    let mut returns = 0;
    let mut capacity = None;
    while let Some((pc, mut s)) = pending.pop() {
        steps += 1;
        need(steps <= 4096, "input: symbolic state budget")?;
        let &(op, next) = graph.get(&pc).ok_or("input: missing decoded target")?;
        need(next > pc, "input: acyclic fallthrough")?;
        match op {
            Op::Allocate => {
                s.allocate(8)?;
                s.flags = None;
            }
            Op::AllocateN(n) => {
                s.allocate(n)?;
                s.flags = None;
            }
            Op::PushReg(r) => s.push_reg(r)?,
            Op::PopReg(r) => s.pop_reg(r)?,
            Op::Anchor => {
                need(
                    s.regs[5] == Value::Original(5)
                        && s.stack.last() == Some(&Word::SavedReg(5, Value::Original(5))),
                    "input: frame creation",
                )?;
                s.regs[5] = Value::Anchor(s.stack.len());
            }
            Op::Leave => {
                need(
                    s.frames.is_empty()
                        && s.regs[5] == Value::Anchor(s.owner_floor)
                        && s.owner_floor == 2,
                    "input: frame teardown",
                )?;
                if s.local_size > 0 {
                    s.cleanup(s.local_size)?;
                }
                s.pop_reg(5)?;
            }
            Op::Buffer | Op::BufferAt(_) | Op::Address(..) => {
                let (d, off) = match op {
                    Op::Buffer => (0, 0),
                    Op::BufferAt(n) => (0, n),
                    Op::Address(d, f, o) => (d, s.stack_offset(f, o)?),
                    _ => unreachable!(),
                };
                let base = s.local(off, 1).map_err(|e| format!("{e} at {pc:x}"))?;
                need(s.live(), "input: caller buffer lifetime")?;
                if let Some(old) = addresses.insert(pc, base) {
                    need(old == base, "input: inconsistent address owner")?;
                }
                s.regs[d] = if base == 0 {
                    Value::Buffer
                } else {
                    Value::BufferOffset(base)
                };
            }
            Op::Call(t) => {
                need(
                    s.calls == 1
                        && s.frames.len() < super::MAX_ACTIVATIONS
                        && t != entry
                        && !s.frames.iter().any(|f| f.target == t),
                    "input: internal call context",
                )?;
                let args = s
                    .stack
                    .iter()
                    .rev()
                    .take_while(|w| w.argument_value().is_some())
                    .count();
                let borrowed = s.stack.iter().rev().take(args).any(|w| {
                    matches!(
                        w.argument_value(),
                        Some(Value::Buffer | Value::BufferOffset(_))
                    )
                });
                if borrowed {
                    need(s.initialized > 0 && s.live(), "input: live borrow")?;
                }
                need(s.stack.len() < 16, "input: stack bound")?;
                s.frames.push(Frame {
                    target: t,
                    next,
                    stack: s.stack.clone(),
                    saved: [s.regs[3].clone(), s.regs[4].clone(), s.regs[5].clone()],
                    args,
                    borrowed,
                });
                s.stack.push(Word::InternalReturn(next));
                pending.push((t, s));
                continue;
            }
            Op::Argument(d, off) => s.regs[d] = s.argument(off)?,
            Op::CompareArgument(off, k) => s.flags = Some((s.argument(off)?.scalar()?, 32, k)),
            Op::ReadWord(d, r, off) => {
                let base = match s.regs[r] {
                    Value::Buffer => 0,
                    Value::BufferOffset(o) => o,
                    _ => return Err("input: borrowed pointer provenance".into()),
                };
                let off = base
                    .checked_add(off)
                    .ok_or("input: borrow offset overflow")?;
                need(
                    s.live()
                        && s.frames.last().is_some_and(|f| f.borrowed)
                        && off % 2 == 0
                        && off.checked_add(2).is_some_and(|e| e <= s.initialized),
                    "input: borrowed initialized WORD",
                )?;
                loads.entry(pc).or_insert(off);
                s.regs[d] = Value::Scalar(s.content(off, 2)?);
            }
            Op::StackRead(d, frame, off, width) => {
                let off = s.stack_offset(frame, off)?;
                if let Ok(value) = s.argument(off) {
                    need(width == 4, "input: argument width")?;
                    if let Some(old) = stack_reads.insert(pc, None) {
                        need(old.is_none(), "input: inconsistent stack role")?;
                    }
                    s.regs[d] = value;
                } else {
                    let local = s.local(off, width).map_err(|e| format!("{e} at {pc:x}"))?;
                    if let Some(old) = stack_reads.insert(pc, Some(local)) {
                        need(old == Some(local), "input: inconsistent stack role")?;
                    }

                    if let Some(old) = loads.insert(pc, local) {
                        need(old == local, "input: inconsistent local alias")?;
                    }
                    s.regs[d] = Value::Scalar(s.content(local, width)?);
                }
            }
            Op::StackCompare(frame, off, k) => {
                let o = s.stack_offset(frame, off)?;
                s.flags = Some((s.argument(o)?.scalar()?, 32, k));
            }
            Op::Push(n) => s.stack.push(Word::Arg(Value::Scalar(Expr::constant(n)))),
            Op::PushEax => s.stack.push(Word::Arg(s.regs[0].clone())),
            Op::Name => s.stack.push(Word::Arg(Value::Name)),
            Op::Acquire => {
                let at = s.owner_floor + usize::from(s.local_size / 4);
                need(
                    s.calls == 0 && s.live() && s.stack.len() == at + 3,
                    "input: API live owner",
                )?;
                let cap = match &s.stack[at] {
                    Word::Arg(Value::Scalar(e)) if e.a == [0; 5] => e.c,
                    _ => return Err("input: API capacity provenance".into()),
                };
                need(
                    matches!(cap, 3 | 5)
                        && s.local_size >= cap as u8 * 2
                        && s.stack[at + 1] == Word::Arg(Value::Buffer)
                        && s.stack[at + 2] == Word::Arg(Value::Name),
                    "input: API arguments/live owner/capacity",
                )?;
                if let Some(old) = capacity.replace(cap) {
                    need(old == cap, "input: inconsistent API capacity")?;
                }
                s.calls = 1;
                s.stack.truncate(at);
                s.flags = None;
                s.regs[0] = Value::Scalar(Expr::variable(2));
                s.regs[1] = Value::Unknown;
                s.regs[2] = Value::Unknown;
                // Full API domain, including conservative raw failure/oversize states.
                let mut classes = vec![(0, 0, 0), (cap + 1, 65, 0), (66, u32::MAX, 0)];
                for n in 1..cap {
                    classes.push((n, n, ((n + 1) * 2) as u8));
                }
                for (lo, hi, initialized) in classes {
                    let mut fork = s.clone();
                    fork.ranges[2] = (lo, hi);
                    fork.initialized = initialized;
                    if initialized > 0 && lo < 4 {
                        fork.ranges[unit_index((lo * 2) as u8)] = (0, 0);
                    }
                    pending.push((next, fork));
                }
                continue;
            }
            Op::Move(d, v) => {
                need(
                    !matches!(
                        s.regs[v],
                        Value::Unknown | Value::OriginalEsi | Value::Original(_) | Value::Anchor(_)
                    ),
                    "input: unknown/anchor move",
                )?;
                s.regs[d] = s.regs[v].clone();
            }
            Op::Mov(r, v) => s.regs[r] = Value::Scalar(Expr::constant(v)),
            Op::Test(r) => s.flags = Some((s.regs[r].scalar()?, 32, 0)),
            Op::Compare(r, width, v) => s.flags = Some((s.regs[r].scalar()?, width, v)),
            Op::Load(d, off) => {
                if let Ok(v) = s.argument(off) {
                    if let Some(old) = stack_reads.insert(pc, None) {
                        need(old.is_none(), "input: inconsistent stack role")?;
                    }
                    s.regs[d] = v;
                    pending.push((next, s));
                    continue;
                }
                let local = s.local(off, 4).map_err(|e| format!("{e} at {pc:x}"))?;
                if let Some(old) = stack_reads.insert(pc, Some(local)) {
                    need(old == Some(local), "input: inconsistent stack role")?;
                }
                need(
                    local.checked_add(4).is_some_and(|e| e <= s.initialized),
                    "input: read outside initialized API result",
                )?;
                need(
                    matches!(local, 0 | 2),
                    "input: unsupported local word offset",
                )?;
                if let Some(old) = loads.insert(pc, local) {
                    need(old == local, "input: inconsistent local alias")?;
                }
                s.regs[d] = Value::Scalar(s.content(local, 4)?);
            }
            Op::Save => s.push_reg(3)?,
            Op::Restore => s.pop_reg(3)?,
            Op::Cleanup => s.cleanup(8)?,
            Op::CleanupN(n) => s.cleanup(n)?,
            Op::Ret => {
                if let Some(f) = s.frames.pop() {
                    need(
                        s.stack.len() == f.stack.len() + 1
                            && s.stack.last() == Some(&Word::InternalReturn(f.next))
                            && s.stack[..f.stack.len()] == f.stack
                            && s.regs[3..] == f.saved,
                        "input: internal return ownership",
                    )?;
                    s.regs[0].expression()?;
                    s.stack.pop();
                    // Actual decoded internal effects survive; external API still clobbers.
                    s.flags = None;
                    pending.push((f.next, s));
                    continue;
                }

                need(
                    s.calls == 1
                        && s.stack == [Word::Return]
                        && s.regs[3] == Value::OriginalEsi
                        && s.regs[4] == Value::Original(4)
                        && s.regs[5] == Value::Original(5),
                    "input: terminal ownership/ABI",
                )?;
                need(
                    s.regs[0].expression()?.bounds(&s.ranges).1 <= 255,
                    "input: unproved portable exit",
                )?;
                returns += 1;
                continue;
            }
            Op::Lea(d, a, b, k, c) => {
                s.regs[d] = match s.regs[a] {
                    Value::Buffer | Value::BufferOffset(_) if k == 0 => {
                        let base = if let Value::BufferOffset(o) = s.regs[a] {
                            o
                        } else {
                            0
                        };
                        let o = i64::from(base) + i64::from(c as i32);
                        need(
                            s.live() && o >= 0 && o < i64::from(s.local_size),
                            "input: buffer offset bounds",
                        )?;
                        if o == 0 {
                            Value::Buffer
                        } else {
                            Value::BufferOffset(o as u8)
                        }
                    }
                    _ => Value::Scalar(s.regs[a].scalar()?.add(s.regs[b].scalar()?, k, c)),
                }
            }
            Op::Scaled(d, v, k, c) => {
                s.regs[d] = Value::Scalar(Expr::constant(0).add(s.regs[v].scalar()?, k, c))
            }
            Op::ZeroExtend(d, v) => s.regs[d] = Value::Scalar(s.regs[v].scalar()?.low16()?),
            Op::Arithmetic(r, v, subtract) => {
                let delta = if subtract { v.wrapping_neg() } else { v };
                s.regs[r] = match s.regs[r].expression()? {
                    Scalar::Affine(e) => Value::Scalar(e.add(Expr::constant(0), 0, delta)),
                    e => e
                        .binary(Scalar::Affine(Expr::constant(delta)), false)?
                        .value(),
                };
                s.flags = None;
            }
            Op::Binary(d, v, multiply) => {
                let left = s.regs[d].expression()?;
                let right = s.regs[v].expression()?;
                s.regs[d] = match (&left, &right, multiply) {
                    (Scalar::Affine(a), Scalar::Affine(b), false) => Value::Scalar(a.add(*b, 1, 0)),
                    _ => left.binary(right, multiply)?.value(),
                };
                s.flags = None;
            }
            Op::Multiply(d, r, k) => {
                s.regs[d] = Value::Scalar(Expr::constant(0).add(s.regs[r].scalar()?, k, 0));
                s.flags = None;
            }
            Op::CompareRegs(a, b) => {
                let k = s.regs[b].scalar()?;
                need(k.a == [0; 5], "input: unproved register comparison")?;
                s.flags = Some((s.regs[a].scalar()?, 32, k.c));
            }
            Op::Select(c, d, r) => {
                let v = s.regs[r].expression()?.value(); // evaluate register even on untaken CMOV
                for mut fork in refine(&s, c, true)? {
                    fork.regs[d] = v.clone();
                    pending.push((next, fork));
                }
                for fork in refine(&s, c, false)? {
                    pending.push((next, fork));
                }
                continue;
            }
            Op::Jump(t) => {
                pending.push((t, s));
                continue;
            }
            Op::Branch(c, target) => {
                for fork in refine(&s, c, true)? {
                    pending.push((target, fork));
                }
                for fork in refine(&s, c, false)? {
                    pending.push((next, fork));
                }
                continue;
            }
        }
        need(s.stack.len() <= 16, "input: stack bound")?;
        pending.push((next, s));
    }
    need(returns > 0, "input: no terminal proof")?;
    // Every emitted read must have an established physical offset; unreachable reads fail.
    for (&pc, (op, _)) in &graph {
        if matches!(op, Op::Buffer | Op::BufferAt(_) | Op::Address(..)) {
            need(
                addresses.contains_key(&pc),
                "input: unproved emitted address",
            )?;
        }
        if matches!(op, Op::StackRead(..)) {
            need(
                stack_reads.contains_key(&pc),
                "input: unproved emitted stack read",
            )?;
        }
        if matches!(op, Op::Load(..) | Op::ReadWord(..)) {
            need(
                loads.contains_key(&pc) || stack_reads.contains_key(&pc),
                "input: unproved emitted read",
            )?;
        }
    }
    Ok(Proven {
        graph,
        entry,
        loads,
        addresses,
        stack_reads,
        capacity: capacity.ok_or("input: no acquisition proof")?,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn modular_digit_preimages_and_wrapping_arithmetic() {
        let mut s = State::new();
        s.flags = Some((
            Expr::variable(0).add(Expr::constant(0), 0, 0xffff_ffd0),
            16,
            9,
        ));
        let yes = refine(&s, Condition::Be, true).unwrap();
        assert_eq!(yes.len(), 1);
        assert_eq!(yes[0].ranges[0], (48, 57));
        let no = refine(&s, Condition::Be, false).unwrap();
        assert_eq!(
            no.iter().map(|s| s.ranges[0]).collect::<Vec<_>>(),
            [(0, 47), (58, 65535)]
        );
        for c in 0..=65535u32 {
            let admitted = yes.iter().any(|s| s.ranges[0].0 <= c && c <= s.ranges[0].1);
            assert_eq!(admitted, (48..=57).contains(&c));
        }
        // Independent algebra: 10*(first-48)+(second-48), with intermediate -24.
        let a = Expr::variable(0).add(Expr::constant(0), 0, 0xffff_ffd0);
        let five = a.add(a, 4, 0);
        let mid = five.add(Expr::constant(0), 0, 0xffff_ffe8);
        assert_eq!(
            mid.bounds(&[(48, 48), (48, 57), (2, 2), (0, 0), (0, 0)]),
            (0xffffffe8, 0xffffffe8)
        );
        let answer = Expr::variable(1).add(mid, 2, 0);
        assert_eq!(
            answer.bounds(&[(48, 57), (48, 57), (2, 2), (0, 0), (0, 0)]),
            (0, 99)
        );
        assert_eq!(
            answer.bounds(&[(48, 48), (55, 55), (2, 2), (0, 0), (0, 0)]),
            (7, 7)
        );
    }
    #[test]
    fn protected_full_ranges_and_zero_extension_exclusions() {
        let mut s = State::new();
        s.stack.extend([
            Word::Local(4),
            Word::Local(0),
            Word::SavedReg(3, Value::OriginalEsi),
        ]);
        assert_eq!(s.local(6, 4).unwrap(), 2);
        for offset in [0, 1, 2, 3, 9, 10, 11, 12, 255] {
            assert!(s.local(offset, 4).is_err(), "{offset}");
        }
        assert_eq!(
            Expr::variable(0)
                .add(Expr::variable(1), 65536, 0)
                .low16()
                .unwrap(),
            Expr::variable(0)
        );
        assert!(Expr::variable(2).low16().is_err());
        assert!(Expr::variable(0)
            .add(Expr::variable(1), 1, 0)
            .low16()
            .is_err());
    }
    #[test]
    fn unknown_flags_and_disjoint_length_refinement() {
        let mut s = State::new();
        assert!(refine(&s, Condition::Ne, true).is_err());
        s.flags = Some((Expr::variable(2), 32, 2));
        assert_eq!(
            refine(&s, Condition::Ne, false).unwrap()[0].ranges[2],
            (2, 2)
        );
        let rest = refine(&s, Condition::Ne, true).unwrap();
        assert_eq!(
            rest.iter().map(|s| s.ranges[2]).collect::<Vec<_>>(),
            [(0, 1), (3, u32::MAX)]
        );
        s.flags = Some((Expr::variable(2), 16, 2));
        assert!(refine(&s, Condition::Ne, false).is_err());
        assert_eq!(
            Expr::variable(0)
                .add(Expr::constant(0), 0, u32::MAX)
                .bounds(&[(0, 1), (0, 0), (0, 0), (0, 0), (0, 0)]),
            (0, u32::MAX)
        );
    }
}

#[cfg(test)]
mod nonlinear_tests {
    use super::*;
    #[test]
    fn independent_modular_products_and_resource_caps() {
        let ranges = [(0, 0); 5];
        for (a, b, result) in [
            (u32::MAX, 2, u32::MAX - 1),
            (0x80000000, u32::MAX, 0x80000000),
            (65536, 65536, 0),
            (9, 9, 81),
        ] {
            let e = Scalar::Affine(Expr::constant(a))
                .binary(Scalar::Affine(Expr::constant(b)), true)
                .unwrap();
            assert_eq!(e.bounds(&ranges), (result, result));
        }
        let x = Scalar::Affine(Expr::variable(0));
        let e = x.clone().binary(x.clone(), true).unwrap();
        assert_eq!(e.bounds(&[(0, 9), (0, 0), (0, 0), (0, 0), (0, 0)]), (0, 81));
        assert_eq!(
            e.bounds(&[(0, u32::MAX), (0, 0), (0, 0), (0, 0), (0, 0)]),
            (0, u32::MAX)
        );
        let mut e = x.clone();
        for _ in 0..5 {
            e = e.clone().binary(e, true).unwrap();
        }
        assert_eq!(e.cost(), (63, 6));
        assert!(e.clone().binary(e, true).is_err());
        let mut e = x.clone();
        for _ in 0..11 {
            e = e.binary(x.clone(), false).unwrap();
        }
        assert_eq!(e.cost(), (23, 12));
        assert!(e.binary(x, false).is_err());
    }
}

#[cfg(test)]
mod borrow_tests {
    use super::*;
    #[test]
    fn protected_context_argument_and_lifetime_boundaries() {
        let mut s = State::new();
        s.stack.extend([
            Word::Local(4),
            Word::Local(0),
            Word::Arg(Value::Scalar(Expr::constant(2))),
            Word::Arg(Value::Buffer),
        ]);
        let f = Frame {
            target: 100,
            next: 200,
            stack: s.stack.clone(),
            saved: [Value::OriginalEsi, Value::Original(4), Value::Original(5)],
            args: 2,
            borrowed: true,
        };
        s.frames.push(f);
        s.stack.push(Word::InternalReturn(200));
        assert_eq!(s.argument(4).unwrap(), Value::Buffer);
        for off in [0, 1, 2, 3, 12, 255] {
            assert!(s.argument(off).is_err());
        }
        s.stack.push(Word::Arg(Value::Unknown));
        assert!(s.argument(4).is_err());
        s.stack.pop();
        s.stack.pop();
        s.stack.push(Word::InternalReturn(201));
        assert!(s.argument(4).is_err());
        assert!(Value::Buffer.scalar().is_err());
        assert!(Value::Name.expression().is_err());
    }
}

#[cfg(test)]
mod postcall_tests {
    use super::*;
    #[test]
    fn entailment_width_wrap_and_unknown_boundaries() {
        let mut s = State::new();
        // JB refines values but cannot rewrite the producer's CF/ZF expression.
        s.flags = Some((Expr::variable(0), 32, 3));
        let clear = refine(&s, Condition::B, false).unwrap();
        assert_eq!(clear[0].flags, s.flags);
        let equal = refine(&clear[0], Condition::Eq, true).unwrap();
        assert_eq!(equal[0].ranges[0], (3, 3));
        let taken = refine(&s, Condition::B, true).unwrap();
        assert_eq!(taken[0].flags, s.flags);
        assert!(refine(&taken[0], Condition::Eq, true).unwrap().is_empty());

        for (c, width, k, expected) in [
            (202, 32, 202, false),
            (65536, 16, 0, false),
            (u32::MAX, 16, 65535, false),
            (0, 32, u32::MAX, true),
        ] {
            s.flags = Some((Expr::constant(c), width, k));
            assert_eq!(
                !refine(&s, Condition::Ne, true).unwrap().is_empty(),
                expected
            );
        }
        s.ranges = [(48, 57), (48, 57), (2, 2), (0, 0), (0, 0)];
        s.flags = Some((
            Expr {
                c: 0u32.wrapping_sub(528),
                a: [10, 1, 0, 0, 0],
            },
            32,
            202,
        ));
        assert_eq!(refine(&s, Condition::Ne, true).unwrap().len(), 1);
        assert!(refine(&s, Condition::Ne, false).unwrap().is_empty());
        s.ranges = [(0, 1), (0, 1), (0, 0), (0, 0), (0, 0)];
        s.flags = Some((
            Expr {
                c: u32::MAX,
                a: [1, 1, 0, 0, 0],
            },
            32,
            0,
        ));
        assert!(refine(&s, Condition::Ne, true).is_err());
        s.flags = None;
        assert!(refine(&s, Condition::Ne, true).is_err());
    }
}

#[cfg(test)]
mod composition_tests {
    use super::*;
    #[test]
    fn owned_frame_offsets_saved_values_and_cleanup_boundaries() {
        let mut s = State::new();
        s.push_reg(5).unwrap();
        s.regs[5] = Value::Anchor(2);
        s.push_reg(1).unwrap();
        s.push_reg(1).unwrap();
        assert!(s.live());
        assert_eq!(s.local_size, 8);
        assert_eq!(s.local(s.stack_offset(true, -8).unwrap(), 8).unwrap(), 0);
        for off in [-12, -1, 0, 4] {
            assert!(
                s.stack_offset(true, off)
                    .and_then(|o| s.local(o, 2))
                    .is_err(),
                "{off}"
            );
        }
        s.calls = 1;
        s.regs[3] = Value::Scalar(Expr::constant(73));
        s.push_reg(3).unwrap();
        s.regs[3] = Value::Scalar(Expr::constant(99));
        s.pop_reg(3).unwrap();
        assert_eq!(s.regs[3], Value::Scalar(Expr::constant(73)));
        let mut bad = s.clone();
        bad.stack.push(Word::Arg(Value::Unknown));
        assert!(bad.cleanup(8).is_err());
        let mut bad = s.clone();
        assert!(bad.cleanup(12).is_err());
        let mut bad = s.clone();
        bad.push_reg(5).unwrap();
        assert!(bad.pop_reg(1).is_err());
        let mut bad = s.clone();
        assert!(bad.allocate(252).is_err());
        s.cleanup(8).unwrap();
        assert!(!s.live());
        assert!(s.local(0, 2).is_err());
        s.pop_reg(5).unwrap();
        assert_eq!(s.regs[5], Value::Original(5));
        assert_eq!(s.stack, [Word::Return]);
    }
    #[test]
    fn byte_word_aliases_include_high_units_and_terminator() {
        let mut s = State::new();
        s.initialized = 10;
        let units = [0x41u32, 0x20ac, 0xd83d, 0xde00];
        for (i, n) in units.iter().enumerate() {
            s.ranges[unit_index((i * 2) as u8)] = (*n, *n);
        }
        s.ranges[2] = (4, 4);
        for (offset, expected) in [
            (0, 0x20ac0041),
            (2, 0xd83d20ac),
            (4, 0xde00d83d),
            (6, 0xde00),
        ] {
            assert_eq!(
                s.content(offset, 4).unwrap().bounds(&s.ranges),
                (expected, expected)
            );
        }
        assert_eq!(s.content(8, 2).unwrap(), Expr::constant(0));
        for (offset, width) in [(1, 2), (7, 4), (8, 4), (10, 2), (255, 4), (0, 1)] {
            assert!(s.content(offset, width).is_err());
        }
        s.initialized = 4;
        assert!(s.content(2, 4).is_err());
        s.initialized = 0;
        assert!(s.content(0, 2).is_err());
    }
    #[test]
    fn arguments_allow_saved_scalar_copies_but_protect_return_and_owner() {
        let mut s = State::new();
        s.allocate(8).unwrap();
        s.calls = 1;
        s.initialized = 6;
        s.regs[3] = Value::BufferOffset(2);
        s.push_reg(3).unwrap();
        let f = Frame {
            target: 100,
            next: 200,
            stack: s.stack.clone(),
            saved: [s.regs[3].clone(), s.regs[4].clone(), s.regs[5].clone()],
            args: 1,
            borrowed: true,
        };
        s.frames.push(f);
        s.stack.push(Word::InternalReturn(200));
        s.push_reg(4).unwrap();
        assert_eq!(s.argument(8).unwrap(), Value::BufferOffset(2));
        for off in [0, 4, 12, 16, 255] {
            assert!(s.argument(off).is_err());
        }
        assert!(s.cleanup(8).is_err());
        s.pop_reg(4).unwrap();
        assert!(s.pop_reg(0).is_err());
        assert!(Value::BufferOffset(2).scalar().is_err());
        assert!(Word::SavedReg(4, Value::Original(4))
            .argument_value()
            .is_none());
        assert!(Word::SavedReg(5, Value::Anchor(2))
            .argument_value()
            .is_none());
    }
}
