use super::*;
/// Affine bit-vector over the two unknown UTF16 units and unknown API length.
/// Coefficients and constants are modulo 2^32; no sampled input is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Expr {
    c: u32,
    a: [u32; 3],
}
impl Expr {
    fn constant(c: u32) -> Self {
        Self { c, a: [0; 3] }
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
    fn bounds(self, ranges: &[(u32, u32); 3]) -> (u32, u32) {
        // Integer affine bounds, then modular projection. Wrap crossing loses precision.
        let (mut lo, mut hi) = (i128::from(self.c as i32), i128::from(self.c as i32));
        for (a, (l, h)) in self.a.into_iter().zip(ranges) {
            let k = i128::from(a as i32);
            let (l, h) = (i128::from(*l), i128::from(*h));
            lo += k * if k >= 0 { l } else { h };
            hi += k * if k >= 0 { h } else { l };
        }
        let m = 1i128 << 32;
        if lo.div_euclid(m) != hi.div_euclid(m) {
            (0, u32::MAX)
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
    fn bounds(&self, ranges: &[(u32, u32); 3]) -> (u32, u32) {
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
    Local(u8),
    Saved,
    Arg(Value),
}
#[derive(Clone)]
struct State {
    regs: [Value; 4],
    stack: Vec<Word>,
    allocated: bool,
    calls: u8,
    initialized: u8,
    ranges: [(u32, u32); 3],
    flags: Option<(Expr, u8, u32)>,
}
impl State {
    fn new() -> Self {
        Self {
            regs: [
                Value::Unknown,
                Value::Unknown,
                Value::Unknown,
                Value::OriginalEsi,
            ],
            stack: vec![Word::Return],
            allocated: false,
            calls: 0,
            initialized: 0,
            ranges: [(0, 65535), (0, 65535), (0, u32::MAX)],
            flags: None,
        }
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
}
/// Intersect a symbol with the exact preimage of an unsigned modular comparison.
/// Splitting retains disjunctions instead of merging initialized and failed API paths.
fn refine(state: &State, condition: Condition, taken: bool) -> Result<Vec<State>, String> {
    let (expr, width, k) = state.flags.ok_or("input: branch consumes unknown flags")?;
    let m = 1u64 << width;
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
    let mut pending = vec![(entry, State::new())];
    let mut loads = BTreeMap::new();
    let mut steps = 0;
    let mut returns = 0;
    while let Some((pc, mut s)) = pending.pop() {
        steps += 1;
        need(steps <= 4096, "input: symbolic state budget")?;
        let &(op, next) = graph.get(&pc).ok_or("input: missing decoded target")?;
        need(next > pc, "input: acyclic fallthrough")?;
        match op {
            Op::Allocate => {
                need(
                    !s.allocated && s.stack == [Word::Return],
                    "input: allocation lifetime/ownership",
                )?;
                s.allocated = true;
                s.stack.extend([Word::Local(4), Word::Local(0)]);
                s.flags = None;
            }
            Op::Buffer => {
                need(s.local(0, 8)? == 0, "input: buffer base")?;
                s.regs[0] = Value::Buffer;
            }
            Op::Push(n) => s.stack.push(Word::Arg(Value::Scalar(Expr::constant(n)))),
            Op::PushEax => s.stack.push(Word::Arg(s.regs[0].clone())),
            Op::Name => s.stack.push(Word::Arg(Value::Name)),
            Op::Acquire => {
                need(
                    s.calls == 0
                        && s.stack
                            == [
                                Word::Return,
                                Word::Local(4),
                                Word::Local(0),
                                Word::Arg(Value::Scalar(Expr::constant(3))),
                                Word::Arg(Value::Buffer),
                                Word::Arg(Value::Name),
                            ],
                    "input: API arguments/live owner/capacity",
                )?;
                need(s.regs[3] == Value::OriginalEsi, "input: API ESI obligation")?;
                s.calls = 1;
                s.stack.truncate(3);
                s.flags = None;
                s.regs[0] = Value::Scalar(Expr::variable(2));
                s.regs[1] = Value::Unknown;
                s.regs[2] = Value::Unknown;
                // Full API domain, including conservative raw failure/oversize states.
                for (lo, hi, initialized) in [
                    (0, 0, 0),
                    (1, 1, 4),
                    (2, 2, 6),
                    (4, 65, 0),
                    (66, u32::MAX, 0),
                ] {
                    let mut fork = s.clone();
                    fork.ranges[2] = (lo, hi);
                    fork.initialized = initialized;
                    if lo == 1 {
                        fork.ranges[1] = (0, 0);
                    }
                    pending.push((next, fork));
                }
                continue;
            }
            Op::Move(d, v) => s.regs[d] = s.regs[v].expression()?.value(),
            Op::Mov(r, v) => s.regs[r] = Value::Scalar(Expr::constant(v)),
            Op::Test(r) => s.flags = Some((s.regs[r].scalar()?, 32, 0)),
            Op::Compare(r, width, v) => s.flags = Some((s.regs[r].scalar()?, width, v)),
            Op::Load(d, off) => {
                let local = s.local(off, 4)?;
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
                let value = if local == 0 {
                    Expr::variable(0).add(Expr::variable(1), 65536, 0)
                } else {
                    Expr::variable(1)
                };
                s.regs[d] = Value::Scalar(value);
            }
            Op::Save => {
                need(
                    s.regs[3] == Value::OriginalEsi && !s.stack.contains(&Word::Saved),
                    "input: saved ESI ownership",
                )?;
                s.stack.push(Word::Saved);
            }
            Op::Restore => {
                need(
                    s.stack.pop() == Some(Word::Saved),
                    "input: protected saved slot",
                )?;
                s.regs[3] = Value::OriginalEsi;
            }
            Op::Cleanup => {
                need(
                    s.stack == [Word::Return, Word::Local(4), Word::Local(0)],
                    "input: local cleanup ownership",
                )?;
                s.stack.truncate(1);
                s.initialized = 0;
                s.flags = None;
            }
            Op::Ret => {
                need(
                    s.calls == 1 && s.stack == [Word::Return] && s.regs[3] == Value::OriginalEsi,
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
                s.regs[d] = Value::Scalar(s.regs[a].scalar()?.add(s.regs[b].scalar()?, k, c))
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
                s.regs[d] = left.binary(right, multiply)?.value();
                s.flags = None;
            }
            Op::Branch(c, target) => {
                need(target > pc, "input: symbolic backedge")?;
                for fork in refine(&s, c, true)? {
                    pending.push((target, fork));
                }
                for fork in refine(&s, c, false)? {
                    pending.push((next, fork));
                }
                continue;
            }
        }
        need(s.stack.len() <= 7, "input: stack bound")?;
        pending.push((next, s));
    }
    need(returns > 0, "input: no terminal proof")?;
    // Every emitted read must have an established physical offset; unreachable reads fail.
    for (&pc, (op, _)) in &graph {
        if matches!(op, Op::Load(..)) {
            need(loads.contains_key(&pc), "input: unproved emitted read")?;
        }
    }
    Ok(Proven {
        graph,
        entry,
        loads,
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
            mid.bounds(&[(48, 48), (48, 57), (2, 2)]),
            (0xffffffe8, 0xffffffe8)
        );
        let answer = Expr::variable(1).add(mid, 2, 0);
        assert_eq!(answer.bounds(&[(48, 57), (48, 57), (2, 2)]), (0, 99));
        assert_eq!(answer.bounds(&[(48, 48), (55, 55), (2, 2)]), (7, 7));
    }
    #[test]
    fn protected_full_ranges_and_zero_extension_exclusions() {
        let mut s = State::new();
        s.stack
            .extend([Word::Local(4), Word::Local(0), Word::Saved]);
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
                .bounds(&[(0, 1), (0, 0), (0, 0)]),
            (0, u32::MAX)
        );
    }
}

#[cfg(test)]
mod nonlinear_tests {
    use super::*;
    #[test]
    fn independent_modular_products_and_resource_caps() {
        let ranges = [(0, 0); 3];
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
        assert_eq!(e.bounds(&[(0, 9), (0, 0), (0, 0)]), (0, 81));
        assert_eq!(e.bounds(&[(0, u32::MAX), (0, 0), (0, 0)]), (0, u32::MAX));
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
