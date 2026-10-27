//! Compiler-only constrained Horn clauses over the *bound production graph*.
//! Spacer must prove the error relation unreachable, including every memory
//! access and known-state use. No sampled execution or bounded unrolling.
use super::{
    frame::{Frames, Slot, Value},
    graph::*,
    Bound, Function,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
#[derive(Debug)]
pub(super) struct Logic {
    pub(super) text: String,
    pub(super) queries: usize,
}
fn and(xs: &[String]) -> String {
    if xs.is_empty() {
        "true".into()
    } else {
        format!("(and {})", xs.join(" "))
    }
}
fn not(x: &str) -> String {
    format!("(not {x})")
}
fn eq(a: &str, b: &str) -> String {
    format!("(= {a} {b})")
}
fn num(n: i64) -> String {
    if n < 0 {
        format!("(- {})", -n)
    } else {
        n.to_string()
    }
}
// Exact unsigned bit mask, with a linear finite-control specialization at use sites.
fn and_mask(a: &str, mask: u32) -> String {
    if mask.checked_add(1).is_some_and(|n| n.is_power_of_two()) {
        return format!("(mod {a} {})", u64::from(mask) + 1);
    }
    let terms: Vec<_> = (0..32)
        .filter(|bit| mask & (1u32 << bit) != 0)
        .map(|bit| {
            let power = 1u64 << bit;
            format!("(* {power} (mod (div {a} {power}) 2))")
        })
        .collect();
    if terms.is_empty() {
        "0".into()
    } else {
        format!("(+ 0 {})", terms.join(" "))
    }
}
/// Candidate discovery is heuristic, never an admission oracle. Binary pending
/// state uses a separate global proof. Weighted candidates are inductive domain
/// obligations: entry and EVERY incoming edge check them before continuation may
/// assume them. All such checks and memory checks are mandatory UNSAT queries;
/// a first failed invariant cannot be removed by the successor's precondition.
#[derive(Clone, Copy)]
struct Hint {
    pc: u32,
    input: u8,
    output: u8,
    pending: u8,
    weight: u32,
    inner: bool,
    modular: bool,
    owner: Option<i32>,
}
impl Hint {
    fn expression(&self, s: &[String]) -> String {
        if self.weight > 1 {
            return if self.inner {
                format!(
                    "(<= (+ {} (- {} {})) (* {} (+ {} 1)))",
                    s[self.output as usize],
                    self.weight,
                    if self.modular {
                        format!("(mod {} {})", s[self.pending as usize], self.weight)
                    } else {
                        s[self.pending as usize].clone()
                    },
                    self.weight,
                    s[self.input as usize]
                )
            } else {
                format!(
                    "(<= {} (* {} {}))",
                    s[self.output as usize], self.weight, s[self.input as usize]
                )
            };
        }
        format!(
            "(<= (+ {} {}) (+ {} 1))",
            s[self.output as usize], s[self.pending as usize], s[self.input as usize]
        )
    }
}
fn hints(bound: &Bound, frames: &Frames) -> Vec<Hint> {
    let mut result = Vec::new();
    for (&end, node) in &bound.graph.nodes {
        let Operation::Branch(Condition::Below, start) = node.operation else {
            continue;
        };
        if start >= end {
            continue;
        }
        // A loop begins with an indexed byte load. Other graphs retain ordinary
        // safety proofs; this is candidate discovery, never a graph recognizer
        // that substitutes program behavior or bypasses proof obligations.
        let Operation::Binary(Binary::Move, _, Operand::Memory(input, 8)) =
            &bound.graph.nodes[&start].operation
        else {
            continue;
        };
        let Some(index) = input.index else {
            continue;
        };
        let mut anchor = input.clone();
        anchor.index = None;
        let Ok(Value::Frame(Some(input_base))) = frames.states[&start].address(&anchor) else {
            continue;
        };
        let body: Vec<_> = bound.graph.nodes.range(start..=end).collect();
        let modified: BTreeSet<_> = body
            .iter()
            .filter_map(|(_, n)| match n.operation {
                Operation::Increment(r)
                | Operation::Decrement(r)
                | Operation::Negate(r)
                | Operation::Binary(_, Operand::Reg(r), _) => Some(r.index),
                _ => None,
            })
            .collect();
        let pending: Vec<_> = frames.states[&start]
            .finite
            .iter()
            .filter_map(|(&r, v)| {
                ((0..8).contains(&r)
                    && modified.contains(&(r as u8))
                    && [2u32, 4, 8].iter().any(|n| *v == (0..*n).collect()))
                .then_some(r as u8)
            })
            .collect();
        if pending.len() != 1 {
            continue;
        }
        let mut outputs = BTreeSet::new();
        for (&pc, n) in &body {
            if let Operation::Binary(Binary::Move, Operand::Memory(a, 8), _) = &n.operation {
                let Some(out) = a.index else {
                    continue;
                };
                let mut anchor = a.clone();
                anchor.index = None;
                if matches!(frames.states[&pc].address(&anchor),Ok(Value::Frame(Some(base))) if base!=input_base)
                    && body
                        .iter()
                        .any(|(_, n)| matches!(n.operation,Operation::Increment(r) if r.index==out))
                {
                    outputs.insert(out);
                }
            }
        }
        if outputs.len() == 1 && result.len() < 8 {
            result.push(Hint {
                pc: start,
                input: index,
                output: *outputs.first().unwrap(),
                pending: pending[0],
                weight: if frames.states[&start].finite[&i32::from(pending[0])].len() == 2 {
                    1
                } else {
                    frames.states[&start].finite[&i32::from(pending[0])].len() as u32
                },
                inner: false,
                modular: false,
                owner: None,
            });
            let outer = *result.last().unwrap();
            if outer.weight > 1 {
                for (&tail, n) in &body {
                    if let Operation::Branch(Condition::NotEqual, head) = n.operation {
                        if head < tail
                            && head >= start
                            && matches!(&bound.graph.nodes[&head].operation, Operation::Binary(Binary::Move, Operand::Memory(a,8),_) if a.index==Some(outer.output))
                        {
                            result.push(Hint {
                                pc: head,
                                inner: true,
                                ..outer
                            });
                        }
                    }
                }
            }
        }
    }
    // Additional structural candidates for rotated/equality-counted loops.
    // Candidates carry no authority: every incoming CFG edge proves the bound.
    for (&start, node) in &bound.graph.nodes {
        if result.len() >= 64 {
            break;
        }
        let input = match &node.operation {
            Operation::Binary(Binary::Move, _, Operand::Memory(a, 8))
            | Operation::ZeroExtend(_, Operand::Memory(a, 8)) => a,
            _ => continue,
        };
        if result.iter().any(|h| h.pc == start) {
            continue;
        }
        let Some(index) = input.index else {
            continue;
        };
        let mut anchor = input.clone();
        anchor.index = None;
        let Ok(Value::Frame(Some(base))) = frames.states[&start].address(&anchor) else {
            continue;
        };
        // Reach only the transformation cycle; API calls delimit read epochs.
        let mut seen = BTreeSet::new();
        let mut todo = vec![start];
        while let Some(pc) = todo.pop() {
            if !seen.insert(pc) {
                continue;
            }
            let n = &bound.graph.nodes[&pc];
            if matches!(n.operation, Operation::Call(_) | Operation::Return) {
                continue;
            }
            todo.extend(n.successors.iter().copied().filter(|p| *p != start));
        }
        let mut outputs = BTreeSet::new();
        let mut owners = BTreeMap::new();
        let mut modular = None;
        for &pc in &seen {
            match &bound.graph.nodes[&pc].operation {
                Operation::Binary(Binary::Move, Operand::Memory(a, 8), _) => {
                    let Some(out) = a.index else {
                        continue;
                    };
                    let mut a = a.clone();
                    a.index = None;
                    if matches!(frames.states[&pc].address(&a),Ok(Value::Frame(Some(b))) if b!=base)
                        && frames.states[&start].registers[out as usize].scalar()
                        && frames.states[&start].known[out as usize] == u32::MAX
                    {
                        outputs.insert(out);
                        if let Ok(Value::Frame(Some(b))) = frames.states[&pc].address(&a) {
                            owners.insert(out, b);
                        }
                    }
                }
                Operation::Binary(Binary::Test, Operand::Reg(r), Operand::Immediate(mask))
                    if r.width == 8 && r.shift == 0 && [3, 7].contains(mask) =>
                {
                    modular = Some((r.index, mask + 1));
                }
                _ => (),
            }
        }
        if outputs.len() != 1 {
            continue;
        }
        let (pending, weight) = modular.unwrap_or((0, 2));
        let outer = Hint {
            pc: start,
            input: index,
            output: *outputs.first().unwrap(),
            pending,
            weight,
            inner: false,
            modular: modular.is_some(),
            owner: owners.get(outputs.first().unwrap()).copied(),
        };
        result.push(outer);
        if modular.is_some() {
            for &pc in &seen {
                if result.len() >= 64 {
                    break;
                }
                if let Operation::Branch(Condition::NotEqual, head) =
                    bound.graph.nodes[&pc].operation
                {
                    if head < pc
                        && seen.contains(&head)
                        && matches!(&bound.graph.nodes[&head].operation,Operation::Binary(Binary::Move,Operand::Memory(a,8),_) if a.index==Some(outer.output))
                    {
                        result.push(Hint {
                            pc: head,
                            inner: true,
                            ..outer
                        });
                    }
                }
            }
        }
    }
    result
}
#[derive(Clone, Copy)]
struct Region {
    base: i32,
    cap: u32,
    prefix: usize,
}
struct Builder<'a> {
    bound: &'a Bound,
    frames: &'a Frames,
    names: Vec<String>,
    bools: BTreeSet<usize>,
    arguments: BTreeMap<i32, usize>,
    cells: BTreeMap<i32, usize>,
    prefix: usize,
    regions: Vec<Region>,
    cf: usize,
    zf: usize,
    ck: usize,
    zk: usize,
    error: usize,
    ek: usize,
    base: i32,
    cap: u32,
    fresh: usize,
    declarations: String,
    rules: String,
    safe: Vec<String>,
    hints: Vec<Hint>,
}
impl Builder<'_> {
    fn fixed(&self, pc: u32) -> BTreeMap<usize, String> {
        let frame = &self.frames.states[&pc];
        let mut fixed = BTreeMap::new();
        fn value(fixed: &mut BTreeMap<usize, String>, i: usize, k: usize, v: Value) {
            match v {
                Value::Constant(n) => {
                    fixed.insert(i, n.to_string());
                    fixed.insert(k, "32".into());
                }
                Value::Frame(Some(n)) => {
                    fixed.insert(i, num(i64::from(n)));
                    fixed.insert(k, "32".into());
                }
                Value::Frame(None)
                | Value::Handle(_)
                | Value::Boolean
                | Value::Error
                | Value::ErrorAffine(_, _) => {
                    fixed.insert(k, "32".into());
                }
                Value::Function(_) => {
                    fixed.insert(i, "0".into());
                    fixed.insert(k, "32".into());
                }
                Value::Entry(_) | Value::Unknown => {
                    fixed.insert(i, "0".into());
                    fixed.insert(k, "0".into());
                }
                Value::Scalar => {}
            }
        }
        for (i, &v) in frame.registers.iter().enumerate() {
            value(&mut fixed, i, i + 8, v);
        }
        for (&at, &i) in &self.arguments {
            match frame.slots.get(&at) {
                Some(Slot::Argument(v)) => value(&mut fixed, i, i + 1, *v),
                _ => {
                    fixed.insert(i, "0".into());
                    fixed.insert(i + 1, "0".into());
                }
            }
        }
        // Must-definedness is a separate finite dataflow proof. Removing these
        // Boolean/mask dimensions leaves relational solving to numeric bounds.
        for i in 0..8 {
            fixed.insert(i + 8, frame.known[i].trailing_ones().to_string());
        }
        for (&at, &i) in &self.arguments {
            fixed.insert(
                i + 1,
                frame
                    .argument_known
                    .get(&at)
                    .unwrap_or(&0)
                    .trailing_ones()
                    .to_string(),
            );
        }
        for (&at, &i) in &self.cells {
            fixed.insert(
                i + 1,
                frame
                    .local_known
                    .get(&at)
                    .unwrap_or(&0)
                    .trailing_ones()
                    .to_string(),
            );
        }
        fixed.insert(self.ck, frame.cf_known.to_string());
        fixed.insert(self.zk, frame.zf_known.to_string());
        fixed
    }
    fn state(&self, pc: u32) -> Vec<String> {
        let fixed = self.fixed(pc);
        self.names
            .iter()
            .enumerate()
            .map(|(i, n)| fixed.get(&i).unwrap_or(n).clone())
            .collect()
    }
    fn domain(&self, pc: u32, s: &[String]) -> String {
        let frame = &self.frames.states[&pc];
        let mut terms = Vec::new();
        let scalar = |v: Value| {
            matches!(
                v,
                Value::Scalar
                    | Value::Constant(_)
                    | Value::Boolean
                    | Value::Error
                    | Value::ErrorAffine(_, _)
                    | Value::Handle(_)
            )
        };
        for (i, _) in s.iter().enumerate().take(8) {
            if scalar(frame.registers[i]) {
                terms.push(format!("(and (<= 0 {}) (<= {} 4294967295))", s[i], s[i]));
            }
        }
        for (&at, &i) in &self.arguments {
            if matches!(frame.slots.get(&at),Some(Slot::Argument(v)) if scalar(*v)) {
                terms.push(format!("(and (<= 0 {}) (<= {} 4294967295))", s[i], s[i]));
            }
        }
        for &i in self.cells.values() {
            terms.push(format!("(and (<= 0 {}) (<= {} 4294967295))", s[i], s[i]));
        }
        for region in &self.regions {
            terms.push(format!(
                "(and (<= 0 {}) (<= {} {}))",
                s[region.prefix], s[region.prefix], region.cap
            ));
        }
        for (&key, values) in &frame.finite {
            let index = if key >= 0 {
                Some(key as usize)
            } else {
                self.cells.get(&key).or(self.arguments.get(&key)).copied()
            };
            if let Some(i) = index {
                let alternatives: Vec<_> =
                    values.iter().map(|v| eq(&s[i], &v.to_string())).collect();
                terms.push(format!("(or false {})", alternatives.join(" ")));
            }
        }
        for hint in &self.hints {
            if hint.pc == pc {
                terms.push(hint.expression(s));
                terms.push(format!(
                    "(and (<= 0 {}) (< {} {}))",
                    s[hint.input as usize], s[hint.input as usize], s[self.prefix]
                ));
                if let Some(base) = hint.owner {
                    if let Some(region) = self.regions.iter().find(|r| r.base == base) {
                        terms.push(format!(
                            "(<= {} {})",
                            s[hint.output as usize], s[region.prefix]
                        ));
                    }
                }
            }
        }
        and(&terms)
    }
    fn fresh(&mut self, boolean: bool) -> String {
        let name = format!("v{}", self.fresh);
        self.fresh += 1;
        writeln!(
            self.declarations,
            "(declare-var {name} {})",
            if boolean { "Bool" } else { "Int" }
        )
        .unwrap();
        name
    }
    fn atom(&self, pc: u32, s: &[String]) -> String {
        let fixed = self.fixed(pc);
        let args: Vec<_> = s
            .iter()
            .enumerate()
            .filter(|(i, _)| !fixed.contains_key(i))
            .map(|(_, v)| v.clone())
            .collect();
        format!("(p{pc} {})", args.join(" "))
    }
    fn check(&mut self, pre: &str, assume: &[String], ok: String) {
        writeln!(
            self.rules,
            "(rule (=> (and {pre} {} {}) bad))",
            and(assume),
            not(&ok)
        )
        .unwrap();
        // Assert before assume: the error edge remains reachable for any first
        // violation. All properties are mandatory, so safe continuation cannot
        // hide the earliest failure on an original execution.
        self.safe.push(ok);
    }
    fn known(&mut self, pre: &str, assume: &[String], k: &str, width: u8) {
        self.check(pre, assume, format!("(>= {k} {width})"));
    }
    fn address(&self, a: &Address, s: &[String]) -> String {
        format!(
            "(+ {} {} {})",
            a.base.map_or("0".into(), |r| s[r as usize].clone()),
            a.index
                .map_or("0".into(), |r| format!("(* {} {})", s[r as usize], a.scale)),
            num(i64::from(a.displacement as i32))
        )
    }
    fn byte_regions(&self, pc: u32, a: &Address) -> Vec<Region> {
        let mut anchor = a.clone();
        anchor.index = None;
        let at = match self.frames.states[&pc].address(&anchor) {
            Ok(Value::Frame(Some(at))) => Some(at),
            _ => None,
        };
        let selected: Vec<_> = self
            .regions
            .iter()
            .copied()
            .filter(|r| at.is_none_or(|at| at >= r.base && at < r.base + r.cap as i32))
            .collect();
        // An addressing displacement may start one byte before a region while
        // a positive index restores the address (reverse traversal). In that
        // case require the ordinary disjunction of complete region bounds.
        if selected.is_empty() {
            self.regions.clone()
        } else {
            selected
        }
    }
    fn coverage(
        &self,
        pc: u32,
        offset: &str,
        len: &str,
        s: &[String],
        append: bool,
        regions: &[Region],
    ) -> String {
        let terms: Vec<_> = regions.iter().filter(|r| self.frames.states[&pc].region(r.base, r.cap as i32)).map(|r| {
            let base = num(i64::from(r.base));
            let end = num(i64::from(r.base) + i64::from(r.cap));
            if append && r.prefix != self.prefix {
                format!("(and (<= {base} {offset}) (< {offset} {end}) (<= {offset} (+ {base} {})))",s[r.prefix])
            } else {
                format!("(and (<= 0 {len}) (<= {base} {offset}) (<= (+ {offset} {len}) (+ {base} {})))",s[r.prefix])
            }
        }).collect();
        format!("(or false {})", terms.join(" "))
    }
    fn read(
        &mut self,
        pc: u32,
        o: &Operand,
        s: &[String],
        pre: &str,
        assume: &[String],
    ) -> Result<(String, String), String> {
        Ok(match o {
            Operand::Immediate(n) => (n.to_string(), "32".into()),
            Operand::Reg(r) => {
                let v = s[r.index as usize].clone();
                (
                    if r.width == 8 {
                        format!("(mod (div {v} {}) 256)", 1u32 << r.shift)
                    } else {
                        v
                    },
                    self.frames.states[&pc].bits(o).to_string(),
                )
            }
            Operand::Memory(a, _) if a.base.is_none() && a.index.is_none() => {
                if !self.bound.loads.contains_key(&pc) {
                    return Err("stream logic: unbound absolute read".into());
                }
                ("0".into(), "32".into())
            }
            Operand::Memory(a, w) => {
                self.address_known(a, s, pre, assume);
                let offset = self.address(a, s);
                if *w == 32 {
                    let Value::Frame(Some(at)) = self.frames.states[&pc].address(a)? else {
                        return Err("stream logic: dynamic word read unsupported".into());
                    };
                    let &i = self
                        .cells
                        .get(&at)
                        .ok_or("stream logic: word read outside API count cells")?;
                    (s[i].clone(), s[i + 1].clone())
                } else {
                    if let Ok(Value::Frame(Some(at))) = self.frames.states[&pc].address(a) {
                        if let Some((&base, &i)) = self.cells.range(..=at).next_back() {
                            if at < base + 4 {
                                let shift = (at - base) * 8;
                                let mask = self.frames.states[&pc]
                                    .local_known
                                    .get(&base)
                                    .copied()
                                    .unwrap_or(0);
                                return Ok((
                                    format!("(mod (div {} {}) 256)", s[i], 1u32 << shift),
                                    ((mask >> shift) & 255).trailing_ones().to_string(),
                                ));
                            }
                        }
                    }
                    self.check(
                        pre,
                        assume,
                        self.coverage(pc, &offset, "1", s, false, &self.byte_regions(pc, a)),
                    );
                    let byte = self.fresh(false);
                    // Any input/stored byte; over-approximate content, never init.
                    (format!("(mod {byte} 256)"), "8".into())
                }
            }
        })
    }
    fn address_known(&mut self, a: &Address, s: &[String], pre: &str, assume: &[String]) {
        for r in [a.base, a.index].into_iter().flatten() {
            self.known(pre, assume, &s[8 + r as usize], 32);
        }
    }
    fn write(
        &mut self,
        pc: u32,
        o: &Operand,
        value: (String, String),
        s: &mut [String],
        pre: &str,
        assume: &[String],
    ) -> Result<(), String> {
        let (v, k) = value;
        match o {
            Operand::Reg(r) => {
                let i = r.index as usize;
                if r.width == 8 {
                    if !self.frames.states[&pc].registers[i].scalar() {
                        s[i] = "0".into();
                    }
                    let scale = 1u32 << r.shift;
                    let end = scale * 256;
                    s[i] = format!(
                        "(+ (mod {} {scale}) (* (mod {v} 256) {scale}) (* (div {} {end}) {end}))",
                        s[i], s[i]
                    );
                    // The finite known-mask analysis supplies successor knowledge.
                    s[8 + i] = "0".into();
                } else {
                    s[i] = v;
                    s[8 + i] = k;
                }
            }
            Operand::Memory(a, w) => {
                self.address_known(a, s, pre, assume);
                if *w == 8 {
                    self.known(pre, assume, &k, *w);
                }
                if *w == 32 {
                    let Value::Frame(Some(at)) = self.frames.states[&pc].address(a)? else {
                        return Err("stream logic: dynamic word store unsupported".into());
                    };
                    let &i = self
                        .cells
                        .get(&at)
                        .ok_or("stream logic: word store outside API count cells")?;
                    s[i] = v;
                    s[i + 1] = k;
                } else {
                    let offset = self.address(a, s);
                    self.check(
                        pre,
                        assume,
                        self.coverage(pc, &offset, "1", s, true, &self.byte_regions(pc, a)),
                    );
                    // A proved store can extend exactly one initialized prefix
                    // by one byte, or overwrite it. It cannot bridge a gap.
                    for r in self.byte_regions(pc, a) {
                        if r.prefix == self.prefix {
                            continue;
                        }
                        let base = num(i64::from(r.base));
                        let end = num(i64::from(r.base) + i64::from(r.cap));
                        s[r.prefix] = format!(
                            "(ite (and (= {offset} (+ {base} {})) (< {offset} {end})) (+ {} 1) {})",
                            s[r.prefix], s[r.prefix], s[r.prefix]
                        );
                    }
                }
            }
            _ => return Err("stream logic: invalid destination".into()),
        }
        Ok(())
    }
    fn node(&mut self, pc: u32) -> Result<(), String> {
        self.safe.clear();
        let state = &self.frames.states[&pc];
        let node = &self.bound.graph.nodes[&pc];
        let mut s = self.state(pc);
        let pre = format!("(and {} {})", self.atom(pc, &s), self.domain(pc, &s));
        let mut assume = vec![];
        match &node.operation {
            Operation::Binary(op, dst, src) => {
                let width = match dst {
                    Operand::Reg(r) => r.width,
                    Operand::Memory(_, w) => *w,
                    _ => return Err("stream logic: width".into()),
                };
                let (b, bk) = self.read(pc, src, &s, &pre, &assume)?;
                if *op == Binary::Move {
                    self.write(pc, dst, (b, bk), &mut s, &pre, &assume)?;
                } else if *op == Binary::Xor && dst == src {
                    self.write(
                        pc,
                        dst,
                        ("0".into(), width.to_string()),
                        &mut s,
                        &pre,
                        &assume,
                    )?;
                    s[self.cf] = "false".into();
                    s[self.zf] = "true".into();
                    s[self.ck] = "true".into();
                    s[self.zk] = "true".into();
                } else {
                    let (a, ak) = self.read(pc, dst, &s, &pre, &assume)?;
                    self.known(&pre, &assume, &ak, width);
                    self.known(&pre, &assume, &bk, width);
                    if width == 8 {
                        let exact = match op {
                            Binary::Compare => Some(format!("(mod (- {a} {b}) 256)")),
                            Binary::Test | Binary::And => {
                                if let Operand::Immediate(mask) = src {
                                    Some(and_mask(&a, *mask & 255))
                                } else {
                                    // Exact byte AND; eight bits, no unverified boolean shortcut.
                                    Some(format!("(+ 0 {})", (0..8).map(|bit| {
                                        let p = 1u32 << bit;
                                        format!("(* {p} (ite (and (= (mod (div {a} {p}) 2) 1) (= (mod (div {b} {p}) 2) 1)) 1 0))")
                                    }).collect::<Vec<_>>().join(" ")))
                                }
                            }
                            _ => None,
                        };
                        let v = exact.unwrap_or_else(|| {
                            let v = self.fresh(false);
                            format!("(mod {v} 256)")
                        });
                        if !matches!(op, Binary::Compare | Binary::Test) {
                            self.write(pc, dst, (v.clone(), "8".into()), &mut s, &pre, &assume)?;
                        }
                        s[self.cf] = match op {
                            Binary::Compare => format!("(< {a} {b})"),
                            Binary::Test | Binary::And => "false".into(),
                            _ => self.fresh(true),
                        };
                        s[self.zf] = eq(&v, "0");
                        s[self.ck] = "true".into();
                        s[self.zk] = "true".into();
                    } else {
                        let pointer = matches!(dst,Operand::Reg(r) if matches!(state.registers[r.index as usize],Value::Frame(_)));
                        let modulus = if width == 8 { 256u64 } else { 1u64 << 32 };
                        let raw = match op {
                            Binary::Add => format!("(+ {a} {b})"),
                            Binary::Sub | Binary::Compare => format!("(- {a} {b})"),
                            Binary::Sbb => {
                                self.check(&pre, &assume, s[self.ck].clone());
                                format!("(- {a} {b} (ite {} 1 0))", s[self.cf])
                            }
                            Binary::And => {
                                let Operand::Immediate(mask) = src else {
                                    return Err("stream logic: AND requires immediate mask".into());
                                };
                                if let Operand::Reg(r) = dst {
                                    if let Some(values) = state.finite.get(&i32::from(r.index)) {
                                        // Each finite input has an exact constant result. Keep
                                        // the general bit expression as the fallback below;
                                        // this avoids nonlinear modulo search on loop control.
                                        let fallback = and_mask(&a, *mask);
                                        values.iter().rev().fold(fallback, |tail, value| {
                                            format!("(ite (= {a} {value}) {} {tail})", value & mask)
                                        })
                                    } else {
                                        and_mask(&a, *mask)
                                    }
                                } else {
                                    and_mask(&a, *mask)
                                }
                            }
                            Binary::Test if dst == src => a.clone(),
                            _ => {
                                return Err(
                                    "stream logic: bitwise form needs separate exact encoding"
                                        .into(),
                                )
                            }
                        };
                        let opaque = matches!(dst,Operand::Reg(r) if matches!(state.registers[r.index as usize],Value::Error|Value::ErrorAffine(_, _)));
                        let v = if pointer || *op == Binary::And {
                            // AND's mathematical result is always within the operand width.
                            raw.clone()
                        } else if opaque || *op == Binary::Sbb {
                            format!("(mod {raw} 4294967296)")
                        } else if width == 32 && matches!(op, Binary::Add | Binary::Sub) {
                            if *op == Binary::Add {
                                format!("(ite (>= {raw} 4294967296) (- {raw} 4294967296) {raw})")
                            } else {
                                format!("(ite (< {raw} 0) (+ {raw} 4294967296) {raw})")
                            }
                        } else {
                            {
                                let overflow = self.fresh(false);
                                assume.push(format!(
                                    "(and (<= 0 {overflow}) (< {overflow} {modulus}))"
                                ));
                                format!(
                                    "(ite (and (<= 0 {raw}) (< {raw} {modulus})) {raw} {overflow})"
                                )
                            }
                        };
                        if !matches!(op, Binary::Compare | Binary::Test) {
                            self.write(
                                pc,
                                dst,
                                (v.clone(), width.to_string()),
                                &mut s,
                                &pre,
                                &assume,
                            )?;
                        }
                        s[self.zf] = if *op == Binary::Compare {
                            eq(&a, &b)
                        } else if *op == Binary::Test {
                            eq(&a, "0")
                        } else {
                            eq(&v, "0")
                        };
                        s[self.cf] = match op {
                            Binary::Add => format!("(>= {raw} {modulus})"),
                            Binary::Sub | Binary::Compare => format!("(< {a} {b})"),
                            Binary::Sbb => format!("(< {raw} 0)"),
                            _ => "false".into(),
                        };
                        let error_predicate = opaque;
                        s[self.ck] = (!pointer && !error_predicate).to_string();
                        s[self.zk] = (!pointer).to_string();
                    }
                }
            }
            Operation::ZeroExtend(dst, src) => {
                let (v, k) = self.read(pc, src, &s, &pre, &assume)?;
                self.known(&pre, &assume, &k, 8);
                s[dst.index as usize] = v;
                s[8 + dst.index as usize] = "32".into();
            }
            Operation::Set(_, dst) => {
                self.check(&pre, &assume, s[self.zk].clone());
                let value = format!("(ite {} 0 1)", s[self.zf]);
                self.write(
                    pc,
                    &Operand::Reg(*dst),
                    (value, "8".into()),
                    &mut s,
                    &pre,
                    &assume,
                )?;
            }
            Operation::Not(dst) => {
                self.known(&pre, &assume, &s[8 + dst.index as usize], 32);
                s[dst.index as usize] = format!("(- 4294967295 {})", s[dst.index as usize]);
            }
            Operation::ConditionalMove(cond, dst, src) => {
                if *cond != Condition::AboveEqual {
                    self.check(&pre, &assume, s[self.zk].clone());
                }
                let predicate = if *cond == Condition::Above {
                    self.check(&pre, &assume, s[self.ck].clone());
                    format!("(and (not {}) (not {}))", s[self.cf], s[self.zf])
                } else if *cond == Condition::AboveEqual {
                    self.check(&pre, &assume, s[self.ck].clone());
                    not(&s[self.cf])
                } else {
                    s[self.zf].clone()
                };
                self.known(&pre, &assume, &s[8 + dst.index as usize], 32);
                self.known(&pre, &assume, &s[8 + src.index as usize], 32);
                s[dst.index as usize] = format!(
                    "(ite {} {} {})",
                    predicate, s[src.index as usize], s[dst.index as usize]
                );
            }
            Operation::Address(r, a) => {
                if matches!(
                    state.registers[a.base.unwrap_or(4) as usize],
                    Value::Frame(_)
                ) {
                    self.address_known(a, &s, &pre, &assume);
                    s[r.index as usize] = self.address(a, &s);
                    s[8 + r.index as usize] = "32".into();
                } else {
                    let bits = [a.base, a.index]
                        .into_iter()
                        .flatten()
                        .map(|i| state.known[i as usize].trailing_ones())
                        .min()
                        .unwrap_or(32);
                    let modulus = 1u64 << bits;
                    let raw = self.address(a, &s);
                    s[r.index as usize] = if bits == 32 && a.index.is_none() {
                        format!("(ite (< {raw} 0) (+ {raw} 4294967296) (ite (>= {raw} 4294967296) (- {raw} 4294967296) {raw}))")
                    } else {
                        format!("(mod {raw} {modulus})")
                    };
                    s[8 + r.index as usize] = bits.to_string();
                }
            }
            Operation::Increment(r) => {
                let i = r.index as usize;
                self.known(&pre, &assume, &s[i + 8], 32);
                s[i] = format!("(ite (= {} 4294967295) 0 (+ {} 1))", s[i], s[i]);
                s[self.zf] = eq(&s[i], "0");
                s[self.zk] = "true".into();
            }
            Operation::Decrement(r) => {
                let i = r.index as usize;
                self.known(&pre, &assume, &s[i + 8], 32);
                s[i] = format!("(ite (= {} 0) 4294967295 (- {} 1))", s[i], s[i]);
                s[self.zf] = eq(&s[i], "0");
                s[self.zk] = "true".into();
            }
            Operation::Negate(r) => {
                let i = r.index as usize;
                self.known(&pre, &assume, &s[i + 8], 32);
                s[self.cf] = not(&eq(&s[i], "0"));
                s[i] = format!("(mod (- {}) 4294967296)", s[i]);
                s[self.zf] = eq(&s[i], "0");
                // The frame proof separately limits opaque-error flag observations.
                s[self.ck] = "true".into();
                s[self.zk] = "true".into();
            }
            Operation::Push(o) => {
                let at = state.sp - 4;
                if let Some(&i) = self.arguments.get(&at) {
                    let (v, k) = self.read(pc, o, &s, &pre, &assume)?;
                    s[i] = v;
                    s[i + 1] = k;
                }
                s[4] = num(i64::from(at));
                s[12] = "32".into();
            }
            Operation::Pop(r) => {
                let i = r.index as usize;
                match &state.slots[&state.sp] {
                    Slot::Saved(_) => {
                        s[i] = "0".into();
                        s[i + 8] = "0".into();
                    }
                    Slot::Argument(_) => {
                        let slot = self.arguments[&state.sp];
                        s[i] = s[slot].clone();
                        s[i + 8] = s[slot + 1].clone();
                    }
                }
                s[4] = num(i64::from(state.sp + 4));
                s[12] = "32".into();
            }
            Operation::Leave => {
                let Value::Frame(Some(bp)) = state.registers[5] else {
                    unreachable!()
                };
                s[4] = num(i64::from(bp + 4));
                s[12] = "32".into();
                s[5] = "0".into();
                s[13] = "0".into();
            }
            Operation::Call(_) => {
                let f = self.bound.calls[&pc];
                let arity = match f {
                    Function::Read | Function::Write => 5,
                    Function::StandardHandle => 1,
                    Function::LastError => 0,
                };
                let args: Vec<_> = (0..arity)
                    .map(|n| self.arguments[&(state.sp + 4 * n)])
                    .collect();
                for &i in &args {
                    self.known(&pre, &assume, &s[i + 1], 32);
                }
                let mut ret = self.fresh(false);
                match f {
                    Function::StandardHandle => {
                        let k = if state.arguments(1)?[0] == Value::Constant(0xfffffff6) {
                            1
                        } else {
                            2
                        };
                        assume.push(format!(
                            "(or (= {ret} 0) (= {ret} 4294967295) (= {ret} {k}))"
                        ));
                        s[self.ek] = "false".into();
                    }
                    Function::Read | Function::Write => {
                        let handle = &s[args[0]];
                        let ptr = s[args[1]].clone();
                        let len = &s[args[2]];
                        let kind = if f == Function::Read { 1 } else { 2 };
                        self.check(&pre, &assume, format!("(= {handle} {kind})"));
                        if f == Function::Read {
                            self.check(&pre,&assume,format!("(and (<= 0 {len}) (<= {len} {}) (<= {} {ptr}) (<= (+ {ptr} {len}) {}))",self.cap,num(i64::from(self.base)),num(i64::from(self.base)+i64::from(self.cap))));
                        }
                        let countptr = &s[args[3]];
                        let Value::Frame(Some(at)) = state.arguments(5)?[3] else {
                            unreachable!()
                        };
                        self.check(&pre, &assume, eq(countptr, &num(i64::from(at))));
                        self.check(
                            &pre,
                            &assume,
                            format!(
                                "(or (<= (+ {ptr} {len}) {countptr}) (<= (+ {countptr} 4) {ptr}))"
                            ),
                        );
                        if f == Function::Write {
                            self.check(
                                &pre,
                                &assume,
                                self.coverage(pc, &ptr, len, &s, false, &self.regions),
                            );
                        }
                        let success = self.fresh(true);
                        let n = self.fresh(false);
                        let error = self.fresh(false);
                        assume.push(format!("(and (<= 0 {n}) (<= {n} {len}) (<= 0 {error}) (<= {error} 4294967295))"));
                        let cell = self.cells[&at];
                        s[cell] = format!("(ite {success} {n} 0)");
                        s[cell + 1] = "32".into();
                        if f == Function::Read {
                            self.check(&pre, &assume, eq(&ptr, &num(i64::from(self.base))));
                            s[self.prefix] = format!("(ite {success} {n} 0)");
                        }
                        ret = format!("(ite {success} 1 0)");
                        s[self.error] = error;
                        s[self.ek] = not(&success);
                    }
                    Function::LastError => {
                        self.check(&pre, &assume, s[self.ek].clone());
                        ret = s[self.error].clone();
                    }
                }
                s[0] = ret;
                s[8] = "32".into();
                s[9] = "0".into();
                s[10] = "0".into();
                s[1] = self.fresh(false);
                s[2] = self.fresh(false);
                s[4] = num(i64::from(state.sp + arity * 4));
                s[12] = "32".into();
                s[self.ck] = "false".into();
                s[self.zk] = "false".into();
            }
            Operation::Return => {
                self.known(&pre, &assume, &s[8], 32);
                self.check(
                    &pre,
                    &assume,
                    format!("(and (<= 0 {}) (<= {} 255))", s[0], s[0]),
                );
            }
            _ => {}
        }
        if let Operation::Binary(
            op,
            Operand::Reg(Reg {
                shift: 0,
                index: 4,
                width: 32,
            }),
            Operand::Immediate(n),
        ) = &node.operation
        {
            if matches!(op, Binary::Add | Binary::Sub) {
                let lo = if *op == Binary::Sub {
                    state.sp - *n as i32
                } else {
                    state.sp
                };
                let hi = lo + *n as i32;
                for r in &self.regions {
                    if lo < r.base + r.cap as i32 && r.base < hi {
                        s[r.prefix] = "0".into();
                    }
                }
                for (&at, &i) in &self.cells {
                    if lo < at + 4 && at < hi {
                        s[i + 1] = "0".into();
                    }
                }
            }
        }
        for &next in &node.successors {
            let mut path = assume.clone();
            if let Operation::Branch(cond, target) = node.operation {
                let cf = &s[self.cf];
                let zf = &s[self.zf];
                if !matches!(cond, Condition::Equal | Condition::NotEqual) {
                    self.check(&pre, &assume, s[self.ck].clone());
                }
                if !matches!(cond, Condition::Below | Condition::AboveEqual) {
                    self.check(&pre, &assume, s[self.zk].clone());
                }
                let c = match cond {
                    Condition::Equal => zf.clone(),
                    Condition::NotEqual => not(zf),
                    Condition::Below => cf.clone(),
                    Condition::Above => format!("(and {} {})", not(cf), not(zf)),
                    Condition::BelowEqual => format!("(or {cf} {zf})"),
                    Condition::AboveEqual => not(cf),
                };
                if node.successors.len() > 1 {
                    path.push(if next == target { c } else { not(&c) });
                }
            }
            // Validate the next state's sort/capability invariant before using
            // it as a precondition there. A first failed invariant reaches bad;
            // it cannot disappear merely because the next relation is bounded.
            self.check(&pre, &path, self.domain(next, &s));
            let edge_domain = self.safe.pop().unwrap();
            path.extend(self.safe.iter().cloned());
            path.push(edge_domain);
            writeln!(
                self.rules,
                "(rule (=> (and {pre} {}) {}))",
                and(&path),
                self.atom(next, &s)
            )
            .unwrap();
        }
        Ok(())
    }
}
pub(super) fn encode(bound: &Bound, frames: &Frames) -> Result<Logic, String> {
    let candidates = hints(bound, frames);
    // Weighted loops use assertion-before-assumption induction over the entire
    // CFG. The independent global search need not rediscover nested-loop bounds:
    // candidate preservation itself is part of the mandatory safety certificate.
    // No cutpoint is seeded with an assumed reachable state or skipped edge.
    if candidates.is_empty() || candidates.iter().any(|h| h.weight > 1) {
        return encode_phase(bound, frames, &candidates, false);
    }
    let first = encode_phase(bound, frames, &candidates, true)?;
    let final_ = encode_phase(bound, frames, &candidates, false)?;
    let text = format!("{}\n(reset)\n{}", first.text, final_.text);
    if text.len() > 8_000_000 {
        return Err("stream logic: combined constraint-size budget".into());
    }
    let queries = first.queries + final_.queries;
    if queries > 1024 {
        return Err("stream logic: combined property budget".into());
    }
    Ok(Logic { text, queries })
}
fn encode_phase(
    bound: &Bound,
    frames: &Frames,
    candidates: &[Hint],
    establish: bool,
) -> Result<Logic, String> {
    let mut names: Vec<_> = (0..8)
        .map(|i| format!("r{i}"))
        .chain((0..8).map(|i| format!("k{i}")))
        .collect();
    let mut arguments = BTreeMap::new();
    let mut cells = BTreeMap::new();
    let mut region = None;
    let mut read_count = None;
    for state in frames.states.values() {
        for (&at, slot) in &state.slots {
            if matches!(slot, Slot::Argument(_)) && !arguments.contains_key(&at) {
                arguments.insert(at, names.len());
                names.extend([format!("a{}", -at), format!("ak{}", -at)]);
            }
        }
    }
    for (&pc, &f) in &bound.calls {
        if matches!(f, Function::Read | Function::Write) {
            let state = &frames.states[&pc];
            let args = state.arguments(5)?;
            let Value::Frame(Some(at)) = args[3] else {
                return Err("stream logic: count pointer".into());
            };
            if let std::collections::btree_map::Entry::Vacant(e) = cells.entry(at) {
                e.insert(names.len());
                names.extend([format!("m{}", -at), format!("mk{}", -at)]);
            }
            if f == Function::Read {
                if read_count.is_some_and(|old| old != at) {
                    return Err("stream logic: read epoch count-cell identity changes".into());
                }
                read_count = Some(at);
                let (Value::Frame(Some(base)), Value::Constant(cap)) = (args[1], args[2]) else {
                    return Err("stream logic: read needs fixed owned region/capacity".into());
                };
                if cap == 0 || cap > 4096 || !state.region(base, cap as i32) {
                    return Err("stream logic: read region full range".into());
                }
                if region.is_some_and(|r| r != (base, cap)) {
                    return Err(
                        "stream logic: multiple read regions need independent epochs".into(),
                    );
                }
                region = Some((base, cap));
            }
        }
    }
    // Inventory fixed owned local words, independently of API count cells.
    for (&pc, node) in &bound.graph.nodes {
        let ops: Vec<&Operand> = match &node.operation {
            Operation::Binary(_, a, b) => vec![a, b],
            Operation::Push(o) => vec![o],
            _ => vec![],
        };
        for o in ops {
            if let Operand::Memory(a, 32) = o {
                if a.base.is_some() {
                    let Value::Frame(Some(at)) = frames.states[&pc].address(a)? else {
                        return Err("stream logic: dynamic local word".into());
                    };
                    if at % 4 != 0 || !frames.states[&pc].region(at, 4) {
                        return Err("stream logic: local word ownership".into());
                    }
                    if let std::collections::btree_map::Entry::Vacant(e) = cells.entry(at) {
                        e.insert(names.len());
                        names.extend([format!("m{}", -at), format!("mk{}", -at)]);
                    }
                }
            }
        }
    }
    let (base, cap) = region.ok_or("stream logic: no read region")?;
    for &at in cells.keys() {
        if at < base + cap as i32 && base < at + 4 {
            return Err("stream logic: count cell aliases read region".into());
        }
    }
    let count_at = read_count.ok_or("stream logic: missing read-count owner")?;
    let unique_count = !bound.calls.iter().any(|(&pc,&f)| f==Function::Write && frames.states[&pc].arguments(5).is_ok_and(|a|a[3]==Value::Frame(Some(count_at))))
        && !bound.graph.nodes.iter().any(|(&pc,n)| matches!(&n.operation,Operation::Binary(op,Operand::Memory(a,32),_) if !matches!(op,Binary::Compare|Binary::Test) && frames.states[&pc].address(a)==Ok(Value::Frame(Some(count_at)))));
    // Split owned stack allocations at every word and the fixed input region.
    // These are machine-frame byte regions, not recovered C array declarations.
    // Padding remains owned, but initially unreadable. Access requires the
    // actual instruction's live allocation plus an initialized prefix.
    let mut ranges = BTreeSet::new();
    for state in frames.states.values() {
        for (&lo, &hi) in &state.locals {
            let mut cursor = lo;
            let mut cuts: Vec<_> = cells.keys().map(|&at| (at, at + 4)).collect();
            cuts.push((base, base + cap as i32));
            cuts.sort();
            for (a, b) in cuts {
                if b <= lo || a >= hi {
                    continue;
                }
                if cursor < a {
                    ranges.insert((cursor, a));
                }
                cursor = cursor.max(b);
            }
            if cursor < hi {
                ranges.insert((cursor, hi));
            }
        }
    }
    // Equality is an optimization only after a structural unique-writer proof.
    // Otherwise guest count writes and read initialization have separate state.
    let prefix = if unique_count {
        cells[&count_at]
    } else {
        let i = names.len();
        names.push("read_prefix".into());
        i
    };
    let mut regions = vec![Region { base, cap, prefix }];
    for (lo, hi) in ranges {
        // Overlapping allocation incarnations need a separate lifetime model.
        if regions
            .iter()
            .any(|r| lo < r.base + r.cap as i32 && r.base < hi)
        {
            return Err("stream logic: overlapping byte-region lifetimes".into());
        }
        let prefix = names.len();
        names.push(format!("init{}", -lo));
        regions.push(Region {
            base: lo,
            cap: (hi - lo) as u32,
            prefix,
        });
    }
    if regions.len() > 64 {
        return Err("stream logic: byte-region budget".into());
    }
    let cf = names.len();
    names.push("cf".into());
    let zf = names.len();
    names.push("zf".into());
    let ck = names.len();
    names.push("ck".into());
    let zk = names.len();
    names.push("zk".into());
    let error = names.len();
    names.push("error".into());
    let ek = names.len();
    names.push("ek".into());
    let bools = BTreeSet::from([cf, zf, ck, zk, ek]);
    let mut b = Builder {
        bound,
        frames,
        names,
        bools,
        arguments,
        cells,
        prefix,
        regions,
        cf,
        zf,
        ck,
        zk,
        error,
        ek,
        base,
        cap,
        fresh: 0,
        declarations: String::new(),
        rules: String::new(),
        safe: Vec::new(),
        hints: if establish {
            vec![]
        } else {
            candidates.to_vec()
        },
    };
    for (i, name) in b.names.iter().enumerate() {
        writeln!(
            b.declarations,
            "(declare-var {name} {})",
            if b.bools.contains(&i) { "Bool" } else { "Int" }
        )
        .unwrap();
    }
    let rlimit = match std::env::var("W2L_Z3_RLIMIT") {
        Ok(v) => v
            .parse::<u32>()
            .ok()
            .filter(|v| *v > 0 && *v <= 20_000_000)
            .ok_or("stream solver resource budget must be 1..20000000")?,
        Err(std::env::VarError::NotPresent) => 20_000_000,
        Err(_) => return Err("stream solver budget encoding".into()),
    };
    let mut text = "(set-logic HORN)\n(set-option :fp.engine spacer)\n(set-option :fp.spacer.global false)\n(set-option :fp.spacer.iuc 0)\n(set-option :memory_max_size 512)\n(set-option :timeout 15000)\n(declare-rel bad ())\n".to_string();
    writeln!(text, "(set-option :rlimit {rlimit})").unwrap();
    for &pc in bound.graph.nodes.keys() {
        let fixed = b.fixed(pc);
        let sorts: Vec<_> = (0..b.names.len())
            .filter(|i| !fixed.contains_key(i))
            .map(|i| if b.bools.contains(&i) { "Bool" } else { "Int" })
            .collect();
        writeln!(text, "(declare-rel p{pc} ({}))", sorts.join(" ")).unwrap();
    }
    let mut initial: Vec<_> = (0..b.names.len())
        .map(|i| {
            if b.bools.contains(&i) {
                "false".into()
            } else {
                "0".into()
            }
        })
        .collect();
    initial[12] = "32".into();
    writeln!(b.rules, "(rule {})", b.atom(bound.graph.entry, &initial)).unwrap();
    let entry_pre = b.atom(bound.graph.entry, &b.state(bound.graph.entry));
    b.check(&entry_pre, &[], b.domain(bound.graph.entry, &initial));
    for &pc in bound.graph.nodes.keys() {
        b.node(pc)?;
    }
    text.push_str(&b.declarations);
    // Separate each instruction's safety property while retaining the entire
    // transition system. Every property is mandatory; no fallback or retry.
    let mut properties: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in b.rules.lines() {
        if line.ends_with("bad))") {
            let pc = line
                .split("(p")
                .nth(1)
                .and_then(|x| x.split_whitespace().next())
                .ok_or("stream logic: property binding")?;
            properties
                .entry(pc.to_string())
                .or_default()
                .insert(line.to_string());
        } else {
            writeln!(text, "{line}").unwrap();
        }
    }
    if establish {
        for (i, hint) in candidates.iter().enumerate() {
            let state = b.state(hint.pc);
            writeln!(
                text,
                "(declare-rel hint{i} ())\n(rule (=> (and {} {} (not {})) hint{i}))",
                b.atom(hint.pc, &state),
                b.domain(hint.pc, &state),
                hint.expression(&state)
            )
            .unwrap();
        }
        for i in 0..candidates.len() {
            writeln!(text, "(query hint{i})").unwrap();
        }
        return Ok(Logic {
            text,
            queries: candidates.len(),
        });
    }
    let queries = properties.len();
    if queries == 0 || queries > 1024 {
        return Err("stream logic: property budget".into());
    }
    for (pc, checks) in &properties {
        writeln!(text, "(declare-rel bad{pc} ())").unwrap();
        for check in checks {
            writeln!(text, "{}bad{pc}))", &check[..check.len() - 5]).unwrap();
        }
    }
    for pc in properties.keys() {
        writeln!(text, "(query bad{pc})").unwrap();
    }
    if text.len() > 8_000_000 {
        return Err("stream logic: constraint-size budget".into());
    }
    Ok(Logic { text, queries })
}
