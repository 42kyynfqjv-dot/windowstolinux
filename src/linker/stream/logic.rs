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
struct Builder<'a> {
    bound: &'a Bound,
    frames: &'a Frames,
    names: Vec<String>,
    bools: BTreeSet<usize>,
    arguments: BTreeMap<i32, usize>,
    cells: BTreeMap<i32, usize>,
    prefix: usize,
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
            fixed.insert(i + 8, frame.known[i].to_string());
        }
        for (&at, &i) in &self.arguments {
            fixed.insert(
                i + 1,
                frame.argument_known.get(&at).unwrap_or(&0).to_string(),
            );
        }
        for (&at, &i) in &self.cells {
            fixed.insert(
                i + 1,
                if frame.initialized.contains(&at) {
                    "32"
                } else {
                    "0"
                }
                .into(),
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
        terms.push(format!(
            "(and (<= 0 {}) (<= {} {}))",
            s[self.prefix], s[self.prefix], self.cap
        ));
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
                        format!("(mod {v} 256)")
                    } else {
                        v
                    },
                    s[8 + r.index as usize].clone(),
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
                    self.check(
                        pre,
                        assume,
                        format!(
                            "(and (<= {} {offset}) (< {offset} (+ {} {})))",
                            num(i64::from(self.base)),
                            num(i64::from(self.base)),
                            s[self.prefix]
                        ),
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
                    // Forget upper-bit knowledge in the proof after a partial
                    // write. The emitter still preserves actual upper bits;
                    // subsequent full reads must be re-established by a full write.
                    s[i] = format!("(mod {v} 256)");
                    s[8 + i] = format!("(ite (>= {k} 8) 8 0)");
                } else {
                    s[i] = v;
                    s[8 + i] = k;
                }
            }
            Operand::Memory(a, w) => {
                self.address_known(a, s, pre, assume);
                self.known(pre, assume, &k, *w);
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
                    // Restrict byte writes to current initialized prefix. This
                    // preserves its initialization without inventing new bytes.
                    self.check(
                        pre,
                        assume,
                        format!(
                            "(and (<= {} {offset}) (< {offset} (+ {} {})))",
                            num(i64::from(self.base)),
                            num(i64::from(self.base)),
                            s[self.prefix]
                        ),
                    );
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
                        // Content is deliberately over-approximated. This proof
                        // establishes access/definedness, not the result of the
                        // byte transform. Emission retains exact x86 arithmetic.
                        if !matches!(op, Binary::Compare | Binary::Test) {
                            let byte = self.fresh(false);
                            self.write(
                                pc,
                                dst,
                                (format!("(mod {byte} 256)"), "8".into()),
                                &mut s,
                                &pre,
                                &assume,
                            )?;
                        }
                        s[self.cf] = self.fresh(true);
                        s[self.zf] = self.fresh(true);
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
                            Binary::Test if dst == src => a.clone(),
                            _ => {
                                return Err(
                                    "stream logic: bitwise form needs separate exact encoding"
                                        .into(),
                                )
                            }
                        };
                        let opaque = matches!(dst,Operand::Reg(r) if matches!(state.registers[r.index as usize],Value::Error|Value::ErrorAffine(_, _)));
                        let v = if pointer {
                            raw.clone()
                        } else if opaque || *op == Binary::Sbb {
                            format!("(mod {raw} 4294967296)")
                        } else if width == 32 && matches!(op, Binary::Add | Binary::Sub) {
                            let range = format!("(and (<= 0 {raw}) (< {raw} 4294967296))");
                            self.check(&pre, &assume, range.clone());
                            assume.push(range);
                            raw.clone()
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
                        .map(|i| state.known[i as usize])
                        .min()
                        .unwrap_or(32);
                    let modulus = 1u64 << bits;
                    s[r.index as usize] = format!("(mod {} {modulus})", self.address(a, &s));
                    s[8 + r.index as usize] = bits.to_string();
                }
            }
            Operation::Increment(r) => {
                let i = r.index as usize;
                self.known(&pre, &assume, &s[i + 8], 32);
                let range = format!("(and (<= 0 {}) (< {} 4294967295))", s[i], s[i]);
                self.check(&pre, &assume, range.clone());
                assume.push(range);
                s[i] = format!("(+ {} 1)", s[i]);
                s[self.zf] = eq(&s[i], "0");
                s[self.zk] = "true".into();
            }
            Operation::Decrement(r) => {
                let i = r.index as usize;
                self.known(&pre, &assume, &s[i + 8], 32);
                let ok = format!("(and (< 0 {}) (<= {} 4294967295))", s[i], s[i]);
                self.check(&pre, &assume, ok.clone());
                assume.push(ok);
                s[i] = format!("(- {} 1)", s[i]);
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
                        self.check(&pre,&assume,format!("(and (<= 0 {len}) (<= {len} {}) (<= {} {ptr}) (<= (+ {ptr} {len}) {}))",self.cap,num(i64::from(self.base)),num(i64::from(self.base)+i64::from(self.cap))));
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
                                format!(
                                    "(<= (+ {ptr} {len}) (+ {} {}))",
                                    num(i64::from(self.base)),
                                    s[self.prefix]
                                ),
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
                if lo < self.base + self.cap as i32 && self.base < hi {
                    s[self.prefix] = "0".into();
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
    for (&pc, &f) in &bound.calls {
        if f == Function::Write
            && frames.states[&pc].arguments(5)?[3] == Value::Frame(Some(count_at))
        {
            return Err("stream logic: write aliases read-epoch length cell".into());
        }
    }
    for (&pc, node) in &bound.graph.nodes {
        if let Operation::Binary(op, Operand::Memory(a, 32), _) = &node.operation {
            if !matches!(op, Binary::Compare | Binary::Test)
                && frames.states[&pc].address(a)? == Value::Frame(Some(count_at))
            {
                return Err("stream logic: scalar store aliases read-epoch length cell".into());
            }
        }
    }
    // Structural unique-writer proof: this word is written only by ReadFile,
    // which resets both count and prefix on every success/failure. All byte
    // stores are separately proved confined to the disjoint current prefix.
    let prefix = cells[&count_at];
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
