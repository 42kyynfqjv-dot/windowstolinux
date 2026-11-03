//! Finite typed proof of original descriptor selection, not a replacement for
//! the surrounding EH4/descriptor-lock wrapper. Every admitted instruction is
//! retained for shared native lowering; unavailable effects reject admission.
use super::crt_stream_ir::{Graph, Op, SignedCondition, Target};
use super::graph::{Address, Binary, Condition, Operand, Operation, Reg};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy)]
pub(crate) struct Region<'a> {
    pub bytes: &'a [u8],
    pub origin: u32,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Bindings {
    pub descriptor_number: u32,
    pub descriptor_limit: u32,
    pub descriptor_table: u32,
    pub descriptor_limit_address: u32,
    pub text_writer: u32,
    pub errno_update: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Effect {
    Console,
    Isatty,
    TextWriter,
    ErrnoUpdate,
}
pub(crate) struct Proof {
    pub selector: Graph,
    pub console: Graph,
    pub isatty: Graph,
    pub calls: BTreeMap<u32, Effect>,
    /// Caller depth including the original CALL return word; add callee depth.
    pub call_depths: BTreeMap<u32, u32>,
    pub bindings: Bindings,
    pub temporary_bytes: u32,
    pub states_checked: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Owner {
    Stack,
    Input,
    Context,
    Descriptor,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    Scalar {
        bits: u32,
        known: u32,
        available: u32,
    },
    Pointer(Owner, i32),
    Saved(u8),
    Return,
    InputLength,
}
impl Value {
    fn constant(bits: u32) -> Self {
        Self::Scalar {
            bits,
            known: u32::MAX,
            available: u32::MAX,
        }
    }
    fn unknown() -> Self {
        Self::Scalar {
            bits: 0,
            known: 0,
            available: u32::MAX,
        }
    }
    fn unavailable() -> Self {
        Self::Scalar {
            bits: 0,
            known: 0,
            available: 0,
        }
    }
    fn number(self) -> Option<u32> {
        match self {
            Self::Scalar {
                bits,
                known: u32::MAX,
                available: u32::MAX,
            } => Some(bits),
            _ => None,
        }
    }
    fn scalar(self) -> bool {
        matches!(
            self,
            Self::Scalar {
                available: u32::MAX,
                ..
            } | Self::InputLength
        )
    }
    fn bits(self) -> Result<(u32, u32, u32), String> {
        match self {
            Self::Scalar {
                bits,
                known,
                available,
            } => Ok((bits, known, available)),
            Self::Pointer(..) | Self::InputLength => Ok((0, 0, u32::MAX)),
            Self::Saved(_) => Ok((0, 0, 0)),
            Self::Return => Err("worker protected return bits".into()),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Flags {
    valid: bool,
    z: Option<bool>,
    c: Option<bool>,
    s: Option<bool>,
    o: Option<bool>,
}
impl Flags {
    fn absent() -> Self {
        Self {
            valid: false,
            z: None,
            c: None,
            s: None,
            o: None,
        }
    }
    fn unknown() -> Self {
        Self {
            valid: true,
            ..Self::absent()
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Cell {
    Byte { bits: u8, known: u8, available: u8 },
    Tagged(Value, u8),
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    r: [Value; 8],
    memory: BTreeMap<(Owner, i32), Cell>,
    flags: Flags,
    depth: u32,
}
impl State {
    fn new(args: &[Value]) -> Result<Self, String> {
        let mut s = Self {
            r: std::array::from_fn(|i| Value::Saved(i as u8)),
            memory: BTreeMap::new(),
            flags: Flags::absent(),
            depth: 0,
        };
        s.r[4] = Value::Pointer(Owner::Stack, 0);
        s.store_raw(Owner::Stack, 0, 32, Value::Return)?;
        for (i, v) in args.iter().enumerate() {
            s.store_raw(Owner::Stack, 4 + (i as i32) * 4, 32, *v)?;
        }
        Ok(s)
    }
    fn register(&self, r: Reg) -> Result<Value, String> {
        let v = *self.r.get(r.index as usize).ok_or("worker register")?;
        if r.width == 32 && r.shift == 0 {
            return Ok(v);
        }
        let mask = mask(r.width)?;
        let (b, k, a) = v.bits()?;
        Ok(Value::Scalar {
            bits: (b >> r.shift) & mask,
            known: ((k >> r.shift) & mask) | !mask,
            available: ((a >> r.shift) & mask) | !mask,
        })
    }
    fn set(&mut self, r: Reg, v: Value) -> Result<(), String> {
        if r.index >= 8 {
            return Err("worker register".into());
        }
        if r.width == 32 && r.shift == 0 {
            self.r[r.index as usize] = v;
            return Ok(());
        }
        let mask = mask(r.width)?;
        let (b, k, a) = v.bits()?;
        let (old, known, available) = self.r[r.index as usize].bits()?;
        let field = mask << r.shift;
        self.r[r.index as usize] = Value::Scalar {
            bits: (old & !field) | ((b & mask) << r.shift),
            known: (known & !field) | ((k & mask) << r.shift),
            available: (available & !field) | ((a & mask) << r.shift),
        };
        Ok(())
    }
    fn stack(&self) -> Result<i32, String> {
        match self.r[4] {
            Value::Pointer(Owner::Stack, n) => Ok(n),
            _ => Err("worker ESP provenance".into()),
        }
    }
    fn store_raw(&mut self, owner: Owner, at: i32, width: u8, value: Value) -> Result<(), String> {
        let n = i32::from(width / 8);
        mask(width)?;
        for i in 0..n {
            if let Some(Cell::Tagged(old, offset)) = self.memory.get(&(owner, at + i)) {
                if matches!(old, Value::Saved(_) | Value::Return) {
                    return Err("worker protected saved/return overwrite".into());
                }
                if width != 32 || i != i32::from(*offset) {
                    return Err("worker partial tagged overwrite".into());
                }
            }
        }
        if let Value::Scalar {
            bits,
            known,
            available,
        } = value
        {
            for i in 0..n {
                self.memory.insert(
                    (owner, at + i),
                    Cell::Byte {
                        bits: (bits >> (i * 8)) as u8,
                        known: (known >> (i * 8)) as u8,
                        available: (available >> (i * 8)) as u8,
                    },
                );
            }
        } else {
            if width != 32 {
                return Err("worker partial pointer/control store".into());
            }
            for i in 0..4 {
                self.memory
                    .insert((owner, at + i), Cell::Tagged(value, i as u8));
            }
        }
        Ok(())
    }
    fn load_raw(&self, owner: Owner, at: i32, width: u8) -> Result<Value, String> {
        let n = i32::from(width / 8);
        mask(width)?;
        if let Some(Cell::Tagged(v, 0)) = self.memory.get(&(owner, at)) {
            if width != 32
                || (0..4)
                    .any(|i| self.memory.get(&(owner, at + i)) != Some(&Cell::Tagged(*v, i as u8)))
            {
                return Err("worker partial tagged read".into());
            }
            return Ok(*v);
        }
        let mut bits = 0;
        let mut known = !mask(width)?;
        let mut available = !mask(width)?;
        for i in 0..n {
            match self.memory.get(&(owner, at + i)) {
                Some(Cell::Byte {
                    bits: b,
                    known: k,
                    available: a,
                }) => {
                    bits |= u32::from(*b) << (i * 8);
                    known |= u32::from(*k) << (i * 8);
                    available |= u32::from(*a) << (i * 8);
                }
                _ => return Err("worker uninitialized/partial tagged read".into()),
            }
        }
        Ok(Value::Scalar {
            bits,
            known,
            available,
        })
    }
    fn address(&self, a: &Address, b: &Bindings) -> Result<(Option<Owner>, i64), String> {
        let mut owner = None;
        let mut offset = i64::from(if a.base.is_some() || a.index.is_some() {
            a.displacement as i32
        } else {
            0
        });
        if a.base.is_none() && a.index.is_none() {
            return Ok((None, i64::from(a.displacement)));
        }
        for (reg, scale) in [(a.base, 1u32), (a.index, a.scale)] {
            if let Some(reg) = reg {
                match self.r[reg as usize] {
                    Value::Pointer(o, n) if scale == 1 && owner.is_none() => {
                        owner = Some(o);
                        offset += i64::from(n)
                    }
                    v if v.number().is_some() => {
                        offset += i64::from(v.number().unwrap()) * i64::from(scale)
                    }
                    _ => return Err("worker address owner/index knowledge".into()),
                }
            }
        }
        if owner.is_none() {
            // Absolute descriptor-table SIB uses the original displacement.
            if a.base.is_none() {
                offset = i64::from(a.displacement)
                    + a.index
                        .map(|i| {
                            i64::from(self.r[i as usize].number().unwrap()) * i64::from(a.scale)
                        })
                        .unwrap_or(0);
            }
            if offset < 0 || offset > u32::MAX as i64 {
                return Err("worker absolute address overflow".into());
            }
        }
        let _ = b;
        Ok((owner, offset))
    }
    fn load(&self, a: &Address, width: u8, b: &Bindings) -> Result<Value, String> {
        let (owner, offset) = self.address(a, b)?;
        if owner.is_none() {
            if width == 32 && offset == i64::from(b.descriptor_limit_address) {
                return Ok(Value::constant(b.descriptor_limit));
            }
            if width == 32
                && offset == i64::from(b.descriptor_table) + i64::from(b.descriptor_number >> 6) * 4
            {
                return Ok(Value::Pointer(
                    Owner::Descriptor,
                    -(((b.descriptor_number & 63) * 56) as i32),
                ));
            }
            return Err("worker unbound absolute read".into());
        }
        let at = i32::try_from(offset).map_err(|_| "worker owned offset overflow")?;
        match owner.unwrap() {
            Owner::Descriptor => match (at, width) {
                (40, 8) => Ok(Value::constant(0x81)),
                (41, 8) => Ok(Value::constant(0)),
                _ => Err("worker unsupported descriptor field".into()),
            },
            Owner::Stack => self.load_raw(Owner::Stack, at, width),
            Owner::Context => self.load_raw(Owner::Context, at, width),
            Owner::Input => Err("worker source read requires separately proven text writer".into()),
        }
    }
    fn store(&mut self, a: &Address, width: u8, value: Value, b: &Bindings) -> Result<(), String> {
        let (owner, offset) = self.address(a, b)?;
        let at = i32::try_from(offset).map_err(|_| "worker store offset")?;
        match owner {
            Some(Owner::Stack) if (-256..0).contains(&at) && at + i32::from(width / 8) <= 0 => {
                self.store_raw(Owner::Stack, at, width, value)
            }
            Some(Owner::Context)
                if matches!((at, width), (0x18, 32) | (0x1c, 8) | (0x20, 32) | (0x24, 8))
                    && value.scalar() =>
            {
                self.store_raw(Owner::Context, at, width, value)
            }
            _ => Err("worker store ownership/protected boundary".into()),
        }
    }
    fn read(&self, o: &Operand, b: &Bindings) -> Result<Value, String> {
        match o {
            Operand::Reg(r) => self.register(*r),
            Operand::Immediate(n) => Ok(Value::constant(*n)),
            Operand::Memory(a, w) => self.load(a, *w, b),
        }
    }
    fn write(&mut self, o: &Operand, v: Value, b: &Bindings) -> Result<(), String> {
        match o {
            Operand::Reg(r) => self.set(*r, v),
            Operand::Memory(a, w) => self.store(a, *w, v, b),
            _ => Err("worker nonwritable operand".into()),
        }
    }
    fn push(&mut self, v: Value) -> Result<(), String> {
        let sp = self
            .stack()?
            .checked_sub(4)
            .ok_or("worker stack overflow")?;
        if !(-256..0).contains(&sp) {
            return Err("worker stack cap/protected push".into());
        }
        self.store_raw(Owner::Stack, sp, 32, v)?;
        self.r[4] = Value::Pointer(Owner::Stack, sp);
        self.depth = self.depth.max((-sp) as u32);
        Ok(())
    }
    fn pop(&mut self) -> Result<Value, String> {
        let sp = self.stack()?;
        if sp >= 0 {
            return Err("worker pop protected caller boundary".into());
        }
        let v = self.load_raw(Owner::Stack, sp, 32)?;
        for i in 0..4 {
            self.memory.remove(&(Owner::Stack, sp + i));
        }
        self.r[4] = Value::Pointer(Owner::Stack, sp + 4);
        Ok(v)
    }
    fn argument(&self, index: i32) -> Result<Value, String> {
        self.load_raw(Owner::Stack, self.stack()? + index * 4, 32)
    }
    fn clobber(&mut self, result: Value) {
        self.r[0] = result;
        self.r[1] = Value::unavailable();
        self.r[2] = Value::unavailable();
        self.flags = Flags::absent();
    }
}
fn mask(width: u8) -> Result<u32, String> {
    match width {
        8 => Ok(255),
        16 => Ok(65535),
        32 => Ok(u32::MAX),
        _ => Err("worker operand width".into()),
    }
}
fn width(o: &Operand) -> u8 {
    match o {
        Operand::Reg(r) => r.width,
        Operand::Memory(_, w) => *w,
        _ => 32,
    }
}
fn binary(s: &mut State, op: Binary, a: Value, b: Value, w: u8) -> Result<Value, String> {
    if op == Binary::Move {
        return Ok(b);
    }
    if w == 32 && matches!(op, Binary::Add | Binary::Sub) {
        if let (Value::Pointer(o, n), Some(v)) = (a, b.number()) {
            let delta = if op == Binary::Add {
                i64::from(v as i32)
            } else {
                -i64::from(v as i32)
            };
            s.flags = Flags::unknown();
            return Ok(Value::Pointer(
                o,
                i32::try_from(i64::from(n) + delta).map_err(|_| "worker pointer overflow")?,
            ));
        }
    }
    if matches!(op, Binary::Test | Binary::Compare) && w == 32 {
        if let Value::Pointer(_, _) = a {
            if b.number() == Some(0) {
                if op == Binary::Test {
                    s.flags = Flags {
                        valid: true,
                        z: Some(true),
                        c: Some(false),
                        s: Some(false),
                        o: Some(false),
                    };
                    return Ok(Value::constant(0));
                }
                s.flags = Flags {
                    valid: true,
                    z: Some(false),
                    c: Some(false),
                    s: None,
                    o: Some(false),
                };
                return Ok(Value::unknown());
            }
            if op == Binary::Test && a == b {
                s.flags = Flags {
                    valid: true,
                    z: Some(false),
                    c: Some(false),
                    s: None,
                    o: Some(false),
                };
                return Ok(Value::unknown());
            }
        }
    }
    if (matches!(a, Value::Scalar { .. } | Value::Saved(_)) && !a.scalar()) || !b.scalar() {
        return Err("worker unavailable machine bits".into());
    }
    if op == Binary::Or
        && b.number()
            .is_some_and(|v| v & mask(w).unwrap() == mask(w).unwrap())
    {
        let m = mask(w)?;
        s.flags = Flags {
            valid: true,
            z: Some(false),
            c: Some(false),
            s: Some(true),
            o: Some(false),
        };
        return Ok(Value::constant(m));
    }
    if matches!(op, Binary::And | Binary::Test) && b.number() == Some(0) {
        s.flags = Flags {
            valid: true,
            z: Some(true),
            c: Some(false),
            s: Some(false),
            o: Some(false),
        };
        return Ok(Value::constant(0));
    }
    if !a.scalar() || !b.scalar() {
        return Err("worker scalar/pointer arithmetic".into());
    }
    let m = mask(w)?;
    let sign = 1u32 << (w - 1);
    if let (Some(x), Some(y)) = (a.number(), b.number()) {
        let x = x & m;
        let y = y & m;
        let (v, c, o) = match op {
            Binary::Add => {
                let n = u64::from(x) + u64::from(y);
                let v = n as u32 & m;
                (v, n > u64::from(m), (!(x ^ y) & (x ^ v) & sign) != 0)
            }
            Binary::Sub | Binary::Compare => {
                let v = x.wrapping_sub(y) & m;
                (v, x < y, ((x ^ y) & (x ^ v) & sign) != 0)
            }
            Binary::And | Binary::Test => (x & y, false, false),
            Binary::Or => (x | y, false, false),
            Binary::Xor => (x ^ y, false, false),
            _ => return Err("worker arithmetic outside contract".into()),
        };
        s.flags = Flags {
            valid: true,
            z: Some(v == 0),
            c: Some(c),
            s: Some(v & sign != 0),
            o: Some(o),
        };
        Ok(Value::constant(v))
    } else {
        s.flags = Flags::unknown();
        Ok(Value::unknown())
    }
}
fn condition(f: Flags, c: Condition) -> Result<Option<bool>, String> {
    if !f.valid {
        return Err("worker branch uses call-clobbered/unknown flags".into());
    }
    Ok(match c {
        Condition::Equal => f.z,
        Condition::NotEqual => f.z.map(|x| !x),
        Condition::Below => f.c,
        Condition::AboveEqual => f.c.map(|x| !x),
        Condition::Above => f.c.zip(f.z).map(|(c, z)| !c && !z),
        Condition::BelowEqual => f.c.zip(f.z).map(|(c, z)| c || z),
    })
}
fn signed(f: Flags, c: SignedCondition) -> Result<Option<bool>, String> {
    if !f.valid {
        return Err("worker signed branch uninitialized flags".into());
    }
    Ok(match c {
        SignedCondition::Sign => f.s,
        SignedCondition::NotSign => f.s.map(|s| !s),
        SignedCondition::Less => f.s.zip(f.o).map(|(s, o)| s != o),
        SignedCondition::GreaterEqual => f.s.zip(f.o).map(|(s, o)| s == o),
        SignedCondition::LessEqual => f.z.zip(f.s.zip(f.o)).map(|(z, (s, o))| z || s != o),
        SignedCondition::Greater => f.z.zip(f.s.zip(f.o)).map(|(z, (s, o))| !z && s == o),
    })
}
#[derive(Clone, Copy)]
enum Kind {
    Isatty,
    Console,
    Selector,
}
struct Checked {
    graph: Graph,
    calls: BTreeMap<u32, Effect>,
    call_depths: BTreeMap<u32, u32>,
    depth: u32,
    states: usize,
    returns: Vec<Value>,
}
fn analyze(
    graph: Graph,
    b: &Bindings,
    kind: Kind,
    console: u32,
    isatty: u32,
) -> Result<Checked, String> {
    let args = match kind {
        Kind::Isatty => vec![Value::constant(b.descriptor_number)],
        Kind::Console => vec![
            Value::constant(b.descriptor_number),
            Value::Pointer(Owner::Context, 0),
        ],
        Kind::Selector => vec![
            Value::constant(b.descriptor_number),
            Value::Pointer(Owner::Input, 0),
            Value::InputLength,
            Value::Pointer(Owner::Context, 0),
        ],
    };
    let mut todo = vec![(graph.origin, State::new(&args)?, BTreeSet::new())];
    let mut reached = BTreeSet::new();
    let mut calls = BTreeMap::new();
    let mut call_depths = BTreeMap::new();
    let mut edges: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    let mut returns = vec![];
    let mut states = 0;
    let mut depth = 0;
    while let Some((pc, mut s, mut path)) = todo.pop() {
        states += 1;
        if states > 16384 {
            return Err("worker finite proof state cap".into());
        }
        if !path.insert(pc) {
            return Err("worker unproved control cycle".into());
        }
        let node = graph.nodes.get(&pc).ok_or("worker instruction boundary")?;
        reached.insert(pc);
        let next = pc + node.length;
        let mut successors = vec![next];
        match &node.op {
            Op::Ordinary(Operation::Binary(op, dst, src)) => {
                let v = if *op == Binary::Move {
                    s.read(src, b)?
                } else if *op == Binary::Xor && dst == src {
                    s.flags = Flags {
                        valid: true,
                        z: Some(true),
                        c: Some(false),
                        s: Some(false),
                        o: Some(false),
                    };
                    Value::constant(0)
                } else {
                    let a = s.read(dst, b)?;
                    let v = s.read(src, b)?;
                    binary(&mut s, *op, a, v, width(dst))
                        .map_err(|e| format!("{e} at {pc:#x}: {a:?} {op:?} {v:?}"))?
                };
                if !matches!(op, Binary::Compare | Binary::Test) {
                    if matches!(
                        dst,
                        Operand::Reg(Reg {
                            index: 4,
                            width: 32,
                            shift: 0
                        })
                    ) {
                        if let Value::Pointer(Owner::Stack, n) = v {
                            if !(-256..=0).contains(&n) {
                                return Err("worker ESP allocation/cleanup bound".into());
                            }
                            if *op == Binary::Add {
                                let Operand::Immediate(bytes) = src else {
                                    return Err("worker dynamic cleanup".into());
                                };
                                if bytes % 4 != 0 || *bytes > 256 {
                                    return Err("worker cleanup word bounds".into());
                                }
                                let start = s.stack()?;
                                for offset in (0..*bytes).step_by(4) {
                                    let value =
                                        s.load_raw(Owner::Stack, start + offset as i32, 32)?;
                                    if matches!(value, Value::Saved(_) | Value::Return) {
                                        return Err("worker cleanup crosses protected word".into());
                                    }
                                }
                                for offset in 0..*bytes {
                                    s.memory.remove(&(Owner::Stack, start + offset as i32));
                                }
                            }
                            s.depth = s.depth.max((-n) as u32);
                        } else {
                            return Err("worker ESP scalarization".into());
                        }
                    }
                    s.write(dst, v, b)?;
                }
            }
            Op::Ordinary(Operation::Address(r, a)) => {
                let (o, n) = s.address(a, b)?;
                let o = o.ok_or("worker LEA unbound absolute")?;
                s.set(
                    *r,
                    Value::Pointer(o, i32::try_from(n).map_err(|_| "worker LEA overflow")?),
                )?;
            }
            Op::Ordinary(Operation::Push(o)) => {
                let v = s.read(o, b)?;
                s.push(v)?;
            }
            Op::Ordinary(Operation::Pop(r)) => {
                let v = s.pop()?;
                s.set(*r, v)?;
            }
            Op::Ordinary(Operation::Leave) => {
                s.r[4] = s.r[5];
                s.r[5] = s.pop()?;
            }
            Op::Ordinary(Operation::Nop) => {}
            Op::Ordinary(Operation::Return) => {
                if s.stack()? != 0
                    || s.load_raw(Owner::Stack, 0, 32)? != Value::Return
                    || [3, 5, 6, 7]
                        .iter()
                        .any(|i| s.r[*i] != Value::Saved(*i as u8))
                {
                    return Err("worker original return/nonvolatile ownership".into());
                }
                returns.push(s.r[0]);
                successors.clear();
            }
            Op::Ordinary(Operation::Jump(t)) => successors = vec![*t],
            Op::Ordinary(Operation::Branch(c, t)) => {
                successors = match condition(s.flags, *c)? {
                    Some(true) => vec![*t],
                    Some(false) => vec![next],
                    None => vec![next, *t],
                }
            }
            Op::SignedBranch {
                condition: c,
                target: t,
            } => {
                successors = match signed(s.flags, *c)? {
                    Some(true) => vec![*t],
                    Some(false) => vec![next],
                    None => vec![next, *t],
                }
            }
            Op::ArithmeticShift { dst, count }
            | Op::Ordinary(Operation::Shift {
                dst,
                count,
                left: false,
            }) => {
                let v = s.register(*dst)?;
                if !v.scalar() {
                    return Err("worker shift pointer".into());
                }
                let arithmetic = matches!(node.op, Op::ArithmeticShift { .. });
                let v = v
                    .number()
                    .map(|v| {
                        if arithmetic {
                            ((v as i32) >> (*count & 31)) as u32
                        } else {
                            v >> (*count & 31)
                        }
                    })
                    .map(Value::constant)
                    .unwrap_or_else(Value::unknown);
                s.set(*dst, v)?;
                // Multi-bit shifts leave OF undefined; this narrow proof does
                // not promote undefined flags to symbolic defined values.
                if *count & 31 != 0 {
                    s.flags = Flags::absent();
                }
            }
            Op::Multiply {
                dst,
                source,
                factor,
            } => {
                let v = s.read(source, b)?;
                if !v.scalar() {
                    return Err("worker IMUL pointer".into());
                }
                s.set(
                    *dst,
                    v.number()
                        .map(|n| Value::constant(n.wrapping_mul(*factor)))
                        .unwrap_or_else(Value::unknown),
                )?;
                s.flags = Flags::absent();
            }
            Op::Ordinary(Operation::ZeroExtend(r, o)) | Op::SignExtend { dst: r, source: o } => {
                let v = s.read(o, b)?;
                if !v.scalar() {
                    return Err("worker extension of unavailable bits".into());
                }
                let signed = matches!(node.op, Op::SignExtend { .. });
                let w = width(o);
                s.set(
                    *r,
                    v.number()
                        .map(|n| {
                            Value::constant(if signed {
                                (((n << (32 - w)) as i32) >> (32 - w)) as u32
                            } else {
                                n
                            })
                        })
                        .unwrap_or_else(Value::unknown),
                )?;
            }
            Op::Ordinary(Operation::Not(r)) => {
                let v = s.register(*r)?;
                if !v.scalar() {
                    return Err("worker NOT pointer".into());
                }
                s.set(
                    *r,
                    v.number()
                        .map(|v| Value::constant(!v))
                        .unwrap_or_else(Value::unknown),
                )?;
            }
            Op::Ordinary(Operation::Set(c, r)) => {
                let v = condition(s.flags, *c)?
                    .map(|n| Value::constant(u32::from(n)))
                    .unwrap_or_else(Value::unknown);
                s.set(*r, v)?;
            }
            Op::CopyString { width: 32 } => {
                let (so, sa) = match s.r[6] {
                    Value::Pointer(o, a) => (o, a),
                    _ => return Err("worker MOVSD source".into()),
                };
                let (doo, da) = match s.r[7] {
                    Value::Pointer(o, a) => (o, a),
                    _ => return Err("worker MOVSD destination".into()),
                };
                if so != Owner::Stack || doo != Owner::Stack || sa >= 0 || da >= 0 {
                    return Err("worker MOVSD frame ownership".into());
                }
                let v = s.load_raw(so, sa, 32)?;
                s.store_raw(doo, da, 32, v)?;
                s.r[6] = Value::Pointer(so, sa + 4);
                s.r[7] = Value::Pointer(doo, da + 4);
            }
            Op::Call(Target::Direct(target)) => {
                let effect = if *target == console {
                    Effect::Console
                } else if *target == isatty {
                    Effect::Isatty
                } else if *target == b.text_writer {
                    Effect::TextWriter
                } else if *target == b.errno_update {
                    Effect::ErrnoUpdate
                } else {
                    return Err(format!(
                        "worker reachable unproved call {target:#x} at {pc:#x}"
                    ));
                };
                if !matches!(
                    (kind, effect),
                    (Kind::Console, Effect::Isatty)
                        | (
                            Kind::Selector,
                            Effect::Console | Effect::TextWriter | Effect::ErrnoUpdate
                        )
                ) {
                    return Err("worker circular/unavailable call contract".into());
                }
                let call_depth = u32::try_from(-s.stack()?)
                    .map_err(|_| "worker call depth")?
                    .checked_add(4)
                    .ok_or("worker call depth overflow")?;
                call_depths
                    .entry(pc)
                    .and_modify(|old: &mut u32| *old = (*old).max(call_depth))
                    .or_insert(call_depth);
                s.depth = s.depth.max(call_depth);
                match effect {
                    Effect::Console => {
                        if s.argument(0)? != Value::constant(b.descriptor_number)
                            || s.argument(1)? != Value::Pointer(Owner::Context, 0)
                        {
                            return Err("worker console arguments".into());
                        }
                        s.clobber(Value::Scalar {
                            bits: 0,
                            known: 255,
                            available: 255,
                        });
                    }
                    Effect::Isatty => {
                        if s.argument(0)? != Value::constant(b.descriptor_number) {
                            return Err("worker isatty argument".into());
                        }
                        s.clobber(Value::constant(0));
                    }
                    Effect::TextWriter => {
                        let result = s.argument(0)?;
                        if s.argument(1)? != Value::constant(b.descriptor_number)
                            || s.argument(2)? != Value::Pointer(Owner::Input, 0)
                            || s.argument(3)? != Value::InputLength
                        {
                            return Err("worker text writer argument provenance".into());
                        }
                        let Value::Pointer(Owner::Stack, at) = result else {
                            return Err("worker writer result owner".into());
                        };
                        if at < -256 || at + 12 > 0 {
                            return Err("worker complete result range".into());
                        }
                        for offset in [0, 4, 8] {
                            s.store_raw(Owner::Stack, at + offset, 32, Value::unknown())?;
                        }
                        s.clobber(result);
                    }
                    Effect::ErrnoUpdate => {
                        if !s.argument(0)?.scalar()
                            || s.argument(1)? != Value::Pointer(Owner::Context, 0)
                        {
                            return Err("worker errno context arguments".into());
                        }
                        for (at, w) in [(0x18, 32), (0x1c, 8), (0x20, 32), (0x24, 8)] {
                            s.store_raw(Owner::Context, at, w, Value::unknown())?;
                        }
                        s.clobber(Value::unknown());
                    }
                }
                if calls
                    .insert(pc, effect)
                    .is_some_and(|previous| previous != effect)
                {
                    return Err("worker call effect join".into());
                }
            }
            other => {
                return Err(format!(
                    "worker unsupported reachable operation {other:?} at {pc:#x}"
                ))
            }
        }
        depth = depth.max(s.depth);
        for target in successors {
            edges.entry(pc).or_default().insert(target);
            todo.push((target, s.clone(), path.clone()));
        }
    }
    if returns.is_empty() {
        return Err("worker no original return".into());
    }
    // Remove only statically impossible edges. Original conditional instruction
    // remains emitted; an impossible runtime branch hits the certified boundary.
    let mut admitted = graph;
    admitted.nodes.retain(|pc, _| reached.contains(pc));
    for (pc, node) in &mut admitted.nodes {
        node.successors = edges.remove(pc).unwrap_or_default().into_iter().collect();
    }
    Ok(Checked {
        graph: admitted,
        calls,
        call_depths,
        depth,
        states,
        returns,
    })
}
impl Proof {
    pub fn prove(
        selector: Region<'_>,
        console: Region<'_>,
        isatty: Region<'_>,
        bindings: Bindings,
    ) -> Result<Self, String> {
        if bindings.descriptor_number >= bindings.descriptor_limit
            || bindings.descriptor_limit > 8192
            || bindings.descriptor_number > i32::MAX as u32
            || !bindings.descriptor_table.is_multiple_of(4)
            || !bindings.descriptor_limit_address.is_multiple_of(4)
            || bindings.text_writer == 0
            || bindings.errno_update == 0
        {
            return Err("worker descriptor identity/range binding".into());
        }
        let ranges = [selector, console, isatty];
        for (i, a) in ranges.iter().enumerate() {
            let end = a
                .origin
                .checked_add(u32::try_from(a.bytes.len()).map_err(|_| "worker code length")?)
                .ok_or("worker code extent")?;
            if a.origin == 0 || a.origin >= end {
                return Err("worker code extent".into());
            }
            for other in ranges.iter().skip(i + 1) {
                let other_end = other
                    .origin
                    .checked_add(other.bytes.len() as u32)
                    .ok_or("worker code extent")?;
                if a.origin < other_end && other.origin < end {
                    return Err("worker code regions alias".into());
                }
            }
            for data in [
                bindings
                    .descriptor_table
                    .checked_add((bindings.descriptor_number >> 6) * 4)
                    .ok_or("worker table overflow")?,
                bindings.descriptor_limit_address,
            ] {
                if data.checked_add(4).is_none() || data < end && a.origin < data + 4 {
                    return Err("worker data/code alias".into());
                }
            }
        }
        let table_cell = bindings
            .descriptor_table
            .checked_add((bindings.descriptor_number >> 6) * 4)
            .ok_or("worker descriptor table extent")?;
        if table_cell == bindings.descriptor_limit_address
            || ranges
                .iter()
                .any(|r| r.origin == bindings.text_writer || r.origin == bindings.errno_update)
            || bindings.text_writer == bindings.errno_update
        {
            return Err("worker role/call binding alias".into());
        }
        let tty = analyze(
            Graph::decode(isatty.bytes, isatty.origin)?,
            &bindings,
            Kind::Isatty,
            console.origin,
            isatty.origin,
        )?;
        if tty.returns.iter().any(|v| v.number() != Some(0)) {
            return Err("worker actual isatty does not establish nondevice result".into());
        }
        let con = analyze(
            Graph::decode(console.bytes, console.origin)?,
            &bindings,
            Kind::Console,
            console.origin,
            isatty.origin,
        )?;
        if con.returns.iter().any(|v| {
            v.bits()
                .map(|(n, k, a)| a & 255 != 255 || k & 255 != 255 || n & 255 != 0)
                .unwrap_or(true)
        }) {
            return Err("worker actual console selector does not establish false AL".into());
        }
        let sel = analyze(
            Graph::decode(selector.bytes, selector.origin)?,
            &bindings,
            Kind::Selector,
            console.origin,
            isatty.origin,
        )?;
        if sel.returns.iter().any(|v| !v.scalar()) {
            return Err("worker scalar result provenance".into());
        }
        let mut call_depths = tty.call_depths;
        call_depths.extend(con.call_depths);
        call_depths.extend(sel.call_depths);
        let mut calls = tty.calls;
        calls.extend(con.calls);
        calls.extend(sel.calls);
        Ok(Self {
            temporary_bytes: tty.depth.max(con.depth).max(sel.depth),
            states_checked: tty.states + con.states + sel.states,
            selector: sel.graph,
            console: con.graph,
            isatty: tty.graph,
            calls,
            call_depths,
            bindings,
        })
    }
    pub fn emit(
        &self,
        prefix: &str,
        mut effect: impl FnMut(Effect, u32) -> Result<String, String>,
    ) -> Result<String, String> {
        let roles = BTreeMap::from([
            (
                self.bindings.descriptor_table,
                "CrtRegionKind::Module".to_owned(),
            ),
            (
                self.bindings.descriptor_limit_address,
                "CrtRegionKind::Module".to_owned(),
            ),
        ]);
        let mut output = String::new();
        for (suffix, graph) in [
            ("isatty", &self.isatty),
            ("console", &self.console),
            ("selector", &self.selector),
        ] {
            output += &super::crt_stream_emit::emit_graph(
                graph,
                &format!("{prefix}_{suffix}"),
                |pc, _| {
                    effect(
                        *self.calls.get(&pc).ok_or("worker missing certified call")?,
                        pc,
                    )
                },
                &roles,
                2048,
            )?;
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bindings() -> Bindings {
        Bindings {
            descriptor_number: 7,
            descriptor_limit: 64,
            descriptor_table: 0x8000,
            descriptor_limit_address: 0x9000,
            text_writer: 0x6000,
            errno_update: 0x7000,
        }
    }
    fn graph(bytes: &[u8]) -> Graph {
        Graph::decode(bytes, 0x1000).unwrap()
    }
    #[test]
    fn unknown_initialized_count_explores_both_original_return_paths() {
        // count is the independent input, not a sampled value or decoder result.
        let bytes = [
            0x8b, 0x44, 0x24, 0x0c, 0x85, 0xc0, 0x74, 6, 0xb8, 1, 0, 0, 0, 0xc3, 0x33, 0xc0, 0xc3,
        ];
        let proof = analyze(graph(&bytes), &bindings(), Kind::Selector, 0x4000, 0x5000).unwrap();
        assert_eq!(proof.returns.len(), 2);
        assert!(
            proof.returns.contains(&Value::constant(0))
                && proof.returns.contains(&Value::constant(1))
        );
        assert_eq!(proof.graph.nodes.len(), 7);
    }
    #[test]
    fn byte_descriptor_access_keeps_table_pointer_and_index_ownership() {
        // fd7 -> index392; table points to record-block base, flags at+392+40.
        let bytes = [
            0x8b, 0x44, 0x24, 4, 0x83, 0xe0, 63, 0x6b, 0xc0, 56, 0x8b, 0x0d, 0, 0x80, 0, 0, 0x0f,
            0xb6, 0x44, 0x01, 40, 0x83, 0xe0, 64, 0xc3,
        ];
        let proof = analyze(graph(&bytes), &bindings(), Kind::Isatty, 0x4000, 0x5000).unwrap();
        assert_eq!(proof.returns, vec![Value::constant(0)]);
        let mut changed = bytes;
        changed[20] = 41;
        // Encoding is independently initialized0; a different field still
        // cannot manufacture a pointer or derive a different device flag.
        assert_eq!(
            analyze(graph(&changed), &bindings(), Kind::Isatty, 0x4000, 0x5000)
                .unwrap()
                .returns,
            vec![Value::constant(0)]
        );
        changed[20] = 39;
        assert!(analyze(graph(&changed), &bindings(), Kind::Isatty, 0x4000, 0x5000).is_err());
    }
    #[test]
    fn uninitialized_reads_protected_stores_and_cycles_reject() {
        for bytes in [
            &[0x83, 0xec, 4, 0x8b, 0x04, 0x24, 0x83, 0xc4, 4, 0xc3][..],
            &[0x89, 0x04, 0x24, 0xc3],
            &[0xeb, 0xfe],
        ] {
            assert!(analyze(graph(bytes), &bindings(), Kind::Selector, 0x4000, 0x5000).is_err());
        }
    }
    #[test]
    fn source_length_identity_is_not_an_arbitrary_initialized_scalar() {
        let mut s = State::new(&[
            Value::constant(7),
            Value::Pointer(Owner::Input, 0),
            Value::InputLength,
            Value::Pointer(Owner::Context, 0),
        ])
        .unwrap();
        let original = s.load_raw(Owner::Stack, 12, 32).unwrap();
        assert_eq!(original, Value::InputLength);
        let changed = binary(&mut s, Binary::Add, original, Value::constant(1), 32).unwrap();
        assert_ne!(changed, Value::InputLength);
        assert!(s
            .store_raw(Owner::Stack, 13, 8, Value::constant(0))
            .is_err());
    }
    #[test]
    fn circular_call_summary_cannot_bootstrap_false_proof() {
        // isatty has no admitted external effects in this valid-fd domain.
        let bytes = [0xe8, 0xfb, 0x2f, 0, 0, 0x33, 0xc0, 0xc3];
        assert!(analyze(graph(&bytes), &bindings(), Kind::Isatty, 0x4000, 0x5000).is_err());
    }
    #[test]
    fn pointer_test_zero_and_dead_pointer_or_are_exact_integer_effects() {
        let mut s = State::new(&[]).unwrap();
        assert_eq!(
            binary(
                &mut s,
                Binary::Test,
                Value::Pointer(Owner::Input, 0),
                Value::constant(0),
                32
            )
            .unwrap(),
            Value::constant(0)
        );
        assert_eq!(s.flags.z, Some(true));
        assert_eq!(
            binary(
                &mut s,
                Binary::Or,
                Value::Pointer(Owner::Descriptor, 0),
                Value::constant(u32::MAX),
                32
            )
            .unwrap(),
            Value::constant(u32::MAX)
        );
        assert_eq!(
            (s.flags.z, s.flags.s, s.flags.c, s.flags.o),
            (Some(false), Some(true), Some(false), Some(false))
        );
    }
}
