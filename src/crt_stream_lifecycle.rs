//! Operand-derived initialization/teardown proof for an owned CRT stream table.
//!
//! This certificate does not close the called CRT helpers. Every executed CALL
//! remains an explicit effect requirement; its return/exception/error contract
//! must be supplied by the enclosing compiler before native emission.
use super::crt_stream_ir::{Graph, Op, SignedCondition, Target};
use super::graph::{Address, Binary, Condition, Operand, Operation, Reg};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Initialize,
    Teardown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Effect {
    AllocateTable,
    FreeAllocation,
    ConstructLock,
    FlushAll,
    CloseAdditional,
    FreeFileBuffer,
    DeleteLock,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Descriptor {
    Valid,
    Null,
    Invalid,
    Detached,
}
#[derive(Clone, Debug)]
pub(crate) struct Layout {
    pub count: u32,
    pub table: u32,
    pub files: u32,
    pub descriptors: u32,
    pub file_stride: u32,
    pub file_count: u32,
    pub lock_offset: u32,
    pub descriptor_stride: u32,
    pub handle_offset: u32,
    pub file_descriptor_offset: u32,
    /// This is a separately checked initial-state requirement, not inferred
    /// from sampled runtime memory. Different counts produce different proofs.
    pub initial_capacity: u32,
    pub handles: Vec<Descriptor>,
}
#[derive(Clone, Debug)]
pub(crate) struct Bindings {
    pub layout: Layout,
    pub calls: BTreeMap<Target, Effect>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Argument {
    Scalar(u32),
    File { index: u32, offset: u32 },
    Table { words: u32 },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CallRequirement {
    pub pc: u32,
    pub target: Target,
    pub effect: Effect,
    pub arguments: Vec<Argument>,
    pub entry_depth: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReturnRequirement {
    pub pc: u32,
    pub result: Option<u32>,
    pub initialized: bool,
}
pub(crate) struct Proof {
    pub graph: Graph,
    pub bindings: Bindings,
    pub kind: Kind,
    pub calls: Vec<CallRequirement>,
    pub returns: Vec<ReturnRequirement>,
    pub temporary_bytes: u32,
    pub step_bound: u32,
}
impl Proof {
    /// Lower every original instruction through the shared native emitter.
    /// The lexical caller provides `rt`, `cpu`, and the exclusive `init` token.
    /// Each callback must discharge its supplied call requirements; this method
    /// does not substitute allocator/lock/flush/close semantics or attest startup.
    pub(crate) fn emit_body(
        &self,
        mut effect: impl FnMut(u32, Target, Effect, &[&CallRequirement]) -> Result<String, String>,
    ) -> Result<String, String> {
        let layout = &self.bindings.layout;
        let mut graph = self.graph.clone();
        let mut roles = BTreeMap::from([
            (layout.count, "CrtRegionKind::Module".to_string()),
            (layout.table, "CrtRegionKind::Module".to_string()),
            (layout.descriptors, "CrtRegionKind::Module".to_string()),
        ]);
        // An immediate is not authority by itself. This exact original MOV is
        // lowered to an address operation only after the operand-derived proof
        // bound its full region. LEA and MOV both preserve arithmetic flags.
        for node in graph.nodes.values_mut() {
            if let Op::Ordinary(Operation::Binary(
                Binary::Move,
                Operand::Reg(dst),
                Operand::Immediate(address),
            )) = &node.op
            {
                if let Some(Value::Address(region, offset)) = layout.absolute(*address) {
                    let role = match region {
                        Region::Files
                            if offset >= 0
                                && (offset as u32) < layout.file_count * layout.file_stride =>
                        {
                            "CrtRegionKind::File"
                        }
                        Region::Count | Region::Table | Region::DescriptorTable => {
                            "CrtRegionKind::Module"
                        }
                        _ => return Err("CRT lifecycle immediate address extent".into()),
                    };
                    roles.insert(*address, role.into());
                    node.op = Op::Ordinary(Operation::Address(
                        *dst,
                        Address {
                            base: None,
                            index: None,
                            scale: 1,
                            displacement: *address,
                        },
                    ));
                }
            }
        }
        let mut source = self.entry_checks();
        source.push_str(&super::crt_stream_emit::emit_body(
            &graph,
            |pc, target| {
                let requirements: Vec<_> = self
                    .calls
                    .iter()
                    .filter(|c| c.pc == pc && c.target == target)
                    .collect();
                let kind = *self
                    .bindings
                    .calls
                    .get(&target)
                    .ok_or("CRT lifecycle emission call binding")?;
                if requirements.is_empty() {
                    return Err("CRT lifecycle unreachable call has no effect certificate".into());
                }
                effect(pc, target, kind, &requirements)
            },
            &roles,
            self.step_bound,
        )?);
        Ok(source)
    }
    fn entry_checks(&self) -> String {
        let l = &self.bindings.layout;
        let count = if self.kind == Kind::Initialize {
            l.initial_capacity
        } else {
            l.capacity()
        };
        let mut s = format!("rt.initialization(init)?;if !rt.locks.is_empty(){{return Err(\"CRT lifecycle entered with live lock lease\");}}let lifecycle_count=rt.resolve_absolute({},CrtRegionKind::Module)?;let lifecycle_table=rt.resolve_absolute({},CrtRegionKind::Module)?;let lifecycle_files=rt.resolve_absolute({},CrtRegionKind::File)?;let lifecycle_descriptors=rt.resolve_absolute({},CrtRegionKind::Module)?;rt.valid(lifecycle_files,{})?;if rt.load(lifecycle_count,32)?.known_scalar()? != {count}{{return Err(\"CRT lifecycle initial count contract\");}}",l.count,l.table,l.files,l.descriptors,l.file_count*l.file_stride);
        match self.kind {
            Kind::Initialize => {
                s.push_str("if !rt.lock_objects.is_empty()||rt.load(lifecycle_table,32)?.known_scalar()?!=0{return Err(\"CRT lifecycle uninitialized table/locks contract\");}let lifecycle_block=CrtCpu::pointer(rt.load(lifecycle_descriptors,32)?)?;if lifecycle_block.kind!=CrtRegionKind::Descriptor{return Err(\"CRT lifecycle descriptor role\");}");
                s.push_str(&format!(
                    "rt.valid(lifecycle_block,{})?;",
                    l.file_count * l.descriptor_stride
                ));
                for (i, h) in l.handles.iter().enumerate() {
                    s.push_str(&format!("if rt.load(rt.offset(lifecycle_files,{})?,32)?.known_scalar()? != {i}{{return Err(\"CRT lifecycle initial descriptor field\");}}let lifecycle_handle=rt.load(rt.offset(lifecycle_block,{})?,32)?;",i as u32*l.file_stride+l.file_descriptor_offset,i as u32*l.descriptor_stride+l.handle_offset));
                    let check = match h {
                        Descriptor::Valid => "matches!(lifecycle_handle,CrtValue::Handle(h) if h.handle!=0 && h.handle!=u32::MAX && h.handle!=u32::MAX-1)".to_string(),
                        Descriptor::Null => "lifecycle_handle==CrtValue::scalar(0)".into(),
                        Descriptor::Invalid => "lifecycle_handle==CrtValue::scalar(u32::MAX)".into(),
                        Descriptor::Detached => "lifecycle_handle==CrtValue::scalar(u32::MAX-1)".into(),
                    };
                    s.push_str(&format!(
                        "if !({check}){{return Err(\"CRT lifecycle descriptor class contract\");}}"
                    ));
                }
            }
            Kind::Teardown => {
                s.push_str(&format!("let lifecycle_allocation=CrtCpu::pointer(rt.load(lifecycle_table,32)?)?;if lifecycle_allocation.kind!=CrtRegionKind::Buffer||lifecycle_allocation.address()!=lifecycle_allocation.base||lifecycle_allocation.size!={}||rt.lock_objects.len()!={}{{return Err(\"CRT lifecycle live table extent/locks\");}}",count*4,l.file_count));
                for i in 0..l.file_count {
                    s.push_str(&format!("let lifecycle_file=rt.offset(lifecycle_files,{})?;if !rt.lock_objects.contains(&lifecycle_file.address())||rt.load(rt.offset(lifecycle_allocation,{})?,32)?!=CrtValue::Pointer(lifecycle_file){{return Err(\"CRT lifecycle table slot/lock identity\");}}",i*l.file_stride,i*4));
                }
            }
        }
        s
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Region {
    Count,
    Table,
    Files,
    DescriptorTable,
    DescriptorBlock,
    Allocation(u32),
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Scalar(u32),
    Address(Region, i32),
    Stack(i32),
    Saved(u8),
    Return,
    Handle(u32),
    Unknown,
}
#[derive(Clone, Copy, Debug, Default)]
struct Flags {
    z: Option<bool>,
    c: Option<bool>,
    s: Option<bool>,
    o: Option<bool>,
}
#[derive(Clone)]
struct State {
    pc: u32,
    r: [Value; 8],
    stack: BTreeMap<i32, Value>,
    sp: i32,
    memory: BTreeMap<(Region, i32), Value>,
    flags: Flags,
    allocations: BTreeMap<u32, u32>,
    next_allocation: u32,
    constructed: BTreeSet<u32>,
    deleted: BTreeSet<u32>,
    freed_buffers: BTreeSet<u32>,
    flushes: u32,
    closed_additional: u32,
    table_freed: bool,
    steps: u32,
    depth: u32,
}
fn full(r: Reg) -> Result<usize, String> {
    if r.width != 32 || r.shift != 0 || r.index >= 8 {
        return Err("CRT lifecycle partial register".into());
    }
    Ok(r.index as usize)
}
fn scalar(v: &Value) -> Result<u32, String> {
    if let Value::Scalar(n) = v {
        Ok(*n)
    } else {
        Err("CRT lifecycle unknown/non-scalar operation".into())
    }
}
impl Layout {
    fn validate(&self) -> Result<(), String> {
        if self.file_count == 0
            || self.file_count > 16
            || self.file_stride < 4
            || self.file_stride > 256
            || !self.file_stride.is_multiple_of(4)
            || !self.descriptor_stride.is_multiple_of(4)
            || self.descriptor_stride < 4
            || self.descriptor_stride > 256
            || self.handles.len() != self.file_count as usize
            || !self.lock_offset.is_multiple_of(4)
            || self
                .lock_offset
                .checked_add(4)
                .is_none_or(|n| n > self.file_stride)
            || !self.handle_offset.is_multiple_of(4)
            || self
                .handle_offset
                .checked_add(4)
                .is_none_or(|n| n > self.descriptor_stride)
            || !self.file_descriptor_offset.is_multiple_of(4)
            || self
                .file_descriptor_offset
                .checked_add(4)
                .is_none_or(|n| n > self.file_stride)
            || self.file_descriptor_offset == self.lock_offset
        {
            return Err("CRT lifecycle layout widths/counts".into());
        }
        // Negative initial counts are handled by the original signed comparison.
        if self.initial_capacity as i32 > 4096 {
            return Err("CRT lifecycle table resource bound".into());
        }
        let ranges = [
            (self.count, 4),
            (self.table, 4),
            (
                self.files,
                self.file_stride
                    .checked_mul(self.file_count)
                    .ok_or("CRT lifecycle FILE extent")?,
            ),
            (self.descriptors, 4),
        ];
        for (i, (a, n)) in ranges.iter().enumerate() {
            if *a == 0 || !a.is_multiple_of(4) || a.checked_add(*n).is_none() {
                return Err("CRT lifecycle image range".into());
            }
            for (b, m) in &ranges[..i] {
                if u64::from(*a) < u64::from(*b) + u64::from(*m)
                    && u64::from(*b) < u64::from(*a) + u64::from(*n)
                {
                    return Err("CRT lifecycle image aliases".into());
                }
            }
        }
        Ok(())
    }
    fn absolute(&self, n: u32) -> Option<Value> {
        if n == self.count {
            return Some(Value::Address(Region::Count, 0));
        }
        if n == self.table {
            return Some(Value::Address(Region::Table, 0));
        }
        if n == self.descriptors {
            return Some(Value::Address(Region::DescriptorTable, 0));
        }
        let end = self
            .files
            .checked_add(self.file_stride.checked_mul(self.file_count)?)?;
        if (self.files..=end).contains(&n) {
            return Some(Value::Address(Region::Files, (n - self.files) as i32));
        }
        None
    }
    fn capacity(&self) -> u32 {
        if self.initial_capacity == 0 {
            512
        } else if (self.initial_capacity as i32) < 3 {
            3
        } else {
            self.initial_capacity
        }
    }
}
impl State {
    fn new(origin: u32, b: &Bindings, kind: Kind) -> Self {
        let l = &b.layout;
        let mut r = std::array::from_fn(|i| Value::Saved(i as u8));
        r[4] = Value::Stack(0);
        let mut memory = BTreeMap::from([
            ((Region::Count, 0), Value::Scalar(l.initial_capacity)),
            ((Region::Table, 0), Value::Scalar(0)),
        ]);
        // These are separately checked pre-initialization facts. They cannot
        // be carried into shutdown: original init and intervening user code may
        // change FILE descriptor fields and the descriptor table.
        if kind == Kind::Initialize {
            memory.insert(
                (Region::DescriptorTable, 0),
                Value::Address(Region::DescriptorBlock, 0),
            );
            for (i, h) in l.handles.iter().enumerate() {
                let i = i as u32;
                memory.insert(
                    (
                        Region::DescriptorBlock,
                        (i * l.descriptor_stride + l.handle_offset) as i32,
                    ),
                    match h {
                        Descriptor::Valid => Value::Handle(i),
                        Descriptor::Null => Value::Scalar(0),
                        Descriptor::Invalid => Value::Scalar(u32::MAX),
                        Descriptor::Detached => Value::Scalar(u32::MAX - 1),
                    },
                );
                memory.insert(
                    (
                        Region::Files,
                        (i * l.file_stride + l.file_descriptor_offset) as i32,
                    ),
                    Value::Scalar(i),
                );
            }
        }
        let mut allocations = BTreeMap::new();
        let mut constructed = BTreeSet::new();
        if kind == Kind::Teardown {
            let cap = l.capacity();
            allocations.insert(1, cap);
            memory.insert((Region::Count, 0), Value::Scalar(cap));
            memory.insert((Region::Table, 0), Value::Address(Region::Allocation(1), 0));
            for i in 0..l.file_count {
                memory.insert(
                    (Region::Allocation(1), (i * 4) as i32),
                    Value::Address(Region::Files, (i * l.file_stride) as i32),
                );
                constructed.insert(i);
            }
        }
        Self {
            pc: origin,
            r,
            stack: BTreeMap::from([(0, Value::Return)]),
            sp: 0,
            memory,
            flags: Flags::default(),
            allocations,
            next_allocation: 2,
            constructed,
            deleted: BTreeSet::new(),
            freed_buffers: BTreeSet::new(),
            flushes: 0,
            closed_additional: 0,
            table_freed: false,
            steps: 0,
            depth: 0,
        }
    }
    fn bounded(&self, region: Region, offset: i32, l: &Layout) -> Result<(), String> {
        let size = match region {
            Region::Count | Region::Table | Region::DescriptorTable => 4,
            Region::Files => l.file_count * l.file_stride,
            Region::DescriptorBlock => l.file_count * l.descriptor_stride,
            Region::Allocation(id) => {
                self.allocations
                    .get(&id)
                    .ok_or("CRT lifecycle stale allocation")?
                    * 4
            }
        };
        if offset < 0
            || !(offset as u32).is_multiple_of(4)
            || (offset as u32).checked_add(4).is_none_or(|end| end > size)
        {
            return Err("CRT lifecycle full-word bounds".into());
        }
        Ok(())
    }
    fn address(&self, a: &Address, l: &Layout) -> Result<Value, String> {
        let mut delta = i64::from(a.displacement as i32);
        let mut base = if let Some(r) = a.base {
            self.r[r as usize].clone()
        } else {
            delta = 0;
            l.absolute(a.displacement)
                .ok_or("CRT lifecycle unbound absolute memory")?
        };
        if let Some(r) = a.index {
            if let (Value::Scalar(n), Value::Address(region, offset), 1) =
                (&base, &self.r[r as usize], a.scale)
            {
                delta = delta
                    .checked_add(i64::from(*n))
                    .ok_or("CRT lifecycle index overflow")?;
                base = Value::Address(*region, *offset);
            } else {
                delta = delta
                    .checked_add(i64::from(scalar(&self.r[r as usize])?) * i64::from(a.scale))
                    .ok_or("CRT lifecycle index overflow")?;
            }
        }
        match base {
            Value::Address(region, n) => Ok(Value::Address(
                region,
                i32::try_from(i64::from(n) + delta)
                    .map_err(|_| "CRT lifecycle address overflow")?,
            )),
            Value::Stack(n) => Ok(Value::Stack(
                i32::try_from(i64::from(n) + delta).map_err(|_| "CRT lifecycle stack overflow")?,
            )),
            _ => Err("CRT lifecycle unowned address".into()),
        }
    }
    fn load(&self, v: Value, l: &Layout) -> Result<Value, String> {
        match v {
            Value::Stack(n) => self
                .stack
                .get(&n)
                .filter(|v| **v != Value::Return)
                .cloned()
                .ok_or("CRT lifecycle protected/uninitialized stack".into()),
            Value::Address(region, n) => {
                self.bounded(region, n, l)?;
                self.memory
                    .get(&(region, n))
                    .cloned()
                    .or_else(|| matches!(region, Region::Allocation(_)).then_some(Value::Scalar(0)))
                    .ok_or("CRT lifecycle uninitialized field".into())
            }
            _ => Err("CRT lifecycle load provenance".into()),
        }
    }
    fn read(&self, o: &Operand, l: &Layout) -> Result<Value, String> {
        match o {
            Operand::Immediate(n) => Ok(l.absolute(*n).unwrap_or(Value::Scalar(*n))),
            Operand::Reg(r) => Ok(self.r[full(*r)?].clone()),
            Operand::Memory(a, 32) => self.load(self.address(a, l)?, l),
            _ => Err("CRT lifecycle operand width".into()),
        }
    }
    fn write(&mut self, o: &Operand, v: Value, l: &Layout) -> Result<(), String> {
        match o {
            Operand::Reg(r) => {
                let i = full(*r)?;
                if i == 4 {
                    return Err("CRT lifecycle arbitrary ESP write".into());
                }
                self.r[i] = v;
                Ok(())
            }
            Operand::Memory(a, 32) => {
                let Value::Address(region, n) = self.address(a, l)? else {
                    return Err("CRT lifecycle stack/protected store".into());
                };
                self.bounded(region, n, l)?;
                match region {
                    Region::Count => {
                        let count = scalar(&v)?;
                        if count < l.file_count || count > 4096 {
                            return Err("CRT lifecycle table count store".into());
                        }
                    }
                    Region::Table => {
                        if !matches!(
                            v,
                            Value::Address(Region::Allocation(_), 0) | Value::Scalar(0)
                        ) {
                            return Err("CRT lifecycle table pointer store".into());
                        }
                    }
                    Region::Allocation(_) => {
                        let index = n as u32 / 4;
                        if index >= l.file_count
                            || v != Value::Address(Region::Files, (index * l.file_stride) as i32)
                            || !self.constructed.contains(&index)
                        {
                            return Err("CRT lifecycle FILE table binding/order".into());
                        }
                    }
                    Region::Files => {
                        let index = n as u32 / l.file_stride;
                        let at = n as u32 % l.file_stride;
                        if at != l.file_descriptor_offset
                            || scalar(&v)? != u32::MAX - 1
                            || !matches!(
                                l.handles[index as usize],
                                Descriptor::Null | Descriptor::Invalid | Descriptor::Detached
                            )
                        {
                            return Err("CRT lifecycle protected FILE write".into());
                        }
                    }
                    _ => return Err("CRT lifecycle read-only descriptor state".into()),
                }
                self.memory.insert((region, n), v);
                Ok(())
            }
            _ => Err("CRT lifecycle store width".into()),
        }
    }
    fn push(&mut self, v: Value) -> Result<(), String> {
        self.sp = self
            .sp
            .checked_sub(4)
            .ok_or("CRT lifecycle stack underflow")?;
        if self.sp < -256 {
            return Err("CRT lifecycle stack budget".into());
        }
        self.depth = self.depth.max(self.sp.unsigned_abs());
        if self.stack.insert(self.sp, v).is_some() {
            return Err("CRT lifecycle live stack alias".into());
        }
        self.r[4] = Value::Stack(self.sp);
        Ok(())
    }
    fn pop(&mut self) -> Result<Value, String> {
        let v = self
            .stack
            .remove(&self.sp)
            .filter(|v| *v != Value::Return)
            .ok_or("CRT lifecycle protected pop")?;
        self.sp += 4;
        self.r[4] = Value::Stack(self.sp);
        Ok(v)
    }
    fn compare(&mut self, a: Value, b: Value, test: bool) -> Result<(), String> {
        if let (Value::Address(ra, x), Value::Address(rb, y)) = (&a, &b) {
            if ra == rb && (!test || a == b) {
                self.flags = Flags {
                    z: Some(!test && x == y),
                    // Capability-relative offsets do not establish numeric
                    // address sign/overflow or arbitrary ordering flags.
                    ..Flags::default()
                };
                return Ok(());
            }
        }
        let pair = match (&a, &b) {
            (Value::Scalar(x), Value::Scalar(y)) => Some((*x, *y)),
            _ => None,
        };
        if let Some((x, y)) = pair {
            let result = if test { x & y } else { x.wrapping_sub(y) };
            self.flags = Flags {
                z: Some(result == 0),
                c: Some(!test && x < y),
                s: Some(result & 0x80000000 != 0),
                o: Some(!test && ((x ^ y) & (x ^ result) & 0x80000000) != 0),
            };
            return Ok(());
        }
        let equal = match (&a, &b) {
            (Value::Address(_, _) | Value::Handle(_), Value::Scalar(0))
            | (Value::Scalar(0), Value::Address(_, _) | Value::Handle(_)) => Some(test),
            (Value::Handle(_), Value::Scalar(n)) if *n == u32::MAX || *n == u32::MAX - 1 => {
                Some(false)
            }
            (Value::Address(_, _) | Value::Handle(_), _) if test && a == b => Some(false),
            _ => None,
        };
        if let Some(z) = equal {
            self.flags = Flags {
                z: Some(z),
                ..Flags::default()
            };
            Ok(())
        } else {
            Err("CRT lifecycle unproved predicate".into())
        }
    }
    fn branch(&self, c: Condition) -> Result<bool, String> {
        let z = self
            .flags
            .z
            .ok_or_else(|| "CRT lifecycle unknown ZF".to_string());
        let cf = self
            .flags
            .c
            .ok_or_else(|| "CRT lifecycle unknown CF".to_string());
        match c {
            Condition::Equal => z,
            Condition::NotEqual => z.map(|v| !v),
            Condition::Below => cf,
            Condition::Above => Ok(!cf? && !z?),
            Condition::BelowEqual => Ok(cf? || z?),
            Condition::AboveEqual => cf.map(|v| !v),
        }
    }
    fn signed(&self, c: SignedCondition) -> Result<bool, String> {
        let s = self.flags.s.ok_or("CRT lifecycle unknown SF")?;
        let o = self.flags.o.ok_or("CRT lifecycle unknown OF")?;
        let z = self.flags.z.ok_or("CRT lifecycle unknown ZF")?;
        Ok(match c {
            SignedCondition::Less => s != o,
            SignedCondition::LessEqual => z || s != o,
            SignedCondition::Greater => !z && s == o,
            SignedCondition::GreaterEqual => s == o,
            SignedCondition::Sign => s,
            SignedCondition::NotSign => !s,
        })
    }
    fn call_args(&self, n: usize) -> Result<Vec<Value>, String> {
        (0..n)
            .map(|i| {
                self.stack
                    .get(&(self.sp + i as i32 * 4))
                    .filter(|v| !matches!(v, Value::Return | Value::Saved(_)))
                    .cloned()
                    .ok_or("CRT lifecycle call argument ownership".into())
            })
            .collect()
    }
    fn file_index(v: &Value, l: &Layout, offset: u32) -> Result<u32, String> {
        if let Value::Address(Region::Files, n) = v {
            if *n >= 0 && (*n as u32) % l.file_stride == offset {
                let i = *n as u32 / l.file_stride;
                if i < l.file_count {
                    return Ok(i);
                }
            }
        }
        Err("CRT lifecycle FILE/lock identity".into())
    }
    fn clobber(&mut self, result: Value) {
        self.r[0] = result;
        self.r[1] = Value::Unknown;
        self.r[2] = Value::Unknown;
        self.flags = Flags::default();
    }
}
fn argument(v: &Value, l: &Layout, alloc: &BTreeMap<u32, u32>) -> Result<Argument, String> {
    match v {
        Value::Scalar(n) => Ok(Argument::Scalar(*n)),
        Value::Address(Region::Files, n) if *n >= 0 => Ok(Argument::File {
            index: *n as u32 / l.file_stride,
            offset: *n as u32 % l.file_stride,
        }),
        Value::Address(Region::Allocation(id), 0) => Ok(Argument::Table {
            words: *alloc.get(id).ok_or("CRT lifecycle freed argument")?,
        }),
        _ => Err("CRT lifecycle call capability".into()),
    }
}
fn call(
    mut s: State,
    t: Target,
    e: Effect,
    b: &Bindings,
    kind: Kind,
    requirements: &mut Vec<CallRequirement>,
) -> Result<Vec<State>, String> {
    let l = &b.layout;
    let argc = match e {
        Effect::AllocateTable => 2,
        Effect::ConstructLock => 3,
        Effect::FreeAllocation | Effect::FreeFileBuffer | Effect::DeleteLock => 1,
        Effect::FlushAll | Effect::CloseAdditional => 0,
    };
    let args = s.call_args(argc)?;
    s.depth = s.depth.max(s.sp.unsigned_abs() + 4);
    let packet = CallRequirement {
        pc: s.pc,
        target: t,
        effect: e,
        arguments: args
            .iter()
            .map(|v| argument(v, l, &s.allocations))
            .collect::<Result<_, _>>()?,
        entry_depth: s.sp.unsigned_abs() + 4,
    };
    if !requirements.contains(&packet) {
        requirements.push(packet);
    }
    match e {
        Effect::AllocateTable => {
            if kind != Kind::Initialize || args[1] != Value::Scalar(4) {
                return Err("CRT lifecycle calloc width/kind".into());
            }
            let n = scalar(&args[0])?;
            if n < l.file_count
                || n > 4096
                || !s.constructed.is_empty()
                || !s.allocations.is_empty()
            {
                return Err("CRT lifecycle allocation count/order".into());
            }
            let mut failed = s.clone();
            failed.clobber(Value::Scalar(0));
            let id = s.next_allocation;
            s.next_allocation += 1;
            s.allocations.insert(id, n);
            s.clobber(Value::Address(Region::Allocation(id), 0));
            Ok(vec![failed, s])
        }
        Effect::FreeAllocation => {
            match args[0] {
                Value::Scalar(0) => {}
                Value::Address(Region::Allocation(id), 0) => {
                    if kind != Kind::Teardown
                        || s.deleted.len() != l.file_count as usize
                        || s.allocations.remove(&id).is_none()
                    {
                        return Err("CRT lifecycle allocation release/order".into());
                    }
                    s.table_freed = true;
                }
                _ => return Err("CRT lifecycle free provenance".into()),
            };
            s.clobber(Value::Unknown);
            Ok(vec![s])
        }
        Effect::ConstructLock => {
            if kind != Kind::Initialize
                || args[1] != Value::Scalar(4000)
                || args[2] != Value::Scalar(0)
            {
                return Err("CRT lifecycle lock helper arguments".into());
            }
            let i = State::file_index(&args[0], l, l.lock_offset)?;
            if i != s.constructed.len() as u32 || !s.constructed.insert(i) {
                return Err("CRT lifecycle lock duplication/order".into());
            }
            // The bound thunk tail-calls InitializeCriticalSectionEx (stdcall).
            // Its successful construction contract remains required externally.
            for _ in 0..3 {
                s.pop()?;
            }
            s.clobber(Value::Unknown);
            Ok(vec![s])
        }
        Effect::FlushAll => {
            if kind != Kind::Teardown
                || s.flushes != 0
                || !s.deleted.is_empty()
                || !s.freed_buffers.is_empty()
            {
                return Err("CRT lifecycle flush order".into());
            }
            s.flushes += 1;
            s.clobber(Value::Unknown);
            Ok(vec![s])
        }
        Effect::CloseAdditional => {
            if kind != Kind::Teardown
                || s.flushes != 1
                || s.closed_additional != 0
                || !s.deleted.is_empty()
            {
                return Err("CRT lifecycle close traversal order".into());
            }
            s.closed_additional += 1;
            s.clobber(Value::Unknown);
            Ok(vec![s])
        }
        Effect::FreeFileBuffer => {
            let i = State::file_index(&args[0], l, 0)?;
            if kind != Kind::Teardown
                || s.flushes != 1
                || s.closed_additional != 1
                || i != s.deleted.len() as u32
                || !s.freed_buffers.insert(i)
            {
                return Err("CRT lifecycle buffer release/order".into());
            }
            s.clobber(Value::Unknown);
            Ok(vec![s])
        }
        Effect::DeleteLock => {
            let i = State::file_index(&args[0], l, l.lock_offset)?;
            if kind != Kind::Teardown
                || !s.freed_buffers.contains(&i)
                || i != s.deleted.len() as u32
                || !s.deleted.insert(i)
            {
                return Err("CRT lifecycle lock deletion/order".into());
            }
            s.pop()?;
            s.clobber(Value::Unknown);
            Ok(vec![s])
        }
    }
}
fn terminal(s: &State, b: &Bindings, kind: Kind) -> Result<ReturnRequirement, String> {
    let l = &b.layout;
    if s.sp != 0
        || s.stack != BTreeMap::from([(0, Value::Return)])
        || [3, 5, 6, 7]
            .iter()
            .any(|&i| s.r[i] != Value::Saved(i as u8))
    {
        return Err("CRT lifecycle saved register/protected RET".into());
    }
    let initialized = match kind {
        Kind::Initialize => {
            let table = s
                .memory
                .get(&(Region::Table, 0))
                .ok_or("CRT lifecycle missing table")?;
            if *table == Value::Scalar(0) {
                if s.r[0] != Value::Scalar(u32::MAX)
                    || !s.constructed.is_empty()
                    || !s.allocations.is_empty()
                {
                    return Err("CRT lifecycle failed init reported success/leak".into());
                }
                false
            } else {
                let Value::Address(Region::Allocation(id), 0) = table else {
                    return Err("CRT lifecycle successful table provenance".into());
                };
                let n = *s
                    .allocations
                    .get(id)
                    .ok_or("CRT lifecycle successful allocation lifetime")?;
                if s.r[0] != Value::Scalar(0)
                    || s.constructed.len() != l.file_count as usize
                    || s.memory.get(&(Region::Count, 0)) != Some(&Value::Scalar(n))
                {
                    return Err("CRT lifecycle incomplete successful initialization".into());
                }
                for i in 0..l.file_count {
                    if s.memory.get(&(Region::Allocation(*id), (i * 4) as i32))
                        != Some(&Value::Address(Region::Files, (i * l.file_stride) as i32))
                    {
                        return Err("CRT lifecycle missing FILE table slot".into());
                    }
                    let expected = match l.handles[i as usize] {
                        Descriptor::Valid => i,
                        _ => u32::MAX - 1,
                    };
                    if s.memory.get(&(
                        Region::Files,
                        (i * l.file_stride + l.file_descriptor_offset) as i32,
                    )) != Some(&Value::Scalar(expected))
                    {
                        return Err("CRT lifecycle descriptor initialization missing".into());
                    }
                }
                true
            }
        }
        Kind::Teardown => {
            if s.flushes != 1
                || s.closed_additional != 1
                || s.freed_buffers.len() != l.file_count as usize
                || s.deleted.len() != l.file_count as usize
                || !s.table_freed
                || !s.allocations.is_empty()
                || s.memory.get(&(Region::Table, 0)) != Some(&Value::Scalar(0))
            {
                return Err("CRT lifecycle incomplete teardown".into());
            }
            false
        }
    };
    Ok(ReturnRequirement {
        pc: s.pc,
        result: if let Value::Scalar(n) = s.r[0] {
            Some(n)
        } else {
            None
        },
        initialized,
    })
}
/// Complete bounded paths are proved from the decoded graph, including both
/// allocation outcomes. Called-helper requirements remain undischarged here.
pub(crate) fn prove(
    code: &[u8],
    origin: u32,
    bindings: Bindings,
    kind: Kind,
) -> Result<Proof, String> {
    bindings.layout.validate()?;
    let graph = Graph::decode(code, origin)?;
    if graph.calls() != bindings.calls.keys().copied().collect() {
        return Err("CRT lifecycle missing/extra call binding".into());
    }
    let end = origin
        .checked_add(code.len() as u32)
        .ok_or("CRT lifecycle source extent")?;
    for (a, size) in [
        (bindings.layout.count, 4),
        (bindings.layout.table, 4),
        (
            bindings.layout.files,
            bindings.layout.file_count * bindings.layout.file_stride,
        ),
        (bindings.layout.descriptors, 4),
    ] {
        if u64::from(a) < u64::from(end) && u64::from(origin) < u64::from(a) + u64::from(size) {
            return Err("CRT lifecycle code/data alias".into());
        }
    }
    for target in bindings.calls.keys() {
        let address = match target {
            Target::Direct(a) | Target::Import(a) => *a,
        };
        if (origin..end).contains(&address) {
            return Err("CRT lifecycle recursive or code-aliased call binding".into());
        }
    }
    let mut todo = vec![State::new(origin, &bindings, kind)];
    let mut calls = Vec::new();
    let mut returns = Vec::new();
    let (mut steps, mut depth, mut paths) = (0, 0, 0);
    while let Some(mut s) = todo.pop() {
        paths += 1;
        if paths > 64 {
            return Err("CRT lifecycle allocation path budget".into());
        }
        loop {
            s.steps += 1;
            if s.steps > 1024 {
                return Err("CRT lifecycle unproved cycle/instruction budget".into());
            }
            let node = graph
                .nodes
                .get(&s.pc)
                .ok_or("CRT lifecycle unknown instruction")?;
            let next = s.pc + node.length;
            match &node.op {
                Op::Call(target) => {
                    let effect = *bindings
                        .calls
                        .get(target)
                        .ok_or("CRT lifecycle unbound call")?;
                    let states = call(s, *target, effect, &bindings, kind, &mut calls)?;
                    for mut state in states {
                        state.pc = next;
                        todo.push(state);
                    }
                    break;
                }
                Op::SignedBranch { condition, target } => {
                    s.pc = if s.signed(*condition)? { *target } else { next };
                    continue;
                }
                Op::ArithmeticShift { dst, count } => {
                    let i = full(*dst)?;
                    s.r[i] = Value::Scalar(((scalar(&s.r[i])? as i32) >> count) as u32);
                    s.flags = Flags::default();
                }
                Op::Multiply {
                    dst,
                    source,
                    factor,
                } => {
                    let n = scalar(&s.read(source, &bindings.layout)?)?;
                    s.r[full(*dst)?] = Value::Scalar(n.wrapping_mul(*factor));
                    s.flags = Flags::default();
                }
                Op::Ordinary(op) => match op {
                    Operation::Return => {
                        let requirement = terminal(&s, &bindings, kind)?;
                        if !returns.contains(&requirement) {
                            returns.push(requirement);
                        }
                        steps = steps.max(s.steps);
                        depth = depth.max(s.depth);
                        break;
                    }
                    Operation::Jump(t) => {
                        s.pc = *t;
                        continue;
                    }
                    Operation::Branch(c, t) => {
                        s.pc = if s.branch(*c)? { *t } else { next };
                        continue;
                    }
                    Operation::Nop => {}
                    Operation::Push(o) => {
                        let v = s.read(o, &bindings.layout)?;
                        s.push(v)?;
                    }
                    Operation::Pop(r) => {
                        let i = full(*r)?;
                        if i == 4 {
                            return Err("CRT lifecycle POP ESP".into());
                        }
                        s.r[i] = s.pop()?;
                    }
                    Operation::Address(r, a) => {
                        let v = s.address(a, &bindings.layout)?;
                        s.write(&Operand::Reg(*r), v, &bindings.layout)?;
                    }
                    Operation::Increment(r) => {
                        let i = full(*r)?;
                        let n = scalar(&s.r[i])?.wrapping_add(1);
                        s.r[i] = Value::Scalar(n);
                        s.flags = Flags::default();
                    }
                    Operation::Shift { left, dst, count } => {
                        let i = full(*dst)?;
                        let n = scalar(&s.r[i])?;
                        s.r[i] = Value::Scalar(if *left {
                            n.wrapping_shl((*count).into())
                        } else {
                            n.wrapping_shr((*count).into())
                        });
                        s.flags = Flags::default();
                    }
                    Operation::Binary(operation, dst, src) => {
                        if *operation == Binary::Move {
                            let v = s.read(src, &bindings.layout)?;
                            s.write(dst, v, &bindings.layout)?;
                        } else if *operation == Binary::Xor && dst == src {
                            if !matches!(dst, Operand::Reg(_)) {
                                return Err("CRT lifecycle memory zero provenance".into());
                            }
                            s.write(dst, Value::Scalar(0), &bindings.layout)?;
                            s.flags = Flags {
                                z: Some(true),
                                c: Some(false),
                                s: Some(false),
                                o: Some(false),
                            };
                        } else {
                            let a = s.read(dst, &bindings.layout)?;
                            let b = s.read(src, &bindings.layout)?;
                            match operation {
                                Binary::Compare | Binary::Test => {
                                    s.compare(a, b, *operation == Binary::Test)?
                                }
                                Binary::Add => {
                                    if let Operand::Reg(r) = dst {
                                        if full(*r)? == 4 {
                                            let n = scalar(&b)?;
                                            if !n.is_multiple_of(4) || n > 256 {
                                                return Err(
                                                    "CRT lifecycle argument cleanup extent".into(),
                                                );
                                            }
                                            for _ in 0..n / 4 {
                                                if matches!(s.pop()?, Value::Saved(_)) {
                                                    return Err(
                                                        "CRT lifecycle cleanup saved register"
                                                            .into(),
                                                    );
                                                }
                                            }
                                            s.flags = Flags::default();
                                            s.pc = next;
                                            continue;
                                        }
                                    }
                                    let value = match (a, b) {
                                        (Value::Scalar(x), Value::Scalar(y)) => {
                                            Value::Scalar(x.wrapping_add(y))
                                        }
                                        (Value::Address(region, n), Value::Scalar(x))
                                        | (Value::Scalar(x), Value::Address(region, n)) => {
                                            Value::Address(
                                                region,
                                                n.checked_add(x as i32)
                                                    .ok_or("CRT lifecycle pointer addition")?,
                                            )
                                        }
                                        _ => return Err("CRT lifecycle addition provenance".into()),
                                    };
                                    s.write(dst, value, &bindings.layout)?;
                                    s.flags = Flags::default();
                                }
                                Binary::And | Binary::Or => {
                                    let n = if *operation == Binary::And && b == Value::Scalar(0) {
                                        0
                                    } else if *operation == Binary::Or
                                        && b == Value::Scalar(u32::MAX)
                                    {
                                        u32::MAX
                                    } else if *operation == Binary::And {
                                        scalar(&a)? & scalar(&b)?
                                    } else {
                                        scalar(&a)? | scalar(&b)?
                                    };
                                    s.write(dst, Value::Scalar(n), &bindings.layout)?;
                                    s.flags = Flags {
                                        z: Some(n == 0),
                                        c: Some(false),
                                        s: Some(n & 0x80000000 != 0),
                                        o: Some(false),
                                    };
                                }
                                _ => return Err("CRT lifecycle unsupported scalar effect".into()),
                            }
                        }
                    }
                    _ => return Err("CRT lifecycle unsupported instruction effect".into()),
                },
                _ => return Err("CRT lifecycle unsupported extended effect".into()),
            }
            s.pc = next;
        }
    }
    if returns.is_empty() {
        return Err("CRT lifecycle no proven return".into());
    }
    Ok(Proof {
        graph,
        bindings,
        kind,
        calls,
        returns,
        temporary_bytes: depth,
        step_bound: steps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    // Retained authored PE instructions. Expectations below are independently
    // stated effects, not generated by replaying the production certificate.
    const INIT:&str="a12ccd4100566a035e85c07507b800020000eb063bc67d078bc6a32ccd41006a0450e8b93700006a00a330cd4100e80d38000083c40c833d30cd410000752b6a045689352ccd4100e8933700006a00a330cd4100e8e737000083c40c833d30cd410000750583c8ff5ec35733ffbe80c041006a0068a00f00008d462050e8e73a0000a130cd41008bd7c1fa068934b88bc783e03f6bc8388b049508cf41008b44081883f8ff740983f8fe740485c07507c74610feffffff83c6384781fe28c1410075af5f33c05ec3";
    const EXIT:&str="8bff56e8fe3e0000e8a83b000033f6a130cd4100ff3406e8f33e0000a130cd4100598b040683c02050ff155450410083c60483fe0c75d85eff3530cd4100e825370000832530cd41000059c3";
    fn bytes(s: &str) -> Vec<u8> {
        s.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
    fn bindings(kind: Kind, capacity: u32, handles: Vec<Descriptor>) -> Bindings {
        let calls = if kind == Kind::Initialize {
            BTreeMap::from([
                (Target::Direct(0x407cf0), Effect::AllocateTable),
                (Target::Direct(0x407d50), Effect::FreeAllocation),
                (Target::Direct(0x408079), Effect::ConstructLock),
            ])
        } else {
            BTreeMap::from([
                (Target::Direct(0x4084ee), Effect::FlushAll),
                (Target::Direct(0x40819d), Effect::CloseAdditional),
                (Target::Direct(0x4084f7), Effect::FreeFileBuffer),
                (Target::Import(0x415054), Effect::DeleteLock),
                (Target::Direct(0x407d50), Effect::FreeAllocation),
            ])
        };
        Bindings {
            calls,
            layout: Layout {
                count: 0x41cd2c,
                table: 0x41cd30,
                files: 0x41c080,
                descriptors: 0x41cf08,
                file_stride: 56,
                file_count: 3,
                lock_offset: 32,
                descriptor_stride: 56,
                handle_offset: 24,
                file_descriptor_offset: 16,
                initial_capacity: capacity,
                handles,
            },
        }
    }
    #[test]
    fn original_initialization_proves_fallback_and_failed_return_without_zeroing_unknowns() {
        for cap in [0, 1, 3, 9, 4096, u32::MAX] {
            let p = prove(
                &bytes(INIT),
                0x404510,
                bindings(
                    Kind::Initialize,
                    cap,
                    vec![Descriptor::Valid, Descriptor::Null, Descriptor::Detached],
                ),
                Kind::Initialize,
            )
            .unwrap();
            assert_eq!(p.temporary_bytes, 24);
            assert!(p
                .returns
                .iter()
                .any(|r| r.result == Some(u32::MAX) && !r.initialized));
            assert!(p
                .returns
                .iter()
                .any(|r| r.result == Some(0) && r.initialized));
            let locks = p
                .calls
                .iter()
                .filter(|c| c.effect == Effect::ConstructLock)
                .map(|c| c.arguments[0].clone())
                .collect::<Vec<_>>();
            assert_eq!(
                locks,
                vec![
                    Argument::File {
                        index: 0,
                        offset: 32
                    },
                    Argument::File {
                        index: 1,
                        offset: 32
                    },
                    Argument::File {
                        index: 2,
                        offset: 32
                    }
                ]
            );
            assert!(p.calls.iter().any(|c| c.effect == Effect::AllocateTable
                && c.arguments == [Argument::Scalar(3), Argument::Scalar(4)]));
        }
        prove(
            &bytes(INIT),
            0x404510,
            bindings(Kind::Initialize, 0, vec![Descriptor::Invalid; 3]),
            Kind::Initialize,
        )
        .unwrap();
    }
    #[test]
    fn original_teardown_retains_per_stream_release_then_lock_destruction() {
        let p = prove(
            &bytes(EXIT),
            0x4045e8,
            bindings(Kind::Teardown, 0, vec![Descriptor::Valid; 3]),
            Kind::Teardown,
        )
        .unwrap();
        let effects = p
            .calls
            .iter()
            .map(|c| (c.effect, c.arguments.clone()))
            .collect::<Vec<_>>();
        assert_eq!(
            effects,
            vec![
                (Effect::FlushAll, vec![]),
                (Effect::CloseAdditional, vec![]),
                (
                    Effect::FreeFileBuffer,
                    vec![Argument::File {
                        index: 0,
                        offset: 0
                    }]
                ),
                (
                    Effect::DeleteLock,
                    vec![Argument::File {
                        index: 0,
                        offset: 32
                    }]
                ),
                (
                    Effect::FreeFileBuffer,
                    vec![Argument::File {
                        index: 1,
                        offset: 0
                    }]
                ),
                (
                    Effect::DeleteLock,
                    vec![Argument::File {
                        index: 1,
                        offset: 32
                    }]
                ),
                (
                    Effect::FreeFileBuffer,
                    vec![Argument::File {
                        index: 2,
                        offset: 0
                    }]
                ),
                (
                    Effect::DeleteLock,
                    vec![Argument::File {
                        index: 2,
                        offset: 32
                    }]
                ),
                (Effect::FreeAllocation, vec![Argument::Table { words: 512 }])
            ]
        );
        assert_eq!(p.temporary_bytes, 12);
        assert_eq!(p.returns.len(), 1);
        assert_eq!(p.returns[0].result, None);
    }
    #[test]
    fn malformed_lifetime_control_and_failure_mutations_reject() {
        let original = bytes(INIT);
        for (at, to) in [
            (0x404576, 0u8),
            (0x4045c9, 52),
            (0x40458b, 0),
            (0x4045a6, 52),
            (0x4045b3, 0),
        ] {
            let mut code = original.clone();
            code[at - 0x404510] = to;
            assert!(
                prove(
                    &code,
                    0x404510,
                    bindings(Kind::Initialize, 0, vec![Descriptor::Valid; 3]),
                    Kind::Initialize
                )
                .is_err(),
                "init {at:x}"
            );
        }
        let original = bytes(EXIT);
        for (at, to) in [(0x40461b, 8u8), (0x40460f, 0), (0x40461a, 0), (0x404631, 1)] {
            let mut code = original.clone();
            code[at - 0x4045e8] = to;
            assert!(
                prove(
                    &code,
                    0x4045e8,
                    bindings(Kind::Teardown, 0, vec![Descriptor::Valid; 3]),
                    Kind::Teardown
                )
                .is_err(),
                "exit {at:x}"
            );
        }
        let mut b = bindings(Kind::Initialize, 0, vec![Descriptor::Valid; 3]);
        b.layout.table = b.layout.count;
        assert!(prove(&bytes(INIT), 0x404510, b, Kind::Initialize).is_err());
        let mut b = bindings(Kind::Teardown, 0, vec![Descriptor::Valid; 3]);
        b.calls
            .insert(Target::Direct(0x4084ee), Effect::CloseAdditional);
        assert!(prove(&bytes(EXIT), 0x4045e8, b, Kind::Teardown).is_err());
        let mut b = bindings(Kind::Initialize, 0, vec![Descriptor::Valid; 3]);
        b.layout.initial_capacity = 4097;
        assert!(prove(&bytes(INIT), 0x404510, b, Kind::Initialize).is_err());
    }
    #[test]
    fn teardown_cannot_inherit_unchecked_pre_initialization_descriptor_values() {
        let mut code = vec![0x90; 9];
        code.extend_from_slice(&[
            0x83, 0x3d, 0xc8, 0xc0, 0x41, 0, 1, 0x74, 6, 0xb8, 0, 0, 0, 0, 0xc3,
        ]);
        code.extend_from_slice(&bytes(EXIT));
        assert!(Graph::decode(&code, 0x4045d0).is_ok());
        assert!(prove(
            &code,
            0x4045d0,
            bindings(
                Kind::Teardown,
                0,
                vec![Descriptor::Valid, Descriptor::Null, Descriptor::Detached]
            ),
            Kind::Teardown
        )
        .is_err());
    }
    #[test]
    fn original_native_lifecycle_executes_fallback_and_interleaved_teardown() {
        let make = |kind, capacity, name| {
            let p = prove(
                &bytes(if kind == Kind::Initialize { INIT } else { EXIT }),
                if kind == Kind::Initialize {
                    0x404510
                } else {
                    0x4045e8
                },
                bindings(
                    kind,
                    capacity,
                    vec![Descriptor::Valid, Descriptor::Null, Descriptor::Detached],
                ),
                kind,
            )
            .unwrap();
            let body = p
                .emit_body(|pc, _, effect, _| {
                    let effect = match effect {
                        Effect::AllocateTable => 0,
                        Effect::FreeAllocation => 1,
                        Effect::ConstructLock => 2,
                        Effect::FlushAll => 3,
                        Effect::CloseAdditional => 4,
                        Effect::FreeFileBuffer => 5,
                        Effect::DeleteLock => 6,
                    };
                    Ok(format!("effect_call(rt,cpu,init,effects,{pc},{effect})?;"))
                })
                .unwrap();
            format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,effects:&mut Effects)->Result<CrtValue,&'static str>{{{body}}}")
        };
        let memory = include_str!("guest_memory.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n");
        let helpers = r#"
struct Effects{alloc:std::collections::VecDeque<bool>,events:Vec<(u32,u32)>,fail_lock:Option<u32>}
fn effect_call(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,e:&mut Effects,pc:u32,kind:u32)->Result<(),&'static str>{
 let argument_sp=CrtCpu::pointer(cpu.r[4])?;cpu.push(rt,CrtValue::ProtectedReturn(u64::from(pc)))?;
 let arg=|rt:&CrtStreamRuntime,i:i64|rt.load(rt.offset(argument_sp,i*4)?,32);
 let mut returned=CrtValue::Scalar{bits:0,known:0};let mut stdcall=0;
 match kind{
  0=>{let count=arg(rt,0)?.known_scalar()?;assert_eq!(arg(rt,1)?.known_scalar()?,4);e.events.push((0,count));let available=e.alloc.pop_front().ok_or("missing allocation schedule")?;returned=rt.alloc_initialization(init,count.checked_mul(4).ok_or("calloc overflow")?,true,available)?.map(CrtValue::Pointer).unwrap_or(CrtValue::scalar(0));},
  1=>{let v=arg(rt,0)?;match v{CrtValue::Pointer(p)=>{e.events.push((1,p.size/4));rt.free_initialization(init,p)?;},CrtValue::Scalar{bits:0,known:u32::MAX}=>e.events.push((1,0)),_=>return Err("free argument")}},
  2=>{let lock=CrtCpu::pointer(arg(rt,0)?)?;assert_eq!(arg(rt,1)?.known_scalar()?,4000);assert_eq!(arg(rt,2)?.known_scalar()?,0);let f=rt.offset(lock,-32)?;let index=(f.address()-rt.file().address())/56;e.events.push((2,index));if e.fail_lock==Some(index){return Err("unclosed lock construction failure");}rt.construct_lock(init,f)?;stdcall=12;},
  3|4=>e.events.push((kind,0)),
  5=>{let f=CrtCpu::pointer(arg(rt,0)?)?;let index=(f.address()-rt.file().address())/56;e.events.push((5,index));},
  6=>{let f=rt.offset(CrtCpu::pointer(arg(rt,0)?)?,-32)?;let index=(f.address()-rt.file().address())/56;e.events.push((6,index));rt.destroy_lock(init,f)?;stdcall=4;},
  _=>return Err("unbound effect"),
 }
 if cpu.pop(rt)?!=CrtValue::ProtectedReturn(u64::from(pc)){return Err("helper protected return");}cpu.discard(rt,stdcall)?;cpu.clobber(returned);Ok(())
}
fn setup()->(CrtStreamRuntime,CrtInitialization,CrtCpu){
 let(mut rt,init)=CrtStreamRuntime::new_initializing_array(7,9,0x41c080,3,65536).unwrap();
 let count=rt.map_region(0x41cd2c,8,CrtRegionKind::Module,Some(&[0;8])).unwrap();
 assert_eq!(count.address(),0x41cd2c);
 let dt=rt.map_region(0x41cf08,4,CrtRegionKind::Module,None).unwrap();
 let block=rt.map_region(0x9000,168,CrtRegionKind::Descriptor,None).unwrap();rt.store(dt,32,CrtValue::Pointer(block)).unwrap();
 let fd=rt.bind_descriptor(0,44).unwrap();
 for i in 0..3{let f=rt.offset(rt.file(),i*56).unwrap();rt.store(rt.offset(f,16).unwrap(),32,CrtValue::scalar(i as u32)).unwrap();let h=match i{0=>CrtValue::Handle(fd),1=>CrtValue::scalar(0),_=>CrtValue::scalar(u32::MAX-1)};rt.store(rt.offset(block,i*56+24).unwrap(),32,h).unwrap();}
 let stack=rt.map_region(0x70000000,256,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,224).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(7)).unwrap();let cpu=CrtCpu::new(sp,7).unwrap();(rt,init,cpu)
}
fn entry_again(rt:&mut CrtStreamRuntime)->CrtCpu{let sp=rt.resolve_absolute(0x700000e0,CrtRegionKind::Stack).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(8)).unwrap();CrtCpu::new(sp,8).unwrap()}
fn main(){
 for (availability,capacity,alloc_events) in [(vec![true],512,vec![(0,512),(1,0)]),(vec![false,true],3,vec![(0,512),(1,0),(0,3),(1,0)]),(vec![false,false],0,vec![(0,512),(1,0),(0,3),(1,0)])]{
  let(mut rt,init,mut cpu)=setup();let mut e=Effects{alloc:availability.into(),events:vec![],fail_lock:None};let result=initialize(&mut rt,&mut cpu,init,&mut e).unwrap().known_scalar().unwrap();
  if capacity==0{assert_eq!(result,u32::MAX);assert_eq!(e.events,alloc_events);assert!(rt.lock_objects.is_empty());assert_eq!(rt.load(rt.resolve_absolute(0x41cd30,CrtRegionKind::Module).unwrap(),32).unwrap(),CrtValue::scalar(0));continue;}
  assert_eq!(result,0);let mut expected=alloc_events;expected.extend([(2,0),(2,1),(2,2)]);assert_eq!(e.events,expected);assert_eq!(rt.lock_objects.len(),3);
  for (index,want) in [0,u32::MAX-1,u32::MAX-1].into_iter().enumerate(){assert_eq!(rt.load(rt.offset(rt.file(),index as i64*56+16).unwrap(),32).unwrap().known_scalar().unwrap(),want);}
  let saved_table=CrtCpu::pointer(rt.load(rt.resolve_absolute(0x41cd30,CrtRegionKind::Module).unwrap(),32).unwrap()).unwrap();e.events.clear();let mut cpu=entry_again(&mut rt);
  let result=if capacity==512{terminate512(&mut rt,&mut cpu,init,&mut e)}else{terminate3(&mut rt,&mut cpu,init,&mut e)}.unwrap();assert_eq!(result,CrtValue::Scalar{bits:0,known:0});
  assert_eq!(e.events,[(3,0),(4,0),(5,0),(6,0),(5,1),(6,1),(5,2),(6,2),(1,capacity)]);assert!(rt.load(saved_table,32).is_err());assert!(rt.lock_objects.is_empty());assert_eq!(rt.load(rt.resolve_absolute(0x41cd30,CrtRegionKind::Module).unwrap(),32).unwrap(),CrtValue::scalar(0));
 }
 for (count,want) in [(1u32,3),(9,9),(u32::MAX,3)]{let(mut rt,init,mut cpu)=setup();let p=rt.resolve_absolute(0x41cd2c,CrtRegionKind::Module).unwrap();rt.store(p,32,CrtValue::scalar(count)).unwrap();let mut e=Effects{alloc:vec![true].into(),events:vec![],fail_lock:None};let result=match count{1=>initialize_one(&mut rt,&mut cpu,init,&mut e),9=>initialize_nine(&mut rt,&mut cpu,init,&mut e),_=>initialize_negative(&mut rt,&mut cpu,init,&mut e)}.unwrap();assert_eq!(result,CrtValue::scalar(0));assert_eq!(e.events,[(0,want),(1,0),(2,0),(2,1),(2,2)]);}
 let(mut rt,init,mut cpu)=setup();let mut e=Effects{alloc:vec![true].into(),events:vec![],fail_lock:Some(1)};assert_eq!(initialize(&mut rt,&mut cpu,init,&mut e),Err("unclosed lock construction failure"));assert_eq!(rt.lock_objects.len(),1);assert_eq!(e.events,[(0,512),(1,0),(2,0),(2,1)]);
 // Proof preconditions fail before the first delegated effect.
 for fault in 0..4{let(mut rt,init,mut cpu)=setup();match fault{0=>{let p=rt.resolve_absolute(0x41cd2c,CrtRegionKind::Module).unwrap();rt.store(p,32,CrtValue::scalar(9)).unwrap();},1=>{let p=rt.offset(rt.file(),16).unwrap();rt.store(p,32,CrtValue::scalar(8)).unwrap();},2=>{let p=rt.resolve_absolute(0x9020,CrtRegionKind::Descriptor).unwrap();rt.store(rt.offset(p,-8).unwrap(),32,CrtValue::scalar(44)).unwrap();},_=>rt.end_initialization(init).unwrap()};let mut e=Effects{alloc:vec![true].into(),events:vec![],fail_lock:None};assert!(initialize(&mut rt,&mut cpu,init,&mut e).is_err());assert!(e.events.is_empty());}
}
"#;
        let programs = [
            make(Kind::Initialize, 0, "initialize"),
            make(Kind::Teardown, 512, "terminate512"),
            make(Kind::Teardown, 3, "terminate3"),
            make(Kind::Initialize, 1, "initialize_one"),
            make(Kind::Initialize, 9, "initialize_nine"),
            make(Kind::Initialize, u32::MAX, "initialize_negative"),
        ]
        .join("\n");
        let source = format!(
            "#![allow(dead_code)]\nmod guest_memory{{{memory}}}\n{}\n{}\n{programs}\n{helpers}",
            super::super::crt_stream_runtime::EMITTED_TYPES,
            super::super::crt_stream_cpu::EMITTED_TYPES
        );
        let dir =
            std::env::temp_dir().join(format!("w2l-crt-lifecycle-native-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("check.rs");
        let executable = dir.join(if cfg!(windows) { "check.exe" } else { "check" });
        std::fs::write(&file, source).unwrap();
        let built = std::process::Command::new("rustc")
            .args(["--edition=2021"])
            .arg(&file)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let run = std::process::Command::new(&executable).output().unwrap();
        assert!(
            run.status.success(),
            "{}",
            String::from_utf8_lossy(&run.stderr)
        );
    }
}
