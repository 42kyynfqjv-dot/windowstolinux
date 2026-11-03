//! Original FILE buffering instructions, with explicit callee effect obligations.
//!
//! These bounded certificates recognize normalized operations and typed field
//! roles, not executable names, hashes, or expected output bytes. Every original
//! node is emitted. Allocator/new-handler, descriptor EH4, temporary-buffer and
//! flush effects must be discharged by the enclosing compiler. This component
//! alone does not grant whole-program emission or infer allocator failure modes.
use super::crt_stream_ir::{Graph, Op, SignedCondition, Target};
use super::graph::{Address, Binary, Condition, Operand, Operation, Reg};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Body {
    Insert,
    Allocate,
    TemporaryFinish,
    Capacity,
    SlowInsert,
    TemporaryEligible,
    TemporaryBegin,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Effect {
    SlowInsert,
    Calloc,
    Free,
    Flush,
    FileNumber,
    LowWrite,
    Seek64,
    ReadModeCheck,
    TemporaryEligible,
    Allocate,
    Capacity,
    FileAccessor,
    Isatty,
    Malloc,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AbsoluteRole {
    AllocationCounter,
    DescriptorTable,
    InvalidDescriptor,
    StdoutCache,
    StderrCache,
}
#[derive(Clone, Debug)]
pub(crate) struct Bindings {
    pub calls: BTreeMap<Target, Effect>,
    pub absolute: BTreeMap<u32, AbsoluteRole>,
}
pub(crate) struct Proof {
    graph: Graph,
    bindings: Bindings,
    body: Body,
    allocation: u32,
    temporary_bytes: u32,
    call_depths: BTreeMap<u32, u32>,
}
impl Proof {
    pub fn graph(&self) -> &Graph {
        &self.graph
    }
    pub fn bindings(&self) -> &Bindings {
        &self.bindings
    }
    pub fn body(&self) -> Body {
        self.body
    }
    pub fn allocation(&self) -> u32 {
        self.allocation
    }
    pub fn temporary_bytes(&self) -> u32 {
        self.temporary_bytes
    }
    pub fn call_depths(&self) -> &BTreeMap<u32, u32> {
        &self.call_depths
    }
    pub fn emit(
        &self,
        name: &str,
        call: impl FnMut(u32, Target) -> Result<String, String>,
    ) -> Result<String, String> {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err("CRT buffer emitted name".into());
        }
        let roles = self
            .bindings
            .absolute
            .keys()
            .map(|&a| (a, "CrtRegionKind::Module".into()))
            .collect();
        let mut graph = self.graph.clone();
        for node in graph.nodes.values_mut() {
            if let Op::Ordinary(Operation::Binary(
                Binary::Move,
                Operand::Reg(dst),
                Operand::Immediate(address),
            )) = &node.op
            {
                if self.bindings.absolute.get(address).is_some_and(|r| {
                    matches!(r, AbsoluteRole::StdoutCache | AbsoluteRole::StderrCache)
                }) {
                    node.op = o(Operation::Address(*dst, addr(None, *address as i32)));
                }
            }
        }
        let body =
            super::crt_stream_emit::emit_body(&graph, call, &roles, self.graph.nodes.len() as u32)?;
        Ok(format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock,backend:&mut impl CrtBackend)->Result<CrtValue,&'static str>{{{}{body}}}",self.entry_source()))
    }
    /// Conditional component domain. Checks precede every original effect.
    /// They establish memory/ABI premises, not successful called API behavior.
    pub fn entry_source(&self) -> String {
        let (filearg, args) = match self.body {
            Body::Allocate | Body::TemporaryEligible | Body::TemporaryBegin => (4, 4),
            Body::Insert | Body::TemporaryFinish | Body::Capacity | Body::SlowInsert => (8, 12),
        };
        let mut s = format!(
            r#"
rt.check_lock(lease)?;
if cpu.returned||cpu.abi!=CrtAbi::Cdecl32Forward||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&i|cpu.r[i]!=cpu.entry[i]){{return Err("CRT buffer entry ABI");}}
let entry=CrtCpu::pointer(cpu.r[4])?;
if entry.kind!=CrtRegionKind::Stack||entry.address()%4!=0||rt.load(entry,32)?!=CrtValue::ProtectedReturn(cpu.return_id){{return Err("CRT buffer protected return");}}
let private=rt.offset(entry,-{depth}i64)?;rt.valid(private,{extent})?;
if rt.overlapping_tags(private.address(),{depth}).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_))){{return Err("CRT buffer scratch protected alias");}}
let file=CrtCpu::pointer(rt.load(rt.offset(entry,{filearg})?,32)?)?;rt.file_record(file)?;
if lease.record!=file.address(){{return Err("CRT buffer FILE lock identity");}}
let flags=rt.load(rt.offset(file,12)?,32)?.known_scalar()?;
"#,
            depth = self.temporary_bytes,
            extent = self.temporary_bytes + 4 + args
        );
        match self.body {
            Body::TemporaryEligible|Body::TemporaryBegin=>{},
            Body::Allocate=>s.push_str(r#"
if flags&0x4c0!=0||rt.load(file,32)?!=CrtValue::scalar(0)||rt.load(rt.offset(file,4)?,32)?!=CrtValue::scalar(0)||rt.load(rt.offset(file,8)?,32)?.known_scalar()?!=0{return Err("CRT ordinary allocation entry state");}
"#),
            Body::Insert=>s.push_str(r#"
let _character=rt.load(rt.offset(entry,4)?,8)?.known_scalar()?;
let context=CrtCpu::pointer(rt.load(rt.offset(entry,12)?,32)?)?;rt.validate_error_context(context)?;
let count=rt.load(rt.offset(file,8)?,32)?.known_scalar()?;
if count>16384{return Err("CRT buffer nonnegative remaining count domain");}
if count!=0{
 let cursor=CrtCpu::pointer(rt.load(file,32)?)?;let base=CrtCpu::pointer(rt.load(rt.offset(file,4)?,32)?)?;
 let capacity=rt.load(rt.offset(file,24)?,32)?.known_scalar()?;
 if flags&0xc0==0||capacity==0||capacity>16384||cursor.cap!=base.cap||cursor.address()<base.address()||u64::from(cursor.address())+u64::from(count)>u64::from(base.address())+u64::from(capacity){return Err("CRT insertion live buffer/count relation");}
 rt.valid(cursor,count)?;rt.valid(base,capacity)?;
 if base.kind!=CrtRegionKind::Buffer && !(base.kind==CrtRegionKind::File&&base.cap==file.cap&&base.address()==file.address()+20&&capacity<=2){return Err("CRT insertion protected buffer alias");}
 if !rt.overlapping_tags(cursor.address(),count).is_empty(){return Err("CRT insertion typed buffer alias");}
}
"#),
            Body::Capacity|Body::SlowInsert=>s.push_str(r#"
let _character=rt.load(rt.offset(entry,4)?,8)?.known_scalar()?;
let context=CrtCpu::pointer(rt.load(rt.offset(entry,12)?,32)?)?;rt.validate_error_context(context)?;
let fd=rt.load(rt.offset(file,16)?,32)?.known_scalar()?;
let id=rt.descriptors.iter().find(|d|d.live&&d.id.number==fd).map(|d|d.id).ok_or("CRT buffer descriptor domain")?;
rt.require_narrow_descriptor(id)?;
if flags&0xc0!=0{
 let cursor=CrtCpu::pointer(rt.load(file,32)?)?;let base=CrtCpu::pointer(rt.load(rt.offset(file,4)?,32)?)?;
 let capacity=rt.load(rt.offset(file,24)?,32)?.known_scalar()?;
 if capacity==0||capacity>16384||cursor.cap!=base.cap||cursor.address()<base.address()||u64::from(cursor.address())>u64::from(base.address())+u64::from(capacity){return Err("CRT capacity live buffer relation");}
 rt.valid(base,capacity)?;
 if base.kind!=CrtRegionKind::Buffer && !(base.kind==CrtRegionKind::File&&base.cap==file.cap&&base.address()==file.address()+20&&capacity<=2){return Err("CRT capacity protected buffer alias");}
 if !rt.overlapping_tags(base.address(),capacity).is_empty(){return Err("CRT capacity typed buffer alias");}
 for i in 0..cursor.address()-base.address(){rt.load(rt.offset(base,i64::from(i))?,8)?.known_scalar()?;}
}
"#),
            Body::TemporaryFinish=>s.push_str(r#"
let active=rt.load(rt.offset(entry,4)?,8)?.known_scalar()?;
if active!=0&&flags&0x200!=0{
 let context=CrtCpu::pointer(rt.load(rt.offset(entry,12)?,32)?)?;rt.validate_error_context(context)?;
 let cursor=CrtCpu::pointer(rt.load(file,32)?)?;let base=CrtCpu::pointer(rt.load(rt.offset(file,4)?,32)?)?;
 let capacity=rt.load(rt.offset(file,24)?,32)?.known_scalar()?;
 if capacity==0||capacity>16384||cursor.cap!=base.cap||cursor.address()<base.address()||u64::from(cursor.address())>u64::from(base.address())+u64::from(capacity){return Err("CRT temporary buffer extent");}
 rt.valid(base,capacity)?;
 if base.kind!=CrtRegionKind::Buffer && !(base.kind==CrtRegionKind::File&&base.cap==file.cap&&base.address()==file.address()+20&&capacity<=2){return Err("CRT temporary protected buffer alias");}
 let used=cursor.address()-base.address();if !rt.overlapping_tags(base.address(),capacity).is_empty(){return Err("CRT temporary typed buffer alias");}
 for i in 0..used{rt.load(rt.offset(base,i64::from(i))?,8)?.known_scalar()?;}
}
"#),
        }
        for (&address, role) in &self.bindings.absolute {
            match role{
 AbsoluteRole::AllocationCounter=>s.push_str(&format!("let counter=rt.resolve_absolute({address},CrtRegionKind::Module)?;rt.load(counter,32)?.known_scalar()?;")),
 AbsoluteRole::DescriptorTable=>s.push_str(&format!("let table=rt.resolve_absolute({address},CrtRegionKind::Module)?;let word=rt.load(rt.offset(table,i64::from(fd/64)*4)?,32)?;let block=CrtCpu::pointer(word)?;let record=rt.offset(block,i64::from(fd%64)*56)?;if record!=rt.descriptor_record(id)?{{return Err(\"CRT capacity descriptor table identity\");}}")),
 AbsoluteRole::InvalidDescriptor=>{},
 AbsoluteRole::StdoutCache|AbsoluteRole::StderrCache=>s.push_str(&format!("let cell=rt.resolve_absolute({address},CrtRegionKind::Module)?;match rt.load(cell,32)?{{CrtValue::Scalar{{bits:0,known:u32::MAX}}=>{{}},CrtValue::Pointer(buffer)=>{{if buffer.kind!=CrtRegionKind::Buffer{{return Err(\"CRT temporary cache ownership\");}}rt.valid(buffer,{allocation})?;if !rt.overlapping_tags(buffer.address(),{allocation}).is_empty(){{return Err(\"CRT temporary cache typed alias\");}}}},_=>return Err(\"CRT unknown temporary buffer cache\")}}",allocation=self.allocation)),
 }
        }
        s
    }
}
fn reg(index: u8) -> Reg {
    Reg {
        index,
        width: 32,
        shift: 0,
    }
}
fn r(index: u8) -> Operand {
    Operand::Reg(reg(index))
}
fn byte(index: u8) -> Operand {
    Operand::Reg(Reg {
        index,
        width: 8,
        shift: 0,
    })
}
fn imm(n: u32) -> Operand {
    Operand::Immediate(n)
}
fn addr(base: Option<u8>, offset: i32) -> Address {
    Address {
        base,
        index: None,
        scale: 1,
        displacement: offset as u32,
    }
}
fn m(index: u8, offset: i32) -> Operand {
    Operand::Memory(addr(Some(index), offset), 32)
}
fn mb(index: u8, offset: i32) -> Operand {
    Operand::Memory(addr(Some(index), offset), 8)
}
fn abs(n: u32) -> Operand {
    Operand::Memory(addr(None, n as i32), 32)
}
fn o(op: Operation) -> Op {
    Op::Ordinary(op)
}
fn bin(b: Binary, a: Operand, c: Operand) -> Op {
    o(Operation::Binary(b, a, c))
}
fn mov(a: Operand, b: Operand) -> Op {
    bin(Binary::Move, a, b)
}
fn push(a: Operand) -> Op {
    o(Operation::Push(a))
}
fn pop(i: u8) -> Op {
    o(Operation::Pop(reg(i)))
}
fn call(ops: &[&Op], i: usize, e: Effect, b: &Bindings) -> Result<Op, String> {
    match ops.get(i) {
        Some(Op::Call(t)) if b.calls.get(t) == Some(&e) => Ok(Op::Call(*t)),
        _ => Err(format!("CRT buffer unbound original call {i} {e:?}")),
    }
}
fn locked(b: Binary, base: u8, source: u8) -> Op {
    Op::Locked {
        operation: b,
        destination: m(base, 0),
        source: r(source),
    }
}
fn same(graph: &Graph, expected: &[Op]) -> Result<(), String> {
    if graph.nodes.len() != expected.len() {
        return Err("CRT buffer complete graph extent".into());
    }
    for ((&pc, node), op) in graph.nodes.iter().zip(expected) {
        if node.op != *op {
            return Err(format!("CRT buffer original effect {pc:#x}: {:?}", node.op));
        }
    }
    Ok(())
}
/// Complete decoded graph and bounded protected stack/call shape. Calls have no
/// implicit cleanup here; each original body is cdecl and cleans its arguments.
fn stack_shape(graph: &Graph) -> Result<(u32, BTreeMap<u32, u32>), String> {
    fn acyclic(
        pc: u32,
        graph: &Graph,
        active: &mut BTreeSet<u32>,
        done: &mut BTreeSet<u32>,
    ) -> Result<(), String> {
        if done.contains(&pc) {
            return Ok(());
        }
        if !active.insert(pc) {
            return Err("CRT buffer cyclic graph outside finite contract".into());
        }
        for &n in &graph.nodes[&pc].successors {
            acyclic(n, graph, active, done)?;
        }
        active.remove(&pc);
        done.insert(pc);
        Ok(())
    }
    acyclic(
        graph.origin,
        graph,
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
    )?;
    let mut todo = vec![(graph.origin, 0i32, None)];
    let mut states = BTreeMap::new();
    let mut maximum = 0u32;
    let mut calls = BTreeMap::new();
    while let Some((pc, mut depth, mut bp)) = todo.pop() {
        if let Some(old) = states.insert(pc, (depth, bp)) {
            if old != (depth, bp) {
                return Err("CRT buffer ambiguous stack join".into());
            }
            continue;
        }
        let node = &graph.nodes[&pc];
        match &node.op {
            Op::Ordinary(Operation::Push(_)) => depth += 4,
            Op::Ordinary(Operation::Pop(_)) => depth -= 4,
            Op::Ordinary(Operation::Binary(
                Binary::Move,
                Operand::Reg(Reg {
                    index: 5,
                    width: 32,
                    shift: 0,
                }),
                Operand::Reg(Reg {
                    index: 4,
                    width: 32,
                    shift: 0,
                }),
            )) => bp = Some(depth),
            Op::Ordinary(Operation::Binary(
                Binary::Add,
                Operand::Reg(Reg {
                    index: 4,
                    width: 32,
                    shift: 0,
                }),
                Operand::Immediate(n),
            )) => depth -= i32::try_from(*n).map_err(|_| "CRT buffer stack cleanup overflow")?,
            Op::Call(_) => {
                calls.insert(
                    pc,
                    u32::try_from(depth + 4).map_err(|_| "CRT buffer CALL depth")?,
                );
                maximum = maximum.max((depth + 4) as u32);
            }
            Op::Ordinary(Operation::Return) if depth != 0 => {
                return Err("CRT buffer unbalanced original return".into());
            }
            _ => {}
        }
        if !(0..=256).contains(&depth) {
            return Err("CRT buffer bounded stack".into());
        }
        maximum = maximum.max(depth as u32);
        for &next in &node.successors {
            todo.push((next, depth, bp));
        }
    }
    Ok((maximum, calls))
}
pub(crate) fn prove(
    code: &[u8],
    origin: u32,
    body: Body,
    bindings: Bindings,
) -> Result<Proof, String> {
    let graph = Graph::decode(code, origin)?;
    let pcs: Vec<_> = graph.nodes.keys().copied().collect();
    let ops: Vec<_> = graph.nodes.values().map(|n| &n.op).collect();
    let at = |n: usize| pcs.get(n).copied().ok_or("CRT buffer graph index");
    let mut allocation = 0;
    let expected = match body {
        Body::Insert => {
            if ops.len() != 20 {
                return Err("CRT insertion complete graph".into());
            }
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                mov(r(2), m(5, 12)),
                bin(Binary::Sub, m(2, 8), imm(1)),
                Op::SignedBranch {
                    condition: SignedCondition::NotSign,
                    target: at(13)?,
                },
                push(m(5, 16)),
                push(r(2)),
                push(m(5, 8)),
                call(&ops, 9, Effect::SlowInsert, &bindings)?,
                bin(Binary::Add, r(4), imm(12)),
                pop(5),
                o(Operation::Return),
                mov(r(0), m(2, 0)),
                mov(byte(1), mb(5, 8)),
                mov(mb(0, 0), byte(1)),
                Op::IncrementMemory(m(2, 0)),
                o(Operation::ZeroExtend(reg(0), byte(1))),
                pop(5),
                o(Operation::Return),
            ]
        }
        Body::Allocate => {
            if ops.len() != 36 {
                return Err("CRT allocation complete graph".into());
            }
            let counter = match ops[3] {
                Op::IncrementMemory(Operand::Memory(a, 32))
                    if a.base.is_none() && a.index.is_none() =>
                {
                    a.displacement
                }
                _ => return Err("CRT allocation original counter".into()),
            };
            if !counter.is_multiple_of(4)
                || bindings.absolute != BTreeMap::from([(counter, AbsoluteRole::AllocationCounter)])
            {
                return Err("CRT allocation counter ownership binding".into());
            }
            allocation = match ops[8] {
                Op::Ordinary(Operation::Binary(
                    Binary::Move,
                    Operand::Reg(Reg {
                        index: 7,
                        width: 32,
                        shift: 0,
                    }),
                    Operand::Immediate(n),
                )) if (4..=16384).contains(n) => *n,
                _ => return Err("CRT allocation bounded size".into()),
            };
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                Op::IncrementMemory(abs(counter)),
                push(r(6)),
                mov(r(6), m(5, 8)),
                push(r(7)),
                push(imm(1)),
                mov(r(7), imm(allocation)),
                push(r(7)),
                call(&ops, 10, Effect::Calloc, &bindings)?,
                push(imm(0)),
                mov(m(6, 4), r(0)),
                call(&ops, 13, Effect::Free, &bindings)?,
                bin(Binary::Add, r(4), imm(12)),
                o(Operation::Address(reg(0), addr(Some(6), 12))),
                bin(Binary::Compare, m(6, 4), imm(0)),
                o(Operation::Branch(Condition::Equal, at(22)?)),
                push(imm(64)),
                pop(1),
                locked(Binary::Or, 0, 1),
                o(Operation::Jump(at(28)?)),
                mov(r(1), imm(1024)),
                locked(Binary::Or, 0, 1),
                o(Operation::Address(reg(0), addr(Some(6), 20))),
                push(imm(2)),
                mov(m(6, 4), r(0)),
                pop(7),
                mov(m(6, 24), r(7)),
                mov(r(0), m(6, 4)),
                bin(Binary::And, m(6, 8), imm(0)),
                pop(7),
                mov(m(6, 0), r(0)),
                pop(6),
                pop(5),
                o(Operation::Return),
            ]
        }

        Body::Capacity => {
            if ops.len() != 87 {
                return Err("CRT capacity complete graph".into());
            }
            let table = match ops[51] {
                Op::Ordinary(Operation::Binary(Binary::Add, _, Operand::Memory(a, 32)))
                    if a.base.is_none() && a.index == Some(1) && a.scale == 4 =>
                {
                    a.displacement
                }
                _ => return Err("CRT capacity descriptor table operand".into()),
            };
            let invalid = match ops[53] {
                Op::Ordinary(Operation::Binary(Binary::Move, _, Operand::Immediate(a))) => *a,
                _ => return Err("CRT capacity invalid descriptor operand".into()),
            };
            if !table.is_multiple_of(4)
                || !invalid.is_multiple_of(4)
                || table == invalid
                || bindings.absolute
                    != BTreeMap::from([
                        (table, AbsoluteRole::DescriptorTable),
                        (invalid, AbsoluteRole::InvalidDescriptor),
                    ])
            {
                return Err("CRT capacity absolute ownership binding".into());
            }
            let br = |c, i| Ok::<_, String>(o(Operation::Branch(c, at(i)?)));
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                push(r(6)),
                push(r(7)),
                push(m(5, 12)),
                call(&ops, 6, Effect::FileNumber, &bindings)?,
                pop(1),
                mov(r(1), m(5, 12)),
                mov(r(2), r(0)),
                mov(r(1), m(1, 12)),
                o(Operation::Nop),
                bin(Binary::Test, byte(1), imm(0xc0)),
                br(Condition::Equal, 72)?,
                mov(r(1), m(5, 12)),
                bin(Binary::Xor, r(7), r(7)),
                mov(r(0), m(1, 4)),
                mov(r(6), m(1, 0)),
                bin(Binary::Sub, r(6), r(0)),
                o(Operation::Increment(reg(0))),
                mov(m(1, 0), r(0)),
                mov(r(0), m(5, 12)),
                mov(r(1), m(0, 24)),
                o(Operation::Decrement(reg(1))),
                mov(m(0, 8), r(1)),
                bin(Binary::Test, r(6), r(6)),
                Op::SignedBranch {
                    condition: SignedCondition::LessEqual,
                    target: at(42)?,
                },
                push(m(5, 16)),
                mov(r(0), m(5, 12)),
                push(r(6)),
                push(m(0, 4)),
                push(r(2)),
                call(&ops, 32, Effect::LowWrite, &bindings)?,
                bin(Binary::Add, r(4), imm(16)),
                mov(r(7), r(0)),
                mov(r(1), m(5, 12)),
                bin(Binary::Compare, r(7), r(6)),
                mov(byte(0), mb(5, 8)),
                mov(r(1), m(1, 4)),
                mov(mb(1, 0), byte(0)),
                o(Operation::Set(
                    Condition::Equal,
                    Reg {
                        index: 0,
                        width: 8,
                        shift: 0,
                    },
                )),
                o(Operation::Jump(at(83)?)),
                bin(Binary::Compare, r(2), imm(u32::MAX)),
                br(Condition::Equal, 53)?,
                bin(Binary::Compare, r(2), imm(u32::MAX - 1)),
                br(Condition::Equal, 53)?,
                mov(r(0), r(2)),
                mov(r(1), r(2)),
                bin(Binary::And, r(0), imm(63)),
                Op::ArithmeticShift {
                    dst: reg(1),
                    count: 6,
                },
                Op::Multiply {
                    dst: reg(0),
                    source: r(0),
                    factor: 56,
                },
                bin(
                    Binary::Add,
                    r(0),
                    Operand::Memory(
                        Address {
                            base: None,
                            index: Some(1),
                            scale: 4,
                            displacement: table,
                        },
                        32,
                    ),
                ),
                o(Operation::Jump(at(54)?)),
                mov(r(0), imm(invalid)),
                bin(Binary::Test, mb(0, 40), imm(32)),
                br(Condition::Equal, 35)?,
                push(imm(2)),
                push(r(7)),
                push(r(7)),
                push(r(2)),
                call(&ops, 60, Effect::Seek64, &bindings)?,
                bin(Binary::And, r(0), r(2)),
                bin(Binary::Add, r(4), imm(16)),
                bin(Binary::Compare, r(0), imm(u32::MAX)),
                br(Condition::NotEqual, 35)?,
                mov(r(0), m(5, 12)),
                push(imm(16)),
                pop(1),
                bin(Binary::Add, r(0), imm(12)),
                locked(Binary::Or, 0, 1),
                mov(byte(0), imm(1)),
                o(Operation::Jump(at(83)?)),
                push(m(5, 16)),
                o(Operation::Address(reg(0), addr(Some(5), 8))),
                push(imm(1)),
                push(r(0)),
                push(r(2)),
                call(&ops, 77, Effect::LowWrite, &bindings)?,
                bin(Binary::Add, r(4), imm(16)),
                o(Operation::Decrement(reg(0))),
                o(Operation::Negate(reg(0))),
                bin(Binary::Sbb, byte(0), byte(0)),
                o(Operation::Increment(Reg {
                    index: 0,
                    width: 8,
                    shift: 0,
                })),
                pop(7),
                pop(6),
                pop(5),
                o(Operation::Return),
            ]
        }
        Body::SlowInsert => {
            if ops.len() != 96 {
                return Err("CRT slow insertion complete graph".into());
            }
            let br = |c, i| Ok::<_, String>(o(Operation::Branch(c, at(i)?)));
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                push(m(5, 12)),
                call(&ops, 4, Effect::FileNumber, &bindings)?,
                mov(r(0), m(5, 12)),
                pop(1),
                mov(r(0), m(0, 12)),
                o(Operation::Nop),
                bin(Binary::Test, byte(0), imm(6)),
                br(Condition::NotEqual, 22)?,
                mov(r(0), m(5, 16)),
                mov(m(0, 24), imm(9)),
                mov(mb(0, 28), imm(1)),
                mov(r(0), m(5, 12)),
                push(imm(16)),
                pop(1),
                bin(Binary::Add, r(0), imm(12)),
                locked(Binary::Or, 0, 1),
                bin(Binary::Or, r(0), imm(u32::MAX)),
                pop(5),
                o(Operation::Return),
                mov(r(0), m(5, 12)),
                mov(r(0), m(0, 12)),
                o(Operation::Nop),
                o(Operation::Shift {
                    left: false,
                    dst: reg(0),
                    count: 12,
                }),
                bin(Binary::Test, byte(0), imm(1)),
                br(Condition::Equal, 31)?,
                mov(r(0), m(5, 16)),
                mov(m(0, 24), imm(34)),
                o(Operation::Jump(at(13)?)),
                mov(r(0), m(5, 12)),
                mov(r(0), m(0, 12)),
                o(Operation::Nop),
                bin(Binary::Test, byte(0), imm(1)),
                br(Condition::Equal, 51)?,
                push(m(5, 12)),
                call(&ops, 37, Effect::ReadModeCheck, &bindings)?,
                pop(1),
                mov(r(1), m(5, 12)),
                bin(Binary::And, m(1, 8), imm(0)),
                bin(Binary::Test, byte(0), byte(0)),
                mov(r(0), m(5, 12)),
                br(Condition::Equal, 15)?,
                mov(r(1), m(0, 4)),
                mov(m(0, 0), r(1)),
                mov(r(0), m(5, 12)),
                push(imm(u32::MAX - 1)),
                pop(1),
                bin(Binary::Add, r(0), imm(12)),
                locked(Binary::And, 0, 1),
                mov(r(0), m(5, 12)),
                push(imm(2)),
                pop(1),
                bin(Binary::Add, r(0), imm(12)),
                locked(Binary::Or, 0, 1),
                mov(r(0), m(5, 12)),
                push(imm(u32::MAX - 8)),
                pop(1),
                bin(Binary::Add, r(0), imm(12)),
                locked(Binary::And, 0, 1),
                mov(r(0), m(5, 12)),
                bin(Binary::And, m(0, 8), imm(0)),
                mov(r(0), m(5, 12)),
                mov(r(0), m(0, 12)),
                o(Operation::Nop),
                bin(Binary::Test, r(0), imm(0x4c0)),
                br(Condition::NotEqual, 76)?,
                push(m(5, 12)),
                call(&ops, 69, Effect::TemporaryEligible, &bindings)?,
                pop(1),
                bin(Binary::Test, byte(0), byte(0)),
                br(Condition::NotEqual, 76)?,
                push(m(5, 12)),
                call(&ops, 74, Effect::Allocate, &bindings)?,
                pop(1),
                push(r(3)),
                push(m(5, 16)),
                mov(r(3), m(5, 8)),
                push(m(5, 12)),
                push(r(3)),
                call(&ops, 81, Effect::Capacity, &bindings)?,
                bin(Binary::Add, r(4), imm(12)),
                bin(Binary::Test, byte(0), byte(0)),
                br(Condition::NotEqual, 92)?,
                mov(r(0), m(5, 12)),
                push(imm(16)),
                pop(1),
                bin(Binary::Add, r(0), imm(12)),
                locked(Binary::Or, 0, 1),
                bin(Binary::Or, r(0), imm(u32::MAX)),
                o(Operation::Jump(at(93)?)),
                o(Operation::ZeroExtend(reg(0), byte(3))),
                pop(3),
                pop(5),
                o(Operation::Return),
            ]
        }

        Body::TemporaryEligible => {
            if ops.len() != 29 {
                return Err("CRT temporary predicate complete graph".into());
            }
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                push(imm(2)),
                call(&ops, 4, Effect::FileAccessor, &bindings)?,
                pop(1),
                bin(Binary::Compare, m(5, 8), r(0)),
                o(Operation::Branch(Condition::Equal, at(26)?)),
                push(imm(1)),
                call(&ops, 9, Effect::FileAccessor, &bindings)?,
                pop(1),
                bin(Binary::Compare, m(5, 8), r(0)),
                o(Operation::Branch(Condition::NotEqual, at(23)?)),
                push(m(5, 8)),
                call(&ops, 14, Effect::FileNumber, &bindings)?,
                push(r(0)),
                call(&ops, 16, Effect::Isatty, &bindings)?,
                bin(Binary::Test, r(0), r(0)),
                pop(1),
                pop(1),
                o(Operation::Set(
                    Condition::NotEqual,
                    Reg {
                        index: 0,
                        width: 8,
                        shift: 0,
                    },
                )),
                pop(5),
                o(Operation::Return),
                bin(Binary::Xor, byte(0), byte(0)),
                pop(5),
                o(Operation::Return),
                mov(byte(0), imm(1)),
                pop(5),
                o(Operation::Return),
            ]
        }
        Body::TemporaryBegin => {
            if ops.len() != 66 {
                return Err("CRT temporary setup complete graph".into());
            }
            let absolute_imm = |i: usize| match ops[i] {
                Op::Ordinary(Operation::Binary(
                    Binary::Move,
                    Operand::Reg(Reg {
                        index: 7,
                        width: 32,
                        shift: 0,
                    }),
                    Operand::Immediate(n),
                )) => Ok(*n),
                _ => Err("CRT temporary cache operand"),
            };
            let stdout = absolute_imm(19)?;
            let stderr = absolute_imm(26)?;
            let counter = match ops[27] {
                Op::IncrementMemory(Operand::Memory(a, 32))
                    if a.base.is_none() && a.index.is_none() =>
                {
                    a.displacement
                }
                _ => return Err("CRT temporary counter operand".into()),
            };
            let addresses = [stdout, stderr, counter];
            if addresses.iter().any(|a| !a.is_multiple_of(4))
                || addresses.iter().collect::<BTreeSet<_>>().len() != 3
                || bindings.absolute
                    != BTreeMap::from([
                        (stdout, AbsoluteRole::StdoutCache),
                        (stderr, AbsoluteRole::StderrCache),
                        (counter, AbsoluteRole::AllocationCounter),
                    ])
            {
                return Err("CRT temporary absolute bindings/alias".into());
            }
            allocation = match ops[37] {
                Op::Ordinary(Operation::Push(Operand::Immediate(n))) if (4..=16384).contains(n) => {
                    *n
                }
                _ => return Err("CRT temporary allocation bound".into()),
            };
            let br = |c, i| Ok::<_, String>(o(Operation::Branch(c, at(i)?)));
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                push(r(3)),
                push(r(6)),
                mov(r(6), m(5, 8)),
                push(r(7)),
                push(r(6)),
                call(&ops, 8, Effect::TemporaryEligible, &bindings)?,
                pop(1),
                bin(Binary::Test, byte(0), byte(0)),
                br(Condition::Equal, 60)?,
                push(imm(1)),
                call(&ops, 13, Effect::FileAccessor, &bindings)?,
                pop(1),
                push(imm(2)),
                pop(3),
                bin(Binary::Compare, r(6), r(0)),
                br(Condition::NotEqual, 21)?,
                mov(r(7), imm(stdout)),
                o(Operation::Jump(at(27)?)),
                push(r(3)),
                call(&ops, 22, Effect::FileAccessor, &bindings)?,
                pop(1),
                bin(Binary::Compare, r(6), r(0)),
                br(Condition::NotEqual, 60)?,
                mov(r(7), imm(stderr)),
                Op::IncrementMemory(abs(counter)),
                o(Operation::Address(reg(1), addr(Some(6), 12))),
                mov(r(0), m(1, 0)),
                o(Operation::Nop),
                bin(Binary::Test, r(0), imm(0x4c0)),
                br(Condition::NotEqual, 60)?,
                mov(r(0), imm(0x282)),
                locked(Binary::Or, 1, 0),
                bin(Binary::Compare, m(7, 0), imm(0)),
                br(Condition::NotEqual, 44)?,
                push(imm(allocation)),
                call(&ops, 38, Effect::Malloc, &bindings)?,
                push(imm(0)),
                mov(m(7, 0), r(0)),
                call(&ops, 41, Effect::Free, &bindings)?,
                pop(1),
                pop(1),
                mov(r(1), m(7, 0)),
                bin(Binary::Test, r(1), r(1)),
                br(Condition::NotEqual, 54)?,
                o(Operation::Address(reg(1), addr(Some(6), 20))),
                mov(m(6, 8), r(3)),
                mov(m(6, 4), r(1)),
                mov(m(6, 0), r(1)),
                mov(m(6, 24), r(3)),
                mov(byte(0), imm(1)),
                o(Operation::Jump(at(61)?)),
                mov(m(6, 4), r(1)),
                mov(r(0), m(7, 0)),
                mov(m(6, 0), r(0)),
                mov(m(6, 8), imm(allocation)),
                mov(m(6, 24), imm(allocation)),
                o(Operation::Jump(at(52)?)),
                bin(Binary::Xor, byte(0), byte(0)),
                pop(7),
                pop(6),
                pop(3),
                pop(5),
                o(Operation::Return),
            ]
        }
        Body::TemporaryFinish => {
            if ops.len() != 29 {
                return Err("CRT temporary completion complete graph".into());
            }
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                bin(Binary::Compare, mb(5, 8), imm(0)),
                o(Operation::Branch(Condition::Equal, at(27)?)),
                push(r(6)),
                mov(r(6), m(5, 12)),
                push(r(7)),
                o(Operation::Address(reg(7), addr(Some(6), 12))),
                mov(r(0), m(7, 0)),
                o(Operation::Nop),
                o(Operation::Shift {
                    left: false,
                    dst: reg(0),
                    count: 9,
                }),
                bin(Binary::Test, byte(0), imm(1)),
                o(Operation::Branch(Condition::Equal, at(25)?)),
                push(m(5, 16)),
                push(r(6)),
                call(&ops, 16, Effect::Flush, &bindings)?,
                pop(1),
                pop(1),
                mov(r(0), imm(0xfffffd7f)),
                Op::Locked {
                    operation: Binary::And,
                    destination: m(7, 0),
                    source: r(0),
                },
                bin(Binary::Xor, r(0), r(0)),
                mov(m(6, 24), r(0)),
                mov(m(6, 4), r(0)),
                mov(m(6, 0), r(0)),
                pop(7),
                pop(6),
                pop(5),
                o(Operation::Return),
            ]
        }
    };
    same(&graph, &expected)?;
    let used = graph.calls();
    if used != bindings.calls.keys().copied().collect::<BTreeSet<_>>() {
        return Err("CRT buffer unused/missing original call binding".into());
    }
    if !matches!(body, Body::Allocate | Body::Capacity | Body::TemporaryBegin)
        && !bindings.absolute.is_empty()
    {
        return Err("CRT buffer unused absolute binding".into());
    }
    let (temporary_bytes, call_depths) = stack_shape(&graph)?;
    Ok(Proof {
        graph,
        bindings,
        body,
        allocation,
        temporary_bytes,
        call_depths,
    })
}

/// A real tail edge preserves the caller's existing return token. It is not a
/// CALL to the target and cannot manufacture a second saved return address.
pub(crate) struct TailProof {
    target: u32,
    origin: u32,
}
impl TailProof {
    pub(crate) fn target(&self) -> u32 {
        self.target
    }
    pub(crate) fn origin(&self) -> u32 {
        self.origin
    }
    pub(crate) fn temporary_bytes(&self) -> u32 {
        4
    }
    pub(crate) fn emit(&self, name: &str, target_name: &str) -> Result<String, String> {
        if [name, target_name]
            .iter()
            .any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        {
            return Err("CRT tail emitted name".into());
        }
        Ok(format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock,backend:&mut impl CrtBackend)->Result<CrtValue,&'static str>{{rt.check_lock(lease)?;let original_edi=cpu.r[7];cpu.r[7]=original_edi;cpu.push(rt,cpu.r[5])?;cpu.r[5]=cpu.r[4];cpu.r[5]=cpu.pop(rt)?;{target_name}(rt,cpu,lease,backend)}}"))
    }
}
pub(crate) fn prove_tail(code: &[u8], origin: u32, target: u32) -> Result<TailProof, String> {
    use iced_x86::{Decoder, DecoderOptions};
    if origin == 0
        || target == 0
        || origin.checked_add(code.len() as u32).is_none()
        || code.len() > 32
    {
        return Err("CRT tail source bounds".into());
    }
    let mut decoder = Decoder::with_ip(32, code, u64::from(origin), DecoderOptions::NONE);
    let mut ops = Vec::new();
    while decoder.can_decode() {
        let before = decoder.position();
        let ins = decoder.decode();
        if ins.is_invalid() {
            return Err("CRT tail invalid original instruction".into());
        }
        ops.push(super::graph::normalized(
            &ins,
            &code[before..decoder.position()],
        )?);
    }
    if ops
        != vec![
            Operation::Binary(Binary::Move, r(7), r(7)),
            Operation::Push(r(5)),
            Operation::Binary(Binary::Move, r(5), r(4)),
            Operation::Pop(reg(5)),
            Operation::Jump(target),
        ]
    {
        return Err("CRT tail original ABI effects/target".into());
    }
    Ok(TailProof { target, origin })
}

#[cfg(test)]
mod tests {
    use super::*;
    const INSERT:&str="8bff558bec8b550c836a08017911ff751052ff7508e83963000083c40c5dc38b028a4d088808ff020fb6c15dc3";
    const ALLOCATE:&str="8bff558becff0534cd4100568b7508576a01bf0010000057e8ea5effff6a00894604e8405fffff83c40c8d460c837e040074086a4059f00908eb11b900040000f009088d46146a028946045f897e188b4604836608005f89065e5dc3";
    const TEMP_FINISH:&str="8bff558bec807d08007431568b750c578d7e0c8b0790c1e809a801741dff751056e83de5ffff5959b87ffdfffff0210733c089461889460489065f5e5dc3";
    const CAPACITY:&str="8bff558bec5657ff750ce8c39dffff598b4d0c8bd08b490c90f6c1c00f84930000008b4d0c33ff8b41048b312bf04089018b450c8b48184989480885f67e27ff75108b450c56ff700452e834dfffff83c4108bf88b4d0c3bfe8a45088b490488010f94c0eb6883faff741b83fafe74168bc28bca83e03fc1f9066bc03803048d08cf4100eb05b838c14100f640282074c36a02575752e83512000023c283c41083f8ff75af8b450c6a105983c00cf00908b001eb19ff75108d45086a015052e8bfdeffff83c41048f7d81ac0fec05f5e5dc3";
    const SLOW:&str="8bff558becff750ce8bb9effff8b450c598b400c90a806751f8b4510c7401809000000c6401c018b450c6a105983c00cf0090883c8ff5dc38b450c8b400c90c1e80ca801740c8b4510c7401822000000ebd18b450c8b400c90a8017428ff750ce863010000598b4d0c8361080084c08b450c74b68b480489088b450c6afe5983c00cf021088b450c6a025983c00cf009088b450c6af75983c00cf021088b450c836008008b450c8b400c90a9c00400007516ff750ce8779effff5984c07509ff750ce87f1e00005953ff75108b5d08ff750c53e81e00000083c40c84c075118b450c6a105983c00cf0090883c8ffeb030fb6c35b5dc3";
    const ELIGIBLE:&str="8bff558bec6a02e8f8a7ffff5939450874286a01e8eba7ffff593945087517ff7508e870ffffff50e80463000085c059590f95c05dc332c05dc3b0015dc3";
    const TEMP_BEGIN:&str="8bff558bec53568b75085756e8b1ffffff5984c00f848a0000006a01e8a5a7ffff596a025b3bf07507bf28d14100eb1053e890a7ffff593bf07569bf2cd14100ff0534cd41008d4e0c8b0190a9c00400007551b882020000f00901833f0075156800100000e8b4e8ffff6a008907e8cbdeffff59598b0f85c975128d4e14895e08894e04890e895e18b001eb19894e048b078906c7460800100000c7461800100000ebe532c05f5e5b5dc3";
    fn bytes(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
    fn binding(body: Body) -> Bindings {
        Bindings {
            calls: match body {
                Body::Insert => BTreeMap::from([(Target::Direct(0x4100fa), Effect::SlowInsert)]),
                Body::Allocate => BTreeMap::from([
                    (Target::Direct(0x407cf0), Effect::Calloc),
                    (Target::Direct(0x407d50), Effect::Free),
                ]),
                Body::TemporaryFinish => {
                    BTreeMap::from([(Target::Direct(0x408420), Effect::Flush)])
                }
                Body::Capacity => BTreeMap::from([
                    (Target::Direct(0x409d6b), Effect::FileNumber),
                    (Target::Direct(0x40df1c), Effect::LowWrite),
                    (Target::Direct(0x411269), Effect::Seek64),
                ]),
                Body::TemporaryEligible => BTreeMap::from([
                    (Target::Direct(0x4045d8), Effect::FileAccessor),
                    (Target::Direct(0x409d6b), Effect::FileNumber),
                    (Target::Direct(0x410105), Effect::Isatty),
                ]),
                Body::TemporaryBegin => BTreeMap::from([
                    (Target::Direct(0x409dd4), Effect::TemporaryEligible),
                    (Target::Direct(0x4045d8), Effect::FileAccessor),
                    (Target::Direct(0x408730), Effect::Malloc),
                    (Target::Direct(0x407d50), Effect::Free),
                ]),
                Body::SlowInsert => BTreeMap::from([
                    (Target::Direct(0x409d6b), Effect::FileNumber),
                    (Target::Direct(0x41006b), Effect::ReadModeCheck),
                    (Target::Direct(0x409dd4), Effect::TemporaryEligible),
                    (Target::Direct(0x411de9), Effect::Allocate),
                    (Target::Direct(0x40ff99), Effect::Capacity),
                ]),
            },
            absolute: if body == Body::Allocate {
                BTreeMap::from([(0x41cd34, AbsoluteRole::AllocationCounter)])
            } else if body == Body::TemporaryBegin {
                BTreeMap::from([
                    (0x41cd34, AbsoluteRole::AllocationCounter),
                    (0x41d128, AbsoluteRole::StdoutCache),
                    (0x41d12c, AbsoluteRole::StderrCache),
                ])
            } else if body == Body::Capacity {
                BTreeMap::from([
                    (0x41cf08, AbsoluteRole::DescriptorTable),
                    (0x41c138, AbsoluteRole::InvalidDescriptor),
                ])
            } else {
                BTreeMap::new()
            },
        }
    }
    #[test]
    fn complete_original_graphs_preserve_calls_and_stack_bounds() {
        for (body, hex, origin, depth) in [
            (Body::Insert, INSERT, 0x409da7, 20),
            (Body::Allocate, ALLOCATE, 0x411de9, 28),
            (Body::TemporaryFinish, TEMP_FINISH, 0x409ebd, 24),
            (Body::Capacity, CAPACITY, 0x40ff99, 32),
            (Body::SlowInsert, SLOW, 0x40fea3, 24),
            (Body::TemporaryEligible, ELIGIBLE, 0x409dd4, 16),
            (Body::TemporaryBegin, TEMP_BEGIN, 0x409e12, 28),
        ] {
            let p = prove(&bytes(hex), origin, body, binding(body)).unwrap();
            assert_eq!(p.temporary_bytes(), depth);
            assert!(!p.call_depths().is_empty());
            assert!(p.emit("original", |_, _| Ok(String::new())).is_ok());
        }
    }
    #[test]
    fn altered_offsets_calls_and_missing_effects_reject() {
        let mut insertion = bytes(INSERT);
        insertion[10] = 12;
        assert!(prove(&insertion, 0x409da7, Body::Insert, binding(Body::Insert)).is_err());
        let mut allocation = bytes(ALLOCATE);
        allocation[21] ^= 1;
        assert!(prove(
            &allocation,
            0x411de9,
            Body::Allocate,
            binding(Body::Allocate)
        )
        .is_err());
        let mut missing = binding(Body::Allocate);
        missing.calls.remove(&Target::Direct(0x407d50));
        assert!(prove(&bytes(ALLOCATE), 0x411de9, Body::Allocate, missing).is_err());
        let mut tail = bytes(TEMP_FINISH);
        tail.push(0xc3);
        assert!(prove(
            &tail,
            0x409ebd,
            Body::TemporaryFinish,
            binding(Body::TemporaryFinish)
        )
        .is_err());
        let mut wrong = binding(Body::Allocate);
        wrong.absolute.clear();
        assert!(prove(&bytes(ALLOCATE), 0x411de9, Body::Allocate, wrong).is_err());
    }
    static NEXT_NATIVE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn native(functions: &str, body: &str) {
        let memory = include_str!("guest_memory.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n");
        let source = format!(
            "#![allow(dead_code)]\nmod guest_memory{{{memory}}}\n{}\n{}\n{functions}\n{body}",
            super::super::crt_stream_runtime::EMITTED_TYPES,
            super::super::crt_stream_cpu::EMITTED_TYPES
        );
        let case = NEXT_NATIVE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "w2l-crt-buffer-native-{}-{case}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("case.rs");
        let exe = dir.join(if cfg!(windows) { "case.exe" } else { "case" });
        std::fs::write(&path, source).unwrap();
        let out = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(path)
            .arg("-o")
            .arg(&exe)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let out = std::process::Command::new(exe).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    #[test]
    fn original_native_allocation_insertion_and_failed_temporary_flush() {
        let allocated = prove(
            &bytes(ALLOCATE),
            0x411de9,
            Body::Allocate,
            binding(Body::Allocate),
        )
        .unwrap();
        let mut functions = String::new();
        for available in [false, true] {
            functions.push_str(&allocated.emit(if available{"allocate_yes"}else{"allocate_no"},|pc,target|{
   let next=pc+allocated.graph().nodes[&pc].length;
   let effect=match allocated.bindings().calls[&target]{
    Effect::Calloc=>format!("let sp=CrtCpu::pointer(cpu.r[4])?;let size=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;let count=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;if size!=4096||count!=1{{return Err(\"test calloc argument contract\");}}rt.check_lock(lease)?;let value=rt.allocate(size,true,{available})?.map(CrtValue::Pointer).unwrap_or(CrtValue::scalar(0));cpu.clobber(value);cpu.finish(rt)"),
    Effect::Free=>"let sp=CrtCpu::pointer(cpu.r[4])?;if rt.load(rt.offset(sp,4)?,32)?!=CrtValue::scalar(0){return Err(\"test free argument\");}cpu.clobber(CrtValue::Scalar{bits:0,known:0});cpu.finish(rt)".into(),_=>unreachable!()
   };Ok(format!("cpu.call(rt,lease,backend,{next},|rt,cpu,lease,_backend|{{{effect}}})?;"))
  }).unwrap());
        }
        let insertion = prove(
            &bytes(INSERT),
            0x409da7,
            Body::Insert,
            binding(Body::Insert),
        )
        .unwrap();
        functions.push_str(
            &insertion
                .emit("insert_fast", |_, _| {
                    Ok("return Err(\"test has no slow-path contract\");".into())
                })
                .unwrap(),
        );
        let finish = prove(
            &bytes(TEMP_FINISH),
            0x409ebd,
            Body::TemporaryFinish,
            binding(Body::TemporaryFinish),
        )
        .unwrap();
        functions.push_str(&finish.emit("temporary_finish",|pc,_|{let next=pc+finish.graph().nodes[&pc].length;Ok(format!(r#"cpu.call(rt,lease,backend,{next},|rt,cpu,lease,_backend|{{
let sp=CrtCpu::pointer(cpu.r[4])?;let file=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;let base=rt.load(rt.offset(file,4)?,32)?;
rt.store(file,32,base)?;rt.store(rt.offset(file,8)?,32,CrtValue::scalar(0))?;rt.atomic_or(lease,rt.offset(file,12)?,0x10)?;
cpu.clobber(CrtValue::scalar(u32::MAX));cpu.finish(rt)
}})?;"#))}).unwrap());
        native(
            &functions,
            r#"
struct Backend;impl CrtBackend for Backend{fn write_once(&mut self,_:CrtDescriptorId,_:&[u8])->Result<CrtWriteResult,&'static str>{panic!("unexpected OS write")}}
fn setup()->(CrtStreamRuntime,CrtLock,CrtPointer,CrtPointer,CrtPointer){let mut rt=CrtStreamRuntime::new(1,2,0x4000,65536).unwrap();let file=rt.file();let lease=rt.lock(2).unwrap();for at in [0,4,8,24]{rt.store(rt.offset(file,at).unwrap(),32,CrtValue::scalar(0)).unwrap();}rt.store(rt.offset(file,12).unwrap(),32,CrtValue::scalar(2)).unwrap();rt.map_region(0x41cd34,4,CrtRegionKind::Module,Some(&41u32.to_le_bytes())).unwrap();let stack=rt.map_region(0x8000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,2048).unwrap();let context=rt.map_region(0xa000,40,CrtRegionKind::Context,None).unwrap();(rt,lease,file,sp,context)}
fn enter(rt:&mut CrtStreamRuntime,sp:CrtPointer,args:&[CrtValue],id:u64)->CrtCpu{rt.store(sp,32,CrtValue::ProtectedReturn(id)).unwrap();for(i,v)in args.iter().copied().enumerate(){rt.store(rt.offset(sp,4+4*i as i64).unwrap(),32,v).unwrap();}CrtCpu::new(sp,id).unwrap()}
fn main(){
for available in [false,true]{let(mut rt,lease,file,sp,context)=setup();let mut cpu=enter(&mut rt,sp,&[CrtValue::Pointer(file)],1);let outcome=if available{allocate_yes(&mut rt,&mut cpu,lease,&mut Backend)}else{allocate_no(&mut rt,&mut cpu,lease,&mut Backend)};assert!(outcome.is_ok(),"{outcome:?}");assert!(cpu.returned);
 let base=CrtCpu::pointer(rt.load(rt.offset(file,4).unwrap(),32).unwrap()).unwrap();assert_eq!(rt.load(file,32).unwrap(),CrtValue::Pointer(base));assert_eq!(rt.load(rt.offset(file,8).unwrap(),32).unwrap(),CrtValue::scalar(0));assert_eq!(rt.load(rt.offset(file,24).unwrap(),32).unwrap(),CrtValue::scalar(if available{4096}else{2}));assert_eq!(rt.load(rt.offset(file,12).unwrap(),32).unwrap(),CrtValue::scalar(if available{0x42}else{0x402}));assert_eq!(rt.load(rt.resolve_absolute(0x41cd34,CrtRegionKind::Module).unwrap(),32).unwrap(),CrtValue::scalar(42));
 if available{assert_eq!(rt.load(base,32).unwrap(),CrtValue::scalar(0));rt.store(rt.offset(file,8).unwrap(),32,CrtValue::scalar(4096)).unwrap();let mut cpu=enter(&mut rt,sp,&[CrtValue::Scalar{bits:0xff,known:0xff},CrtValue::Pointer(file),CrtValue::Pointer(context)],2);assert_eq!(insert_fast(&mut rt,&mut cpu,lease,&mut Backend).unwrap(),CrtValue::scalar(255));assert_eq!(rt.load(base,8).unwrap(),CrtValue::scalar(255));assert_eq!(rt.load(rt.offset(file,8).unwrap(),32).unwrap(),CrtValue::scalar(4095));assert_eq!(rt.load(file,32).unwrap(),CrtValue::Pointer(rt.offset(base,1).unwrap()));
 let before=rt.load(rt.offset(file,8).unwrap(),32).unwrap();rt.store(rt.offset(file,24).unwrap(),32,CrtValue::scalar(1)).unwrap();let mut cpu=enter(&mut rt,sp,&[CrtValue::scalar(8),CrtValue::Pointer(file),CrtValue::Pointer(context)],3);assert!(insert_fast(&mut rt,&mut cpu,lease,&mut Backend).is_err());assert_eq!(rt.load(rt.offset(file,8).unwrap(),32).unwrap(),before);
 }else{assert_eq!(base.address(),file.address()+20);assert_eq!(rt.load(base,8).unwrap(),CrtValue::Scalar{bits:0,known:0xffffff00});}
}
let(mut rt,lease,file,sp,context)=setup();let base=rt.subrange(rt.offset(file,20).unwrap(),2).unwrap();rt.store(base,8,CrtValue::scalar(65)).unwrap();rt.store(file,32,CrtValue::Pointer(rt.offset(base,1).unwrap())).unwrap();rt.store(rt.offset(file,4).unwrap(),32,CrtValue::Pointer(base)).unwrap();rt.store(rt.offset(file,24).unwrap(),32,CrtValue::scalar(2)).unwrap();rt.store(rt.offset(file,8).unwrap(),32,CrtValue::scalar(1)).unwrap();rt.store(rt.offset(file,12).unwrap(),32,CrtValue::scalar(0x282)).unwrap();let mut cpu=enter(&mut rt,sp,&[CrtValue::scalar(1),CrtValue::Pointer(file),CrtValue::Pointer(context)],7);temporary_finish(&mut rt,&mut cpu,lease,&mut Backend).unwrap();for at in [0,4,8,24]{assert_eq!(rt.load(rt.offset(file,at).unwrap(),32).unwrap(),CrtValue::scalar(0));}assert_eq!(rt.load(rt.offset(file,12).unwrap(),32).unwrap(),CrtValue::scalar(0x12));assert_eq!(rt.load(base,8).unwrap(),CrtValue::scalar(65));
}
"#,
        );
    }

    #[test]
    fn original_native_capacity_retains_character_after_short_zero_and_error() {
        let proof = prove(
            &bytes(CAPACITY),
            0x40ff99,
            Body::Capacity,
            binding(Body::Capacity),
        )
        .unwrap();
        let functions=proof.emit("capacity",|pc,target|{let next=pc+proof.graph().nodes[&pc].length;let effect=match proof.bindings().calls[&target]{
 Effect::FileNumber=>"let sp=CrtCpu::pointer(cpu.r[4])?;let file=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;let fd=rt.load(rt.offset(file,16)?,32)?;cpu.clobber(fd);cpu.finish(rt)".to_string(),
 Effect::Seek64=>"return Err(\"unclosed append seek must be excluded by owned descriptor\");".to_string(),
 Effect::LowWrite=>r#"let sp=CrtCpu::pointer(cpu.r[4])?;let fd=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;let p=CrtCpu::pointer(rt.load(rt.offset(sp,8)?,32)?)?;let count=rt.load(rt.offset(sp,12)?,32)?.known_scalar()?;let id=rt.descriptors.iter().find(|d|d.live&&d.id.number==fd).unwrap().id;
 let file=rt.file();let flags=rt.load(rt.offset(file,12)?,32)?.known_scalar()?;if flags&0xc0!=0{let base=CrtCpu::pointer(rt.load(rt.offset(file,4)?,32)?)?;if rt.load(file,32)?!=CrtValue::Pointer(rt.offset(base,1)?)||rt.load(rt.offset(file,8)?,32)?!=CrtValue::scalar(3){return Err("original mutation ordering");}}
 let out=rt.write_once(id,p,count,backend)?;cpu.clobber(CrtValue::scalar(if out.success{out.written}else{u32::MAX}));cpu.finish(rt)"#.into(),_=>unreachable!()};Ok(format!("cpu.call(rt,lease,backend,{next},|rt,cpu,_lease,backend|{{{effect}}})?;"))}).unwrap();
        native(
            &functions,
            r#"
struct B{mode:u8,buffered:bool,calls:usize}impl CrtBackend for B{fn write_once(&mut self,_:CrtDescriptorId,bytes:&[u8])->Result<CrtWriteResult,&'static str>{self.calls+=1;assert_eq!(bytes,if self.buffered{b"ABCD" as &[u8]}else{b"Z" as &[u8]});Ok(match self.mode{0=>CrtWriteResult{success:true,written:bytes.len()as u32,last_error:None},1=>CrtWriteResult{success:true,written:if self.buffered{1}else{0},last_error:None},2=>CrtWriteResult{success:true,written:0,last_error:None},_=>CrtWriteResult{success:false,written:0,last_error:Some(5)}})}}
fn main(){for buffered in [false,true]{for mode in 0..4{
 let mut rt=CrtStreamRuntime::new(1,2,0x4000,65536).unwrap();let lease=rt.lock(2).unwrap();let file=rt.file();let fd=rt.bind_descriptor(0,77).unwrap();let record=rt.map_region(0x6000,56,CrtRegionKind::Descriptor,None).unwrap();let dl=rt.claim_descriptor_record(2,fd,record).unwrap();rt.store(rt.offset(record,24).unwrap(),32,CrtValue::Handle(fd)).unwrap();rt.store(rt.offset(record,40).unwrap(),8,CrtValue::scalar(0x81)).unwrap();rt.store(rt.offset(record,41).unwrap(),8,CrtValue::scalar(0)).unwrap();rt.bind_descriptor_record(lease,fd,record).unwrap();let table=rt.map_region(0x41cf08,4,CrtRegionKind::Module,None).unwrap();rt.store(table,32,CrtValue::Pointer(record)).unwrap();
 let base=if buffered{rt.alloc_buffer(lease,4,true).unwrap().unwrap()}else{rt.subrange(rt.offset(file,20).unwrap(),2).unwrap()};if buffered{for(i,b)in b"ABCD".iter().enumerate(){rt.store(rt.offset(base,i as i64).unwrap(),8,CrtValue::scalar(u32::from(*b))).unwrap();}}
 rt.store(file,32,CrtValue::Pointer(rt.offset(base,if buffered{4}else{0}).unwrap())).unwrap();rt.store(rt.offset(file,4).unwrap(),32,CrtValue::Pointer(base)).unwrap();for(at,value)in [(8,0),(12,if buffered{0x42}else{0x402}),(16,0),(24,if buffered{4}else{2})]{rt.store(rt.offset(file,at).unwrap(),32,CrtValue::scalar(value)).unwrap();}
 let stack=rt.map_region(0x8000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,2048).unwrap();let context=rt.map_region(0xa000,40,CrtRegionKind::Context,None).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();for(i,v)in [CrtValue::Scalar{bits:90,known:255},CrtValue::Pointer(file),CrtValue::Pointer(context)].into_iter().enumerate(){rt.store(rt.offset(sp,4+4*i as i64).unwrap(),32,v).unwrap();}
 let mut cpu=CrtCpu::new(sp,1).unwrap();let mut backend=B{mode,buffered,calls:0};capacity(&mut rt,&mut cpu,lease,&mut backend).unwrap();assert_eq!(cpu.get(0,8,0).unwrap().known_scalar().unwrap(),u32::from(mode==0));assert_eq!(backend.calls,1);assert!(cpu.returned);
 if buffered{assert_eq!(rt.load(file,32).unwrap(),CrtValue::Pointer(rt.offset(base,1).unwrap()));assert_eq!(rt.load(rt.offset(file,8).unwrap(),32).unwrap(),CrtValue::scalar(3));assert_eq!(rt.load(base,32).unwrap(),CrtValue::scalar(0x4443425a));assert_eq!(rt.load(rt.offset(file,12).unwrap(),32).unwrap(),CrtValue::scalar(0x42));}else{assert_eq!(rt.load(rt.offset(file,8).unwrap(),32).unwrap(),CrtValue::scalar(0));}
 rt.unlock_descriptor(dl).unwrap();rt.unlock(lease).unwrap();
}}}
"#,
        );
    }
}
