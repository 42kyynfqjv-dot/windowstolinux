//! Complete, bounded library-loop grammar certificates for original CRT bodies.
//!
//! This is deliberately narrower than a general cyclic x86 verifier. It checks
//! every decoded effect and edge of two parameterized algorithms before the
//! shared emitter lowers every original instruction. No symbol, image hash,
//! fixture output, or sampled input grants admission. Typed entry/call contracts
//! below remain mandatory composition obligations, not facts proved by decoding.
use super::crt_stream_ir::{Graph, Op, SignedCondition, Target};
use super::graph::{Address, Binary, Condition, Operand, Operation, Reg};
use std::collections::BTreeMap;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CallEffect {
    StackProbe,
    SecurityCheck,
    WriteFile,
    LastError,
    FileNumber,
    LowWrite,
}
#[derive(Clone, Debug)]
pub(crate) struct Bindings {
    pub calls: BTreeMap<Target, CallEffect>,
    pub absolute: BTreeMap<u32, AbsoluteRole>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AbsoluteRole {
    Cookie,
    DescriptorTable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Body {
    TextWriter,
    Flush,
}
pub(crate) struct Proof {
    graph: Graph,
    bindings: Bindings,
    body: Body,
    temporary_bytes: u32,
    max_input: u32,
    scratch_capacity: u32,
    call_depths: BTreeMap<u32, u32>,
    instruction_bound: u32,
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
    pub fn temporary_bytes(&self) -> u32 {
        self.temporary_bytes
    }
    pub fn max_input(&self) -> u32 {
        self.max_input
    }
    pub fn scratch_capacity(&self) -> u32 {
        self.scratch_capacity
    }
    /// Original function entry ESP through callee entry, including CALL word.
    pub fn call_depths(&self) -> &BTreeMap<u32, u32> {
        &self.call_depths
    }
    pub fn instruction_bound(&self) -> u32 {
        self.instruction_bound
    }
    /// Call snippets require separately proved implementation/effect contracts.
    /// These are not arbitrary trusted replacements for an unexamined callee.
    pub fn emit(
        &self,
        name: &str,
        call: impl FnMut(u32, Target) -> Result<String, String>,
    ) -> Result<String, String> {
        let roles = self
            .bindings
            .absolute
            .iter()
            .map(|(&a, _)| (a, "CrtRegionKind::Module".into()))
            .collect();
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err("CRT emitted name".into());
        }
        let preflight = self.entry_source();
        let body =
            super::crt_stream_emit::emit_body(&self.graph, call, &roles, self.instruction_bound)?;
        Ok(format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock,backend:&mut impl CrtBackend)->Result<CrtValue,&'static str>{{{preflight}{body}}}"))
    }
    /// Read-only preflight of the conditional component domain. Every check
    /// precedes guest writes and external calls. It does not prove original
    /// process startup or substitute a runtime error for a supported failure.
    pub fn entry_source(&self) -> String {
        let args = if self.body == Body::TextWriter { 16 } else { 8 };
        let mut source = format!(
            r#"
rt.check_lock(lease)?;
if cpu.returned||cpu.abi!=CrtAbi::Cdecl32Forward||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&i|cpu.r[i]!=cpu.entry[i]){{return Err("CRT entry ABI/saved-state premise");}}
let entry=CrtCpu::pointer(cpu.r[4])?;
if entry.kind!=CrtRegionKind::Stack||entry.address()%4!=0||rt.load(entry,32)?!=CrtValue::ProtectedReturn(cpu.return_id){{return Err("CRT entry protected return");}}
let private=rt.offset(entry,-{depth}i64)?;
rt.valid(private,{extent})?;
if rt.overlapping_tags(private.address(),{depth}).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_))){{return Err("CRT private frame aliases protected state");}}
let overlaps=|a:u32,n:u32,b:u32,m:u32|u64::from(a)<u64::from(b)+u64::from(m)&&u64::from(b)<u64::from(a)+u64::from(n);
"#,
            depth = self.temporary_bytes,
            extent = self.temporary_bytes + 4 + args
        );
        match self.body{
            Body::TextWriter=>{
                let cookie=*self.bindings.absolute.iter().find(|(_,v)|**v==AbsoluteRole::Cookie).unwrap().0;
                let table=*self.bindings.absolute.iter().find(|(_,v)|**v==AbsoluteRole::DescriptorTable).unwrap().0;
                source.push_str(&format!(r#"
// The separately proved x86 stack probe uses 4096-byte page steps.
// Validate its actual read addresses now, before the prolog writes saved slots.
let probe_target=entry.address().checked_sub({allocation}+8).ok_or("CRT probe target underflow")?;
let mut probe_page=entry.address().checked_sub(12).ok_or("CRT probe saved slot underflow")?&!4095u32;
while probe_target<probe_page{{probe_page=probe_page.checked_sub(4096).ok_or("CRT probe page underflow")?;let p=rt.offset(entry,i64::from(probe_page)-i64::from(entry.address()))?;rt.valid(p,4)?;}}
let result=CrtCpu::pointer(rt.load(rt.offset(entry,4)?,32)?)?;
let fd=rt.load(rt.offset(entry,8)?,32)?.known_scalar()?;
let input=CrtCpu::pointer(rt.load(rt.offset(entry,12)?,32)?)?;
let count=rt.load(rt.offset(entry,16)?,32)?.known_scalar()?;
if count>{maximum}||fd>2047||!matches!(result.kind,CrtRegionKind::Result|CrtRegionKind::Buffer|CrtRegionKind::Stack)||!matches!(input.kind,CrtRegionKind::Input|CrtRegionKind::Buffer|CrtRegionKind::Stack){{return Err("CRT text entry result/input/descriptor domain");}}
rt.valid(result,12)?;rt.valid(input,count)?;rt.offset(input,i64::from(count))?;
if !rt.overlapping_tags(result.address(),12).is_empty()||overlaps(result.address(),12,input.address(),count)||overlaps(result.address(),12,private.address(),{extent})||overlaps(input.address(),count,private.address(),{extent}){{return Err("CRT text entry writable alias");}}
for i in 0..count{{rt.load(rt.offset(input,i64::from(i))?,8)?.known_scalar()?;}}
let cookie=rt.resolve_absolute({cookie},CrtRegionKind::Module)?;
rt.load(cookie,32)?.known_scalar()?;
let table=rt.resolve_absolute({table},CrtRegionKind::Module)?;
let bank=CrtCpu::pointer(rt.load(rt.offset(table,i64::from(fd>>6)*4)?,32)?)?;
if bank.kind!=CrtRegionKind::Descriptor{{return Err("CRT text descriptor bank identity");}}
let record=rt.offset(bank,i64::from(fd&63)*56)?;rt.valid(record,56)?;
let CrtValue::Handle(id)=rt.load(rt.offset(record,24)?,32)? else{{return Err("CRT text handle authority");}};
if id.number!=fd||rt.require_narrow_descriptor(id)?!=record{{return Err("CRT text descriptor record binding");}}
"#,maximum=self.max_input,extent=self.temporary_bytes+20,allocation=self.scratch_capacity+12));
            },
            Body::Flush=>source.push_str(&format!(r#"
let file=CrtCpu::pointer(rt.load(rt.offset(entry,4)?,32)?)?;
rt.file_record(file)?;rt.valid(file,56)?;
if lease.record!=file.address(){{return Err("CRT flush FILE lease identity");}}
let flags=rt.load(rt.offset(file,12)?,32)?.known_scalar()?;
if flags&3==2&&flags&0xc0!=0{{
 let current=CrtCpu::pointer(rt.load(file,32)?)?;
 let base=CrtCpu::pointer(rt.load(rt.offset(file,4)?,32)?)?;
 let count=rt.difference(current,base)?;
 if count>{maximum}||!matches!(base.kind,CrtRegionKind::Buffer|CrtRegionKind::Stack){{return Err("CRT flush pending initialized buffer bound");}}
 rt.valid(base,count)?;rt.load(rt.offset(file,8)?,32)?;
 if overlaps(base.address(),count,private.address(),{extent})||overlaps(base.address(),count,file.address(),56){{return Err("CRT flush buffer alias");}}
 for i in 0..count{{rt.load(rt.offset(base,i64::from(i))?,8)?.known_scalar()?;}}
 if count>0{{let fd=rt.load(rt.offset(file,16)?,32)?.known_scalar()?;
 let id=rt.descriptors.iter().find(|d|d.live&&d.id.number==fd).map(|d|d.id).ok_or("CRT flush descriptor ownership")?;rt.require_narrow_descriptor(id)?;
 let context=CrtCpu::pointer(rt.load(rt.offset(entry,8)?,32)?)?;rt.validate_error_context(context)?;
 if overlaps(context.address(),40,private.address(),{extent})||overlaps(context.address(),40,base.address(),count)||overlaps(context.address(),40,file.address(),56){{return Err("CRT flush context alias");}}
 }}
}}
"#,maximum=self.max_input,extent=self.temporary_bytes+12)),
        }
        source
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
fn addr(base: Option<u8>, index: Option<u8>, scale: u32, disp: i32) -> Address {
    Address {
        base,
        index,
        scale,
        displacement: disp as u32,
    }
}
fn m(base: u8, disp: i32) -> Operand {
    Operand::Memory(addr(Some(base), None, 1, disp), 32)
}
fn mb(base: u8, disp: i32) -> Operand {
    Operand::Memory(addr(Some(base), None, 1, disp), 8)
}
fn abs(va: u32) -> Operand {
    Operand::Memory(addr(None, None, 1, va as i32), 32)
}
fn o(op: Operation) -> Op {
    Op::Ordinary(op)
}
fn bin(b: Binary, d: Operand, s: Operand) -> Op {
    o(Operation::Binary(b, d, s))
}
fn mov(d: Operand, s: Operand) -> Op {
    bin(Binary::Move, d, s)
}
fn push(a: Operand) -> Op {
    o(Operation::Push(a))
}
fn pop(i: u8) -> Op {
    o(Operation::Pop(reg(i)))
}
fn lea(i: u8, base: u8, disp: i32) -> Op {
    o(Operation::Address(reg(i), addr(Some(base), None, 1, disp)))
}
fn full_reg(op: &Op) -> Result<u8, String> {
    match op {
        Op::Ordinary(Operation::Binary(Binary::Move, Operand::Reg(d), _))
            if d.width == 32 && d.shift == 0 =>
        {
            Ok(d.index)
        }
        _ => Err("CRT grammar register role".into()),
    }
}
fn call_at(
    ops: &[&Op],
    index: usize,
    effect: CallEffect,
    bindings: &Bindings,
) -> Result<Target, String> {
    let Op::Call(target) = ops[index] else {
        return Err(format!("CRT grammar missing call at {index}"));
    };
    if bindings.calls.get(target) != Some(&effect) {
        return Err(format!("CRT unproved call binding {target:?}"));
    }
    Ok(*target)
}
fn compare(graph: &Graph, expected: Vec<Op>) -> Result<(), String> {
    if expected.len() != graph.nodes.len() {
        return Err("CRT grammar complete graph size".into());
    }
    let pcs: Vec<_> = graph.nodes.keys().copied().collect();
    for (index, ((&pc, node), op)) in graph.nodes.iter().zip(expected.iter()).enumerate() {
        if node.op != *op {
            return Err(format!(
                "CRT grammar effect at {pc:#x} (node {index}): {:?}",
                node.op
            ));
        }
        let mut edges = match op {
            Op::Ordinary(Operation::Return) => vec![],
            Op::Ordinary(Operation::Jump(t)) => vec![*t],
            Op::Ordinary(Operation::Branch(_, t)) | Op::SignedBranch { target: t, .. } => {
                vec![pc + node.length, *t]
            }
            _ => vec![pc + node.length],
        };
        edges.sort();
        edges.dedup();
        let mut actual = node.successors.clone();
        actual.sort();
        actual.dedup();
        if actual != edges || edges.iter().any(|p| !pcs.contains(p)) {
            return Err("CRT grammar edge closure".into());
        }
    }
    Ok(())
}
/// Typed entry obligations: DF=0; cdecl protected return/saved state; disjoint
/// valid private stack covering temporary_bytes; initialized input[0,count),
/// count<=max_input; writable result triple disjoint from input/stack/module;
/// fd belongs to a live locked descriptor with the bound 64x56 table/handle;
/// actual module cookie initialized; source/end arithmetic cannot wrap.
/// WriteFile must return 0<=written<=requested, initialize countout on success,
/// preserve source/other owned regions, and expose GetLastError after failure.
/// A positive short success stops. No retry or inferred all-written effect.
pub(crate) fn prove_text(
    code: &[u8],
    origin: u32,
    bindings: Bindings,
    max_input: u32,
) -> Result<Proof, String> {
    if max_input == 0 || max_input > 16384 {
        return Err("CRT text input resource bound".into());
    }
    let graph = Graph::decode(code, origin)?;
    let pcs: Vec<_> = graph.nodes.keys().copied().collect();
    let ops: Vec<_> = graph.nodes.values().map(|n| &n.op).collect();
    if ops.len() != 80 {
        return Err("CRT text complete loop grammar".into());
    }
    let Op::Ordinary(Operation::Binary(
        Binary::Move,
        Operand::Reg(a),
        Operand::Immediate(allocation),
    )) = ops[3]
    else {
        return Err("CRT text stack allocation".into());
    };
    if *a != reg(0) || !allocation.is_multiple_of(4) || !(16..=8192).contains(allocation) {
        return Err("CRT text scratch allocation bound".into());
    }
    let allocation = *allocation;
    let capacity = allocation - 12;
    let cookie = match ops[5] {
        Op::Ordinary(Operation::Binary(Binary::Move, _, Operand::Memory(a, 32)))
            if a.base.is_none() && a.index.is_none() =>
        {
            a.displacement
        }
        _ => return Err("CRT text cookie operand".into()),
    };
    let table = match ops[16] {
        Op::Ordinary(Operation::Binary(Binary::Move, _, Operand::Memory(a, 32)))
            if a.base.is_none() && a.index == Some(0) && a.scale == 4 =>
        {
            a.displacement
        }
        _ => return Err("CRT text descriptor operand".into()),
    };
    if cookie % 4 != 0
        || table % 4 != 0
        || cookie == table
        || bindings.absolute
            != BTreeMap::from([
                (cookie, AbsoluteRole::Cookie),
                (table, AbsoluteRole::DescriptorTable),
            ])
    {
        return Err("CRT text absolute role authority".into());
    }
    let cursor = full_reg(ops[8])?;
    let end = full_reg(ops[10])?;
    let result = full_reg(ops[15])?;
    let output = match ops[32] {
        Op::Ordinary(Operation::Address(d, _)) if d.width == 32 && d.shift == 0 => d.index,
        _ => return Err("CRT text output role".into()),
    };
    if !matches!((cursor, end), (1, 2) | (2, 1)) || !matches!((result, output), (3, 6) | (6, 3)) {
        return Err("CRT text distinct register roles".into());
    }
    let probe = call_at(&ops, 4, CallEffect::StackProbe, &bindings)?;
    let write = call_at(&ops, 57, CallEffect::WriteFile, &bindings)?;
    let error = call_at(&ops, 69, CallEffect::LastError, &bindings)?;
    let security = call_at(&ops, 77, CallEffect::SecurityCheck, &bindings)?;
    if !matches!(probe, Target::Direct(_))
        || !matches!(security, Target::Direct(_))
        || !matches!(write, Target::Import(_))
        || !matches!(error, Target::Import(_))
        || bindings.calls.len() != 4
    {
        return Err("CRT text call kind/closure".into());
    }
    let br = |c, i| o(Operation::Branch(c, pcs[i]));
    let inc = |i| o(Operation::Increment(reg(i)));
    let mut e = vec![
        mov(r(7), r(7)),
        push(r(5)),
        mov(r(5), r(4)),
        mov(r(0), imm(allocation)),
        Op::Call(probe),
        mov(r(0), abs(cookie)),
        bin(Binary::Xor, r(0), r(5)),
        mov(m(5, -4), r(0)),
        mov(r(cursor), m(5, 12)),
        mov(r(0), r(cursor)),
        mov(r(end), m(5, 20)),
        bin(Binary::And, r(cursor), imm(63)),
        Op::ArithmeticShift {
            dst: reg(0),
            count: 6,
        },
        Op::Multiply {
            dst: reg(cursor),
            source: r(cursor),
            factor: 56,
        },
        push(r(result)),
        mov(r(result), m(5, 8)),
        mov(
            r(0),
            Operand::Memory(addr(None, Some(0), 4, table as i32), 32),
        ),
        push(r(output)),
        push(r(7)),
        mov(r(7), r(result)),
        mov(
            r(0),
            Operand::Memory(addr(Some(0), Some(cursor), 1, 24), 32),
        ),
        mov(r(cursor), m(5, 16)),
        bin(Binary::Add, r(end), r(cursor)),
        mov(m(5, -(allocation as i32 - 4)), r(0)),
        bin(Binary::Xor, r(0), r(0)),
        Op::StoreString { width: 32 },
        mov(m(5, -(allocation as i32)), r(end)),
        Op::StoreString { width: 32 },
        Op::StoreString { width: 32 },
        bin(Binary::Compare, r(cursor), r(end)),
        br(Condition::AboveEqual, 71),
        mov(r(7), m(5, -(allocation as i32 - 4))),
        lea(output, 5, -(allocation as i32 - 8)),
        bin(Binary::Compare, r(cursor), r(end)),
        br(Condition::AboveEqual, 47),
        mov(byte(0), mb(cursor, 0)),
        inc(cursor),
        bin(Binary::Compare, byte(0), imm(10)),
        br(Condition::NotEqual, 42),
        Op::IncrementMemory(m(result, 8)),
        mov(mb(output, 0), imm(13)),
        inc(output),
        mov(mb(output, 0), byte(0)),
        inc(output),
        lea(0, 5, -5),
        bin(Binary::Compare, r(output), r(0)),
        br(Condition::Below, 33),
        lea(0, 5, -(allocation as i32 - 8)),
        mov(m(5, 16), r(cursor)),
        bin(Binary::Sub, r(output), r(0)),
        lea(0, 5, -(allocation as i32 - 4)),
        push(imm(0)),
        push(r(0)),
        push(r(output)),
        lea(0, 5, -(allocation as i32 - 8)),
        push(r(0)),
        push(r(7)),
        Op::Call(write),
        bin(Binary::Test, r(0), r(0)),
        br(Condition::Equal, 69),
        mov(r(0), m(5, -(allocation as i32 - 4))),
        bin(Binary::Add, m(result, 4), r(0)),
        bin(Binary::Compare, r(0), r(output)),
        br(Condition::Below, 71),
        mov(r(cursor), m(5, 16)),
        mov(r(end), m(5, -(allocation as i32))),
        bin(Binary::Compare, r(cursor), r(end)),
        br(Condition::Below, 32),
        o(Operation::Jump(pcs[71])),
        Op::Call(error),
        mov(m(result, 0), r(0)),
        mov(r(1), m(5, -4)),
        mov(r(0), r(result)),
        pop(7),
        pop(output),
        bin(Binary::Xor, r(1), r(5)),
        pop(result),
        Op::Call(security),
        o(Operation::Leave),
        o(Operation::Return),
    ];
    // A hotpatch no-op may name any full register; it cannot grant new effects.
    if let Op::Ordinary(Operation::Binary(Binary::Move, Operand::Reg(a), Operand::Reg(b))) = ops[0]
    {
        if a == b && a.width == 32 && a.shift == 0 {
            e[0] = (*ops[0]).clone();
        }
    }
    compare(&graph, e)?;
    let call_depths = BTreeMap::from([
        (pcs[4], 8),
        (pcs[57], allocation + 40),
        (pcs[69], allocation + 20),
        (pcs[77], allocation + 8),
    ]);
    // Each inner iteration consumes one source byte and writes <=2. Before an
    // iteration scratch_used<capacity-1; hence both stores fit. Full-write backedge
    // consumes >=1 byte; short/failure exits. Counters<=2*max_input, no overflow.
    // 64 instructions/source byte plus fixed prolog/exit dominates both loops.
    Ok(Proof {
        graph,
        bindings,
        body: Body::TextWriter,
        temporary_bytes: allocation + 40,
        max_input,
        scratch_capacity: capacity,
        call_depths,
        instruction_bound: max_input * 64 + 128,
    })
}
/// Entry obligations: live locked FILE with correctly tagged current/base
/// pointers into the same initialized buffer, nonnegative pending<=max_input,
/// scalar flags/count/descriptor fields, typed locale/error context. The low
/// writer is a separately proved exact original body; its return may be negative
/// or short. Reset writes and error-flag effects are original graph effects.
pub(crate) fn prove_flush(
    code: &[u8],
    origin: u32,
    bindings: Bindings,
    max_input: u32,
) -> Result<Proof, String> {
    if max_input == 0 || max_input > 16384 || !bindings.absolute.is_empty() {
        return Err("CRT flush entry bound/absolute roles".into());
    }
    let graph = Graph::decode(code, origin)?;
    let pcs: Vec<_> = graph.nodes.keys().copied().collect();
    let ops: Vec<_> = graph.nodes.values().map(|n| &n.op).collect();
    if ops.len() != 52 {
        return Err("CRT flush complete finite graph".into());
    }
    let fileno = call_at(&ops, 24, CallEffect::FileNumber, &bindings)?;
    let lowwrite = call_at(&ops, 29, CallEffect::LowWrite, &bindings)?;
    if !matches!(fileno, Target::Direct(_))
        || !matches!(lowwrite, Target::Direct(_))
        || bindings.calls.len() != 2
    {
        return Err("CRT flush call closure".into());
    }
    let br = |c, i| o(Operation::Branch(c, pcs[i]));
    let e = vec![
        mov(r(7), r(7)),
        push(r(5)),
        mov(r(5), r(4)),
        mov(r(1), m(5, 8)),
        push(r(3)),
        push(r(6)),
        push(r(7)),
        lea(6, 1, 12),
        mov(r(2), m(6, 0)),
        o(Operation::Nop),
        mov(r(0), r(2)),
        bin(Binary::And, byte(0), imm(3)),
        bin(Binary::Compare, byte(0), imm(2)),
        br(Condition::NotEqual, 46),
        bin(Binary::Test, byte(2), imm(192)),
        br(Condition::Equal, 46),
        mov(r(7), m(1, 0)),
        mov(r(3), m(1, 4)),
        bin(Binary::Sub, r(7), r(3)),
        mov(m(1, 0), r(3)),
        bin(Binary::And, m(1, 8), imm(0)),
        bin(Binary::Test, r(7), r(7)),
        Op::SignedBranch {
            condition: SignedCondition::LessEqual,
            target: pcs[46],
        },
        push(r(1)),
        Op::Call(fileno),
        push(m(5, 12)),
        push(r(7)),
        push(r(3)),
        push(r(0)),
        Op::Call(lowwrite),
        bin(Binary::Add, r(4), imm(20)),
        bin(Binary::Compare, r(7), r(0)),
        br(Condition::Equal, 38),
        push(imm(16)),
        pop(0),
        Op::Locked {
            operation: Binary::Or,
            destination: m(6, 0),
            source: r(0),
        },
        bin(Binary::Or, r(0), imm(u32::MAX)),
        o(Operation::Jump(pcs[47])),
        mov(r(0), m(6, 0)),
        o(Operation::Nop),
        o(Operation::Shift {
            left: false,
            dst: reg(0),
            count: 2,
        }),
        bin(Binary::Test, byte(0), imm(1)),
        br(Condition::Equal, 46),
        push(imm(u32::MAX - 2)),
        pop(0),
        Op::Locked {
            operation: Binary::And,
            destination: m(6, 0),
            source: r(0),
        },
        bin(Binary::Xor, r(0), r(0)),
        pop(7),
        pop(6),
        pop(3),
        pop(5),
        o(Operation::Return),
    ];
    compare(&graph, e)?;
    Ok(Proof {
        graph,
        bindings,
        body: Body::Flush,
        temporary_bytes: 40,
        max_input,
        scratch_capacity: 0,
        call_depths: BTreeMap::from([(pcs[24], 24), (pcs[29], 40)]),
        instruction_bound: 128,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    // Independently assembled small-buffer instance of the algorithm, not bytes
    // copied from a retained compiler fixture. Long branches vary all PC offsets.
    fn assemble(
        mut n: Vec<Vec<u8>>,
        origin: u32,
        branches: &[(usize, u8, usize)],
        calls: &[(usize, u32)],
    ) -> Vec<u8> {
        for &(at, c, _) in branches {
            n[at] = if c == 0xff {
                vec![0xe9, 0, 0, 0, 0]
            } else {
                vec![0x0f, c, 0, 0, 0, 0]
            };
        }
        for &(at, _) in calls {
            n[at] = vec![0xe8, 0, 0, 0, 0];
        }
        let mut pc = origin;
        let pcs: Vec<_> = n
            .iter()
            .map(|v| {
                let here = pc;
                pc += v.len() as u32;
                here
            })
            .collect();
        for &(at, _, target) in branches {
            let len = n[at].len();
            let delta = pcs[target].wrapping_sub(pcs[at] + len as u32);
            n[at][len - 4..].copy_from_slice(&delta.to_le_bytes());
        }
        for &(at, target) in calls {
            let delta = target.wrapping_sub(pcs[at] + 5);
            n[at][1..].copy_from_slice(&delta.to_le_bytes());
        }
        n.concat()
    }
    pub(super) fn text_fixture(origin: u32, allocation: u8) -> (Vec<u8>, Bindings) {
        let count = 4u8.wrapping_sub(allocation);
        let end = 0u8.wrapping_sub(allocation);
        let scratch = 8u8.wrapping_sub(allocation);
        let n = vec![
            vec![0x89, 0xc0],
            vec![0x55],
            vec![0x89, 0xe5],
            vec![0xb8, allocation, 0, 0, 0],
            vec![],
            vec![0xa1, 0, 0x50, 0, 0],
            vec![0x31, 0xe8],
            vec![0x89, 0x45, 0xfc],
            vec![0x8b, 0x4d, 12],
            vec![0x89, 0xc8],
            vec![0x8b, 0x55, 20],
            vec![0x83, 0xe1, 63],
            vec![0xc1, 0xf8, 6],
            vec![0x6b, 0xc9, 56],
            vec![0x53],
            vec![0x8b, 0x5d, 8],
            vec![0x8b, 0x04, 0x85, 0, 0x60, 0, 0],
            vec![0x56],
            vec![0x57],
            vec![0x89, 0xdf],
            vec![0x8b, 0x44, 0x08, 24],
            vec![0x8b, 0x4d, 16],
            vec![0x01, 0xca],
            vec![0x89, 0x45, count],
            vec![0x31, 0xc0],
            vec![0xab],
            vec![0x89, 0x55, end],
            vec![0xab],
            vec![0xab],
            vec![0x39, 0xd1],
            vec![],
            vec![0x8b, 0x7d, count],
            vec![0x8d, 0x75, scratch],
            vec![0x39, 0xd1],
            vec![],
            vec![0x8a, 0x01],
            vec![0x41],
            vec![0x3c, 10],
            vec![],
            vec![0xff, 0x43, 8],
            vec![0xc6, 0x06, 13],
            vec![0x46],
            vec![0x88, 0x06],
            vec![0x46],
            vec![0x8d, 0x45, 0xfb],
            vec![0x39, 0xc6],
            vec![],
            vec![0x8d, 0x45, scratch],
            vec![0x89, 0x4d, 16],
            vec![0x29, 0xc6],
            vec![0x8d, 0x45, count],
            vec![0x6a, 0],
            vec![0x50],
            vec![0x56],
            vec![0x8d, 0x45, scratch],
            vec![0x50],
            vec![0x57],
            vec![0xff, 0x15, 0, 0x70, 0, 0],
            vec![0x85, 0xc0],
            vec![],
            vec![0x8b, 0x45, count],
            vec![0x01, 0x43, 4],
            vec![0x39, 0xf0],
            vec![],
            vec![0x8b, 0x4d, 16],
            vec![0x8b, 0x55, end],
            vec![0x39, 0xd1],
            vec![],
            vec![],
            vec![0xff, 0x15, 4, 0x70, 0, 0],
            vec![0x89, 0x03],
            vec![0x8b, 0x4d, 0xfc],
            vec![0x89, 0xd8],
            vec![0x5f],
            vec![0x5e],
            vec![0x31, 0xe9],
            vec![0x5b],
            vec![],
            vec![0xc9],
            vec![0xc3],
        ];
        let code = assemble(
            n,
            origin,
            &[
                (30, 0x83, 71),
                (34, 0x83, 47),
                (38, 0x85, 42),
                (46, 0x82, 33),
                (59, 0x84, 69),
                (63, 0x82, 71),
                (67, 0x82, 32),
                (68, 0xff, 71),
            ],
            &[(4, 0x20000), (77, 0x20100)],
        );
        let bindings = Bindings {
            calls: BTreeMap::from([
                (Target::Direct(0x20000), CallEffect::StackProbe),
                (Target::Direct(0x20100), CallEffect::SecurityCheck),
                (Target::Import(0x7000), CallEffect::WriteFile),
                (Target::Import(0x7004), CallEffect::LastError),
            ]),
            absolute: BTreeMap::from([
                (0x5000, AbsoluteRole::Cookie),
                (0x6000, AbsoluteRole::DescriptorTable),
            ]),
        };
        (code, bindings)
    }
    fn flush_fixture(origin: u32) -> (Vec<u8>, Bindings) {
        let n = vec![
            vec![0x89, 0xff],
            vec![0x55],
            vec![0x89, 0xe5],
            vec![0x8b, 0x4d, 8],
            vec![0x53],
            vec![0x56],
            vec![0x57],
            vec![0x8d, 0x71, 12],
            vec![0x8b, 0x16],
            vec![0x90],
            vec![0x89, 0xd0],
            vec![0x24, 3],
            vec![0x3c, 2],
            vec![],
            vec![0xf6, 0xc2, 192],
            vec![],
            vec![0x8b, 0x39],
            vec![0x8b, 0x59, 4],
            vec![0x29, 0xdf],
            vec![0x89, 0x19],
            vec![0x83, 0x61, 8, 0],
            vec![0x85, 0xff],
            vec![],
            vec![0x51],
            vec![],
            vec![0xff, 0x75, 12],
            vec![0x57],
            vec![0x53],
            vec![0x50],
            vec![],
            vec![0x83, 0xc4, 20],
            vec![0x39, 0xc7],
            vec![],
            vec![0x6a, 16],
            vec![0x58],
            vec![0xf0, 0x09, 0x06],
            vec![0x83, 0xc8, 0xff],
            vec![],
            vec![0x8b, 0x06],
            vec![0x90],
            vec![0xc1, 0xe8, 2],
            vec![0xa8, 1],
            vec![],
            vec![0x6a, 0xfd],
            vec![0x58],
            vec![0xf0, 0x21, 0x06],
            vec![0x31, 0xc0],
            vec![0x5f],
            vec![0x5e],
            vec![0x5b],
            vec![0x5d],
            vec![0xc3],
        ];
        let code = assemble(
            n,
            origin,
            &[
                (13, 0x85, 46),
                (15, 0x84, 46),
                (22, 0x8e, 46),
                (32, 0x84, 38),
                (37, 0xff, 47),
                (42, 0x84, 46),
            ],
            &[(24, 0x22000), (29, 0x22100)],
        );
        (
            code,
            Bindings {
                calls: BTreeMap::from([
                    (Target::Direct(0x22000), CallEffect::FileNumber),
                    (Target::Direct(0x22100), CallEffect::LowWrite),
                ]),
                absolute: BTreeMap::new(),
            },
        )
    }
    #[test]
    fn independent_flush_requires_reset_before_write_and_exact_error_flag() {
        for origin in [0x10000, 0x31000] {
            let (c, b) = flush_fixture(origin);
            let p = prove_flush(&c, origin, b.clone(), 1024).unwrap();
            assert_eq!(p.temporary_bytes(), 40);
            assert_eq!(p.instruction_bound(), 128);
            for (index, byte, value) in [
                (19, 1, 0x09),
                (20, 3, 1),
                (22, 1, 0x86),
                (30, 2, 16),
                (33, 1, 8),
                (35, 0, 0x90),
                (43, 1, 0xfe),
            ] {
                let mut changed = c.clone();
                mutate_node(&mut changed, origin, index, byte, value);
                assert!(
                    prove_flush(&changed, origin, b.clone(), 1024).is_err(),
                    "node{index}"
                );
            }
        }
    }
    fn mutate_node(code: &mut [u8], origin: u32, index: usize, byte: usize, value: u8) {
        let g = Graph::decode(code, origin).unwrap();
        let pc = *g.nodes.keys().nth(index).unwrap();
        code[(pc - origin) as usize + byte] = value;
    }
    #[test]
    fn independent_relocated_small_buffers_have_derived_bounds() {
        for origin in [0x10000, 0x31000] {
            for allocation in [16, 28, 60, 120] {
                let (c, b) = text_fixture(origin, allocation);
                let p = prove_text(&c, origin, b, 257).unwrap();
                assert_eq!(p.scratch_capacity(), u32::from(allocation) - 12);
                assert_eq!(p.temporary_bytes(), u32::from(allocation) + 40);
                assert_eq!(p.instruction_bound(), 257 * 64 + 128);
                let s = p
                    .emit("original", |_, _| {
                        Ok("return Err(\"unbound test contract\");".into())
                    })
                    .unwrap();
                assert!(s.contains("cpu.condition(2)?"));
                assert!(!s.contains("uppercase"));
            }
        }
    }
    #[test]
    fn loop_safety_and_short_write_edges_are_proof_obligations() {
        let origin = 0x10000;
        let (c, b) = text_fixture(origin, 28);
        for (index, byte, value) in [
            (36, 0, 0x49),
            (37, 1, 11),
            (39, 2, 4),
            (40, 2, 10),
            (44, 2, 0xfc),
            (46, 1, 0x86),
            (63, 1, 0x83),
            (67, 1, 0x86),
            (73, 0, 0x5e),
        ] {
            let mut changed = c.clone();
            mutate_node(&mut changed, origin, index, byte, value);
            assert!(
                prove_text(&changed, origin, b.clone(), 257).is_err(),
                "node{index}"
            );
        }
        let mut wrong = b.clone();
        wrong
            .calls
            .insert(Target::Import(0x7000), CallEffect::LastError);
        assert!(prove_text(&c, origin, wrong, 257).is_err());
        assert!(prove_text(&c, origin, b.clone(), 16385).is_err());
        let mut wrong = b;
        wrong.absolute.insert(0x5000, AbsoluteRole::DescriptorTable);
        assert!(prove_text(&c, origin, wrong, 257).is_err());
    }
    #[test]
    fn resource_or_hidden_effects_never_grant_a_certificate() {
        let (c, b) = text_fixture(0x10000, 12);
        assert!(prove_text(&c, 0x10000, b, 1).is_err());
        let (mut c, b) = text_fixture(0x10000, 28);
        c.push(0x90);
        assert!(prove_text(&c, 0x10000, b, 1).is_err());
    }
    #[test]
    fn native_entry_preflight_rejects_unknown_alias_and_dead_owner_before_effects() {
        let (code, bindings) = text_fixture(0x10000, 28);
        let proof = prove_text(&code, 0x10000, bindings, 257).unwrap();
        let memory = include_str!("guest_memory.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n");
        let body=r#"
fn check(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock)->Result<(),&'static str>{PREFLIGHT Ok(())}
fn one(which:u8){
 let mut rt=CrtStreamRuntime::new(1,2,0x2000,1048576).unwrap();let lease=rt.lock(2).unwrap();
 let stack=rt.map_region(0x10000,65536,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,0xf000).unwrap();
 let input=rt.map_region(0x30000,4,CrtRegionKind::Input,if which==1{None}else{Some(b"A\nZ\0")}).unwrap();
 let result=rt.map_region(0x40000,12,CrtRegionKind::Result,None).unwrap();
 let descriptor=rt.map_region(0x50000,56,CrtRegionKind::Descriptor,None).unwrap();let id=rt.bind_descriptor(0,7).unwrap();
 rt.store(rt.offset(descriptor,24).unwrap(),32,CrtValue::Handle(id)).unwrap();rt.store(rt.offset(descriptor,40).unwrap(),8,CrtValue::scalar(0x81)).unwrap();rt.store(rt.offset(descriptor,41).unwrap(),8,CrtValue::scalar(0)).unwrap();rt.bind_descriptor_record(lease,id,descriptor).unwrap();
 let table=rt.map_region(0x6000,4,CrtRegionKind::Module,None).unwrap();rt.store(table,32,CrtValue::Pointer(descriptor)).unwrap();
 rt.map_region(0x5000,4,CrtRegionKind::Module,if which==4{None}else{Some(&[1,2,3,4])}).unwrap();
 rt.store(sp,32,CrtValue::ProtectedReturn(17)).unwrap();
 let resultarg=if which==2{rt.offset(sp,-4).unwrap()}else{result};
 for (i,arg) in [CrtValue::Pointer(resultarg),CrtValue::scalar(0),CrtValue::Pointer(input),CrtValue::scalar(if which==3{258}else{4})].into_iter().enumerate(){rt.store(rt.offset(sp,4+i as i64*4).unwrap(),32,arg).unwrap();}
 if which==5{rt.descriptors[0].live=false;}
 let mut cpu=CrtCpu::new(sp,17).unwrap();let initial=cpu.r;let tags=rt.tags.clone();let outcome=check(&mut rt,&mut cpu,lease);
 assert_eq!(outcome.is_ok(),which==0,"case{which}: {outcome:?}");assert_eq!(cpu.r,initial);assert_eq!(rt.tags,tags);assert_eq!(rt.load(result,32).unwrap(),CrtValue::Scalar{bits:0,known:0});
}
fn main(){for which in 0..=5{one(which);}}
"#.replace("PREFLIGHT",&proof.entry_source());
        let source = format!(
            "#![allow(dead_code)]\nmod guest_memory{{{memory}}}\n{}\n{}\n{body}",
            crate::crt_stream_runtime::EMITTED_TYPES,
            crate::crt_stream_cpu::EMITTED_TYPES
        );
        let dir = std::env::temp_dir().join(format!("w2l-crt-preflight-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("test.rs");
        let exe = dir.join("test");
        std::fs::write(&src, source).unwrap();
        let output = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(&src)
            .arg("-o")
            .arg(&exe)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = std::process::Command::new(&exe).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn original_flush_native_resets_before_call_and_marks_short_or_error_results() {
        let (code, bindings) = flush_fixture(0x10000);
        let proof = prove_flush(&code, 0x10000, bindings, 1024).unwrap();
        let emitted=proof.emit("original_flush",|pc,target|{
            let next=pc+proof.graph().nodes[&pc].length;
            Ok(match target{
                Target::Direct(0x22000)=>format!(r#"cpu.call(rt,lease,backend,{next},|rt,cpu,_,_|{{let sp=CrtCpu::pointer(cpu.r[4])?;let file=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;let value=rt.load(rt.offset(file,16)?,32)?;cpu.clobber(value);cpu.finish(rt)}})?;"#),
                Target::Direct(0x22100)=>format!(r#"cpu.call(rt,lease,backend,{next},|rt,cpu,_,backend|{{let sp=CrtCpu::pointer(cpu.r[4])?;let fd=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;let buffer=CrtCpu::pointer(rt.load(rt.offset(sp,8)?,32)?)?;let count=rt.load(rt.offset(sp,12)?,32)?.known_scalar()?;let file=rt.file();assert_eq!(rt.load(file,32)?,rt.load(rt.offset(file,4)?,32)?);assert_eq!(rt.load(rt.offset(file,8)?,32)?,CrtValue::scalar(0));let id=rt.descriptors.iter().find(|d|d.live&&d.id.number==fd).ok_or("test fd")?.id;let result=rt.write_once(id,buffer,count,backend)?;cpu.clobber(CrtValue::scalar(if result.success{{result.written}}else{{u32::MAX}}));cpu.finish(rt)}})?;"#),
                _=>return Err("unbound test callee".into()),
            })
        }).unwrap();
        // Deliberately declared test callees, not a claim of proving the CRT
        // fileno/worker bodies. All reset/branch/flag/return effects come from
        // the admitted original flush instructions around these boundary values.
        let main = r#"
struct Backend{mode:u8,calls:usize}impl CrtBackend for Backend{fn write_once(&mut self,_:CrtDescriptorId,bytes:&[u8])->Result<CrtWriteResult,&'static str>{self.calls+=1;assert_eq!(bytes,b"A\nZ");Ok(match self.mode{0=>CrtWriteResult{success:true,written:3,last_error:None},1=>CrtWriteResult{success:true,written:1,last_error:None},_=>CrtWriteResult{success:false,written:0,last_error:Some(5)}})}}
fn main(){for mode in 0..3{
 let mut rt=CrtStreamRuntime::new(1,2,0x2000,1048576).unwrap();let lease=rt.lock(2).unwrap();let file=rt.file();
 let buffer=rt.alloc_buffer(lease,16,true).unwrap().unwrap();for(i,b)in b"A\nZ".iter().enumerate(){rt.store(rt.offset(buffer,i as i64).unwrap(),8,CrtValue::scalar(u32::from(*b))).unwrap();}
 rt.store(file,32,CrtValue::Pointer(rt.offset(buffer,3).unwrap())).unwrap();rt.store(rt.offset(file,4).unwrap(),32,CrtValue::Pointer(buffer)).unwrap();rt.store(rt.offset(file,8).unwrap(),32,CrtValue::scalar(13)).unwrap();rt.store(rt.offset(file,12).unwrap(),32,CrtValue::scalar(0x46)).unwrap();rt.store(rt.offset(file,16).unwrap(),32,CrtValue::scalar(0)).unwrap();
 let record=rt.map_region(0x50000,56,CrtRegionKind::Descriptor,None).unwrap();let id=rt.bind_descriptor(0,7).unwrap();rt.store(rt.offset(record,24).unwrap(),32,CrtValue::Handle(id)).unwrap();rt.store(rt.offset(record,40).unwrap(),8,CrtValue::scalar(0x81)).unwrap();rt.store(rt.offset(record,41).unwrap(),8,CrtValue::scalar(0)).unwrap();rt.bind_descriptor_record(lease,id,record).unwrap();
 let context=rt.map_region(0x60000,40,CrtRegionKind::Context,Some(&[0;40])).unwrap();let stack=rt.map_region(0x10000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,2048).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(17)).unwrap();rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::Pointer(file)).unwrap();rt.store(rt.offset(sp,8).unwrap(),32,CrtValue::Pointer(context)).unwrap();
 let mut cpu=CrtCpu::new(sp,17).unwrap();let mut backend=Backend{mode,calls:0};let result=original_flush(&mut rt,&mut cpu,lease,&mut backend).unwrap();assert_eq!(result,CrtValue::scalar(if mode==0{0}else{u32::MAX}));assert_eq!(rt.load(rt.offset(file,12).unwrap(),32).unwrap(),CrtValue::scalar(if mode==0{0x44}else{0x56}));assert_eq!(backend.calls,1);assert!(cpu.returned);
}}
"#;
        let memory = include_str!("guest_memory.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n");
        let source = format!(
            "#![allow(dead_code)]\nmod guest_memory{{{memory}}}\n{}\n{}\n{emitted}\n{main}",
            crate::crt_stream_runtime::EMITTED_TYPES,
            crate::crt_stream_cpu::EMITTED_TYPES
        );
        let dir = std::env::temp_dir().join(format!("w2l-crt-flush-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("test.rs");
        let exe = dir.join("test");
        std::fs::write(&src, source).unwrap();
        let output = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(&src)
            .arg("-o")
            .arg(&exe)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = std::process::Command::new(&exe).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
