//! Native lowering of already admitted original CRT graphs.
//! Each decoded instruction lowers to Rust operations; runtime never decodes x86.
use super::crt_stream_ir::{Graph, Op, SignedCondition, Target};
use super::graph::{Address, Binary, Condition, Operand, Operation, Reg};
use std::collections::BTreeMap;
fn condition(c: Condition) -> u8 {
    match c {
        Condition::Equal => 0,
        Condition::NotEqual => 1,
        Condition::Below => 2,
        Condition::Above => 3,
        Condition::BelowEqual => 4,
        Condition::AboveEqual => 5,
    }
}
fn address(a: &Address, roles: &BTreeMap<u32, String>) -> Result<String, String> {
    let role = if a.base.is_none() {
        format!(
            "Some({})",
            roles
                .get(&a.displacement)
                .ok_or("CRT emit unbound absolute address role")?
        )
    } else {
        "None".into()
    };
    Ok(format!(
        "cpu.address(rt,{:?},{:?},{},{},{role})?",
        a.base.map(usize::from),
        a.index.map(usize::from),
        a.scale,
        a.displacement
    ))
}
fn read(o: &Operand, roles: &BTreeMap<u32, String>) -> Result<String, String> {
    Ok(match o {
        Operand::Reg(r) => format!("cpu.get({},{},{})?", r.index, r.width, r.shift),
        Operand::Immediate(n) => format!("CrtValue::scalar({n})"),
        Operand::Memory(a, w) => format!("rt.load({}, {w})?", address(a, roles)?),
    })
}
fn write(o: &Operand, v: &str, roles: &BTreeMap<u32, String>) -> Result<String, String> {
    Ok(match o {
        Operand::Reg(r) => format!("cpu.set({},{},{},{v})?;", r.index, r.width, r.shift),
        Operand::Memory(a, w) => format!("rt.store({}, {w},{v})?;", address(a, roles)?),
        _ => return Err("CRT emit nonwritable operand".into()),
    })
}
fn width(o: &Operand) -> u8 {
    match o {
        Operand::Reg(r) => r.width,
        Operand::Memory(_, w) => *w,
        _ => 32,
    }
}
fn binary(b: Binary) -> u8 {
    match b {
        Binary::Move => 0,
        Binary::Add => 1,
        Binary::Sub => 2,
        Binary::Xor => 3,
        Binary::And => 4,
        Binary::Or => 5,
        Binary::Sbb => 6,
        Binary::Compare => 7,
        Binary::Test => 8,
    }
}
fn register(r: Reg) -> Operand {
    Operand::Reg(r)
}
/// The caller supplies original-byte proof of each callback contract, graph
/// memory invariants and a derived instruction bound. This function is a
/// lowering utility, not an execution certificate or independent admission path.
/// Call snippets operate on rt,cpu,lease,backend. They must preserve/consume the
/// original CALL return and argument convention and emit declared effects only.
pub(crate) fn emit_graph(
    graph: &Graph,
    name: &str,
    call: impl FnMut(u32, Target) -> Result<String, String>,
    roles: &BTreeMap<u32, String>,
    step_budget: u32,
) -> Result<String, String> {
    if name.is_empty()
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        || step_budget == 0
        || step_budget > 4_000_000
    {
        return Err("CRT emit name/instruction bound".into());
    }
    let body = emit_body(graph, call, roles, step_budget)?;
    Ok(format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock,backend:&mut impl CrtBackend)->Result<CrtValue,&'static str>{{{body}}}"))
}
/// Lexical lowering for a certified caller with its own typed lifecycle token.
/// Atomic effects still require an actual `lease`; no dummy lock is introduced.
pub(crate) fn emit_body(
    graph: &Graph,
    mut call: impl FnMut(u32, Target) -> Result<String, String>,
    roles: &BTreeMap<u32, String>,
    step_budget: u32,
) -> Result<String, String> {
    if step_budget == 0 || step_budget > 4_000_000 {
        return Err("CRT emit instruction bound".into());
    }
    let mut source=format!("let mut pc={}u32;let mut local_steps=0u32;loop{{if local_steps>={step_budget}{{return Err(\"CRT original graph instruction bound\");}}local_steps+=1;cpu.tick(u32::MAX)?;match pc{{",graph.origin);
    for (&pc, node) in &graph.nodes {
        let mut out = String::new();
        let mut controlled = false;
        match &node.op{
 Op::Call(target)=>out.push_str(&call(pc,*target)?),
 Op::Ordinary(Operation::Binary(op,dst,src))=>{
 let value=if *op==Binary::Move{read(src,roles)?}else if *op==Binary::Xor&&dst==src&&matches!(dst,Operand::Reg(_)){"cpu.zero()".into()}else{out.push_str(&format!("let a={};let b={};",read(dst,roles)?,read(src,roles)?));format!("cpu.binary(rt,{},a,b,{})?",binary(*op),width(dst))};
 out.push_str(&format!("let {}={value};", if matches!(op,Binary::Compare|Binary::Test){"_"}else{"v"}));
 if !matches!(op,Binary::Compare|Binary::Test){
 if matches!(dst,Operand::Reg(Reg{index:4,width:32,shift:0}))&&*op==Binary::Add{if let Operand::Immediate(n)=src{out.push_str(&format!("cpu.discard(rt,{n})?;"));}else{return Err("CRT emit dynamic ESP cleanup outside admission".into());}}
 out.push_str(&write(dst,"v",roles)?);}
 },
 Op::Ordinary(Operation::Address(dst,a))=>out.push_str(&format!("let p={};{}",address(a,roles)?,write(&register(*dst),"CrtValue::Pointer(p)",roles)?)),
 Op::Ordinary(Operation::Push(o))=>out.push_str(&format!("let v={};cpu.push(rt,v)?;",read(o,roles)?)),
 Op::Ordinary(Operation::Pop(dst))=>out.push_str(&format!("let v=cpu.pop(rt)?;{}",write(&register(*dst),"v",roles)?)),
 Op::Ordinary(Operation::Leave)=>out.push_str("cpu.leave(rt)?;"),
 Op::Ordinary(Operation::Return)=>{out.push_str("return cpu.finish(rt);");controlled=true;},
 Op::Ordinary(Operation::Jump(target))=>{out.push_str(&format!("pc={target};continue;"));controlled=true;},
 Op::Ordinary(Operation::Branch(c,target))=>{let next=pc+node.length;out.push_str(&format!("pc=if cpu.condition({})?{{{target}}}else{{{next}}};continue;",condition(*c)));controlled=true;},
 Op::SignedBranch{condition:c,target}=>{let next=pc+node.length;let kind=match c{SignedCondition::Less=>6,SignedCondition::LessEqual=>7,SignedCondition::Greater=>8,SignedCondition::GreaterEqual=>9,SignedCondition::Sign=>10,SignedCondition::NotSign=>11};out.push_str(&format!("pc=if cpu.condition({kind})?{{{target}}}else{{{next}}};continue;"));controlled=true;},
 Op::Ordinary(Operation::Nop)=>{},
 Op::Ordinary(Operation::Increment(r)|Operation::Decrement(r))=>{let kind=if matches!(node.op,Op::Ordinary(Operation::Increment(_))){1}else{2};let o=register(*r);out.push_str(&format!("let carry=cpu.flags.cf;let a={};let v=cpu.binary(rt,{kind},a,CrtValue::scalar(1),{})?;cpu.flags.cf=carry;{}",read(&o,roles)?,r.width,write(&o,"v",roles)?));},
 Op::IncrementMemory(o)=>out.push_str(&format!("let carry=cpu.flags.cf;let a={};let v=cpu.binary(rt,1,a,CrtValue::scalar(1),32)?;cpu.flags.cf=carry;{}",read(o,roles)?,write(o,"v",roles)?)),
 Op::Ordinary(Operation::Negate(r))=>{let o=register(*r);out.push_str(&format!("let a={};let v=cpu.binary(rt,2,CrtValue::scalar(0),a,{})?;{}",read(&o,roles)?,r.width,write(&o,"v",roles)?));},
 Op::Ordinary(Operation::Not(r))=>{let o=register(*r);out.push_str(&format!("let v=CrtValue::scalar(!CrtCpu::number({})?);{}",read(&o,roles)?,write(&o,"v",roles)?));},
 Op::Ordinary(Operation::Shift{left,dst,count})=>{let o=register(*dst);out.push_str(&format!("let a={};let v=cpu.shift(a,{count},{},{})?;{}",read(&o,roles)?,if *left{0}else{1},dst.width,write(&o,"v",roles)?));},
 Op::ArithmeticShift{dst,count}=>{let o=register(*dst);out.push_str(&format!("let a={};let v=cpu.shift(a,{count},2,{})?;{}",read(&o,roles)?,dst.width,write(&o,"v",roles)?));},
 Op::Multiply{dst,source:a,factor}=>out.push_str(&format!("let a={};let v=cpu.multiply(a,{factor})?;{}",read(a,roles)?,write(&register(*dst),"v",roles)?)),
 Op::Ordinary(Operation::ZeroExtend(dst,o))|Op::SignExtend{dst,source:o}=>{let signed=matches!(node.op,Op::SignExtend{..});let w=width(o);out.push_str(&format!("let a=CrtCpu::number({})?;let v=CrtValue::scalar({});{}",read(o,roles)?,if signed{format!("(((a<<{})as i32)>>{})as u32",32-w,32-w)}else{format!("a&{}u32",if w==8{255}else{65535})},write(&register(*dst),"v",roles)?));},
 Op::Ordinary(Operation::Set(c,r))=>out.push_str(&format!("let v=CrtValue::scalar(u32::from(cpu.condition({})?));{}",condition(*c),write(&register(*r),"v",roles)?)),
 Op::Ordinary(Operation::ConditionalMove(c,dst,src))=>{let o=register(*src);out.push_str(&format!("let v={};if cpu.condition({})?{{{}}}",read(&o,roles)?,condition(*c),write(&register(*dst),"v",roles)?));},
 Op::ConditionalMove{condition:c,dst,source:o}=>out.push_str(&format!("let v={};if cpu.condition({})?{{{}}}",read(o,roles)?,condition(*c),write(&register(*dst),"v",roles)?)),
 Op::StoreString{width}=>out.push_str(&format!("let p=CrtCpu::pointer(cpu.r[7])?;let v=cpu.get(0,{width},0)?;rt.store(p,{width},v)?;cpu.r[7]=CrtValue::Pointer(rt.offset(p,{})?);",width/8)),
 Op::CopyString{width}=>out.push_str(&format!("let src=CrtCpu::pointer(cpu.r[6])?;let dst=CrtCpu::pointer(cpu.r[7])?;let v=rt.load(src,{width})?;rt.store(dst,{width},v)?;cpu.r[6]=CrtValue::Pointer(rt.offset(src,{})?);cpu.r[7]=CrtValue::Pointer(rt.offset(dst,{})?);",width/8,width/8)),
 Op::Locked{operation,destination,source:o}=>{let Operand::Memory(a,32)=destination else{return Err("CRT emit atomic word form".into());};let method=match operation{Binary::Or=>"atomic_or",Binary::And=>"atomic_and",_=>return Err("CRT emit atomic operation".into())};out.push_str(&format!("let p={};let b={};let old=rt.{method}(lease,p,CrtCpu::number(b)?)?;cpu.binary(rt,{},CrtValue::scalar(old),b,32)?;",address(a,roles)?,read(o,roles)?,binary(*operation)));},
 _=>return Err(format!("CRT emit unsupported normalized operation {:?}",node.op)),
 }
        if !controlled {
            out.push_str(&format!("pc={};continue;", pc + node.length));
        }
        source.push_str(&format!("{pc}=>{{{out}}},"));
    }
    source.push_str("_=>return Err(\"CRT control outside certified graph\"),}}");
    Ok(source)
}
