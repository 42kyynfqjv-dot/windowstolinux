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
    let role = if let Some(role) = roles.get(&a.displacement) {
        format!("Some({role})")
    } else if a.base.is_none() {
        return Err("CRT emit unbound absolute address role".into());
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
fn lea_address(a: &Address, roles: &BTreeMap<u32, String>) -> String {
    let role = if a.base.is_none() {
        roles
            .get(&a.displacement)
            .map(|r| format!("Some({r})"))
            .unwrap_or_else(|| "None".into())
    } else {
        "None".into()
    };
    format!(
        "cpu.lea(rt,{:?},{:?},{},{},{role})?",
        a.base.map(usize::from),
        a.index.map(usize::from),
        a.scale,
        a.displacement
    )
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
/// A path established by a separate semantic proof, not sampled execution.
/// Original conditional edges are still checked at runtime before lowering the
/// branch. Only a bound terminal call may have an explicit unexecuted cut.
#[allow(dead_code)] // Used by the connected owned handler compiler.
pub(crate) struct PathStep<'a> {
    pub pc: u32,
    pub bytes: &'a [u8],
    pub next: Option<u32>,
}
#[allow(dead_code)] // Used by the connected owned handler compiler.
pub(crate) fn emit_proved_path(
    path: &[PathStep<'_>],
    call: impl FnMut(u32, Target) -> Result<String, String>,
    roles: &BTreeMap<u32, String>,
    before: impl FnMut(u32, &Op) -> Result<String, String>,
) -> Result<String, String> {
    emit_proved_path_with_store(path, call, roles, before, |_, _, _| Ok(None))
}
#[allow(dead_code)]
pub(crate) fn emit_proved_path_with_store(
    path: &[PathStep<'_>],
    call: impl FnMut(u32, Target) -> Result<String, String>,
    roles: &BTreeMap<u32, String>,
    mut before: impl FnMut(u32, &Op) -> Result<String, String>,
    store: impl FnMut(u32, &Address, u8) -> Result<Option<String>, String>,
) -> Result<String, String> {
    if path.is_empty() || path.len() > 2048 {
        return Err("CRT path: instruction budget".into());
    }
    let mut nodes: BTreeMap<u32, super::crt_stream_ir::Node> = BTreeMap::new();
    let mut expected = BTreeMap::new();
    let mut end = 0;
    for (index, step) in path.iter().enumerate() {
        let mut node = Graph::decode_instruction(step.bytes, step.pc)?;
        if nodes.contains_key(&step.pc) {
            return Err("CRT path: repeated instruction requires loop proof".into());
        }
        let instruction_end = step.pc + node.length;
        if nodes
            .range(..step.pc)
            .next_back()
            .is_some_and(|(&pc, previous)| pc + previous.length > step.pc)
            || nodes.range(step.pc..instruction_end).next().is_some()
        {
            return Err("CRT path: overlapping instruction cuts".into());
        }
        if index + 1 == path.len() {
            if step.next.is_some() || !matches!(node.op, Op::Call(_)) {
                return Err("CRT path: terminal call cut".into());
            }
        } else if step.next != Some(path[index + 1].pc)
            || !node.successors.contains(&path[index + 1].pc)
        {
            return Err("CRT path: original successor mismatch".into());
        }
        end = end.max(step.pc + node.length);
        expected.insert(step.pc, step.next);
        node.successors = step.next.into_iter().collect();
        nodes.insert(step.pc, node);
    }
    let graph = Graph {
        origin: path[0].pc,
        end,
        nodes,
    };
    emit_body_with_store(
        &graph,
        call,
        roles,
        path.len() as u32,
        |_, _| Err("CRT path: unbound thread effect".into()),
        |pc, op| {
            let branch = match op {
                Op::Ordinary(Operation::Branch(c, t)) => Some((condition(*c), *t)),
                Op::SignedBranch {
                    condition: c,
                    target,
                } => Some((
                    match c {
                        SignedCondition::Less => 6,
                        SignedCondition::LessEqual => 7,
                        SignedCondition::Greater => 8,
                        SignedCondition::GreaterEqual => 9,
                        SignedCondition::Sign => 10,
                        SignedCondition::NotSign => 11,
                    },
                    *target,
                )),
                _ => None,
            };
            let mut code = String::new();
            if let Some((kind, target)) = branch {
                let next = expected[&pc].ok_or("CRT path: branch without proved edge")?;
                let fallthrough = pc + graph.nodes[&pc].length;
                code.push_str(&format!("if (if cpu.condition({kind})?{{{target}u32}}else{{{fallthrough}u32}})!={next}u32{{return Err(\"CRT branch disagrees with semantic proof\");}}"));
            }
            code.push_str(&before(pc, op)?);
            Ok(code)
        },
        |_, _| Err("CRT path: unproved return".into()),
        None,
        store,
    )
}
/// Lexical lowering for a certified caller with its own typed lifecycle token.
/// Atomic effects still require an actual `lease`; no dummy lock is introduced.
pub(crate) fn emit_body(
    graph: &Graph,
    call: impl FnMut(u32, Target) -> Result<String, String>,
    roles: &BTreeMap<u32, String>,
    step_budget: u32,
) -> Result<String, String> {
    emit_body_with_thread(graph, call, roles, step_budget, |_, _| {
        Err("CRT emit unbound thread-head effect".into())
    })
}
/// Only a wrapper with a proved typed registry projection may supply this hook.
/// Original FS effects are never lowered as host pointers or ignored prefixes.
pub(crate) fn emit_body_with_thread(
    graph: &Graph,
    call: impl FnMut(u32, Target) -> Result<String, String>,
    roles: &BTreeMap<u32, String>,
    step_budget: u32,
    thread: impl FnMut(u32, &Op) -> Result<String, String>,
) -> Result<String, String> {
    emit_body_with_hooks(
        graph,
        call,
        roles,
        step_budget,
        thread,
        |_, _| Ok(String::new()),
        |_, _| Ok(None),
    )
}
/// A straight-line original instruction cut returns to the compiler-owned
/// component boundary without executing RET or consuming a continuation.
#[allow(dead_code)]
pub(crate) fn emit_linear_fragment(
    graph: &Graph,
    roles: &BTreeMap<u32, String>,
) -> Result<String, String> {
    if graph.nodes.is_empty() || graph.nodes.len() > 128 {
        return Err("CRT fragment instruction budget".into());
    }
    for (&pc, node) in &graph.nodes {
        if node.successors != [pc + node.length] {
            return Err("CRT fragment requires one original fallthrough".into());
        }
    }
    emit_body_with_exit(
        graph,
        |_, _| Err("CRT fragment call unbound".into()),
        roles,
        128,
        |_, _| Err("CRT fragment thread effect unbound".into()),
        |_, _| Ok(String::new()),
        |_, _| Err("CRT fragment cannot return".into()),
        Some(graph.end),
    )
}
/// Proof-bound bookkeeping precedes the original instruction; it cannot replace
/// arbitrary instructions. Only an independently validated special return ABI
/// may override RET. Ordinary callers retain exact protected-return checks.
pub(crate) fn emit_body_with_hooks(
    graph: &Graph,
    call: impl FnMut(u32, Target) -> Result<String, String>,
    roles: &BTreeMap<u32, String>,
    step_budget: u32,
    thread: impl FnMut(u32, &Op) -> Result<String, String>,
    before: impl FnMut(u32, &Op) -> Result<String, String>,
    return_hook: impl FnMut(u32, u16) -> Result<Option<String>, String>,
) -> Result<String, String> {
    emit_body_with_exit(
        graph,
        call,
        roles,
        step_budget,
        thread,
        before,
        return_hook,
        None,
    )
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_body_with_exit(
    graph: &Graph,
    call: impl FnMut(u32, Target) -> Result<String, String>,
    roles: &BTreeMap<u32, String>,
    step_budget: u32,
    thread: impl FnMut(u32, &Op) -> Result<String, String>,
    before: impl FnMut(u32, &Op) -> Result<String, String>,
    return_hook: impl FnMut(u32, u16) -> Result<Option<String>, String>,
    exit: Option<u32>,
) -> Result<String, String> {
    emit_body_with_store(
        graph,
        call,
        roles,
        step_budget,
        thread,
        before,
        return_hook,
        exit,
        |_, _, _| Ok(None),
    )
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_body_with_store(
    graph: &Graph,
    call: impl FnMut(u32, Target) -> Result<String, String>,
    roles: &BTreeMap<u32, String>,
    step_budget: u32,
    thread: impl FnMut(u32, &Op) -> Result<String, String>,
    before: impl FnMut(u32, &Op) -> Result<String, String>,
    return_hook: impl FnMut(u32, u16) -> Result<Option<String>, String>,
    exit: Option<u32>,
    store: impl FnMut(u32, &Address, u8) -> Result<Option<String>, String>,
) -> Result<String, String> {
    emit_body_with_indirect(
        graph,
        call,
        roles,
        step_budget,
        thread,
        before,
        return_hook,
        exit,
        store,
        |_, _| Err("CRT emit indirect call requires target proof".into()),
    )
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_body_with_indirect(
    graph: &Graph,
    mut call: impl FnMut(u32, Target) -> Result<String, String>,
    roles: &BTreeMap<u32, String>,
    step_budget: u32,
    mut thread: impl FnMut(u32, &Op) -> Result<String, String>,
    mut before: impl FnMut(u32, &Op) -> Result<String, String>,
    mut return_hook: impl FnMut(u32, u16) -> Result<Option<String>, String>,
    exit: Option<u32>,
    mut store: impl FnMut(u32, &Address, u8) -> Result<Option<String>, String>,
    mut indirect: impl FnMut(u32, &Operand) -> Result<String, String>,
) -> Result<String, String> {
    if graph
        .nodes
        .values()
        .flat_map(|n| &n.successors)
        .any(|target| !graph.nodes.contains_key(target) && Some(*target) != exit)
    {
        return Err("CRT emit unresolved external control edge".into());
    }
    if step_budget == 0 || step_budget > 4_000_000 {
        return Err("CRT emit instruction bound".into());
    }
    let terminal = exit
        .map(|exit| format!("if pc=={exit}{{return Ok(cpu.r[0]);}}"))
        .unwrap_or_default();
    let mut source=format!("let mut pc={}u32;let mut local_steps=0u32;loop{{{terminal}if local_steps>={step_budget}{{return Err(\"CRT original graph instruction bound\");}}local_steps+=1;cpu.tick(u32::MAX)?;match pc{{",graph.origin);
    for (&pc, node) in &graph.nodes {
        let mut out = before(pc, &node.op)?;
        let mut controlled = false;
        match &node.op{
 Op::Exchange{address:a,register:r}=>{out.push_str(&format!("let p={};let incoming=cpu.get({},32,0)?;let old=rt.exchange_module_word(p,incoming)?;cpu.set({},32,0,old)?;",address(a,roles)?,r.index,r.index));},
 Op::Call(target)=>out.push_str(&call(pc,*target)?),
 Op::IndirectCall(operand)=>{out.push_str(&format!("let target={};",read(operand,roles)?));out.push_str(&indirect(pc,operand)?);},
 Op::FsRead(_)|Op::FsWrite(_)|Op::FsPush=>out.push_str(&thread(pc,&node.op)?),
 Op::ReturnPop(bytes)=>{out.push_str(&return_hook(pc,*bytes)?.unwrap_or_else(||format!("return cpu.finish_pop(rt,{bytes});")));controlled=true;},
 Op::SignDividend=>out.push_str("cpu.sign_dividend()?;"),
 Op::AddCarry{destination,source:operand}=>out.push_str(&format!("let a={};let b={};let v=cpu.add_carry(a,b)?;{}",read(destination,roles)?,read(operand,roles)?,write(destination,"v",roles)?)),
 Op::DivideUnsigned(operand)=>out.push_str(&format!("let divisor={};cpu.divide_unsigned(divisor)?;",read(operand,roles)?)),
 Op::TableJump{index,address:table,targets}=>{
  out.push_str(&format!("let index=cpu.get({},32,0)?.known_scalar()?;let targets:&[u32]=&{:?};let expected=*targets.get(index as usize).ok_or(\"CRT unproved table index\")?;let table=rt.resolve_absolute({table},CrtRegionKind::Module)?;let word=rt.load(rt.offset(table,i64::from(index)*4)?,32)?.known_scalar()?;if word!=expected{{return Err(\"CRT original jump table changed\");}}pc=word;continue;",index.index,targets));controlled=true;
 },
 Op::Ordinary(Operation::Binary(op,dst,src))=>{
 let value=if *op==Binary::Move{read(src,roles)?}else if *op==Binary::Xor&&dst==src&&matches!(dst,Operand::Reg(_)){"cpu.zero()".into()}else{out.push_str(&format!("let a={};let b={};",read(dst,roles)?,read(src,roles)?));format!("cpu.binary(rt,{},a,b,{})?",binary(*op),width(dst))};
 out.push_str(&format!("let {}={value};", if matches!(op,Binary::Compare|Binary::Test){"_"}else{"v"}));
 if !matches!(op,Binary::Compare|Binary::Test){
 if matches!(dst,Operand::Reg(Reg{index:4,width:32,shift:0}))&&*op==Binary::Add{if let Operand::Immediate(n)=src{out.push_str(&format!("cpu.discard(rt,{n})?;"));}else{return Err("CRT emit dynamic ESP cleanup outside admission".into());}}
 let special=if *op==Binary::Move{if let Operand::Memory(address,width)=dst{store(pc,address,*width)?}else{None}}else{None};
 out.push_str(&special.unwrap_or(write(dst,"v",roles)?));}
 },
 Op::Ordinary(Operation::Address(dst,a))=>out.push_str(&format!("let v={};{}",lea_address(a,roles),write(&register(*dst),"v",roles)?)),
 Op::Ordinary(Operation::Push(o))=>out.push_str(&format!("let v={};cpu.push(rt,v)?;",read(o,roles)?)),
 Op::Ordinary(Operation::Pop(dst))=>out.push_str(&format!("let v=cpu.pop(rt)?;{}",write(&register(*dst),"v",roles)?)),
 Op::Ordinary(Operation::Leave)=>out.push_str("cpu.leave(rt)?;"),
 Op::Ordinary(Operation::Return)=>{out.push_str(&return_hook(pc,0)?.unwrap_or_else(||"return cpu.finish(rt);".into()));controlled=true;},
 Op::Ordinary(Operation::Jump(target))=>{out.push_str(&format!("pc={target};continue;"));controlled=true;},
 Op::Ordinary(Operation::Branch(c,target))=>{let next=pc+node.length;out.push_str(&format!("pc=if cpu.condition({})?{{{target}}}else{{{next}}};continue;",condition(*c)));controlled=true;},
 Op::SignedBranch{condition:c,target}=>{let next=pc+node.length;let kind=match c{SignedCondition::Less=>6,SignedCondition::LessEqual=>7,SignedCondition::Greater=>8,SignedCondition::GreaterEqual=>9,SignedCondition::Sign=>10,SignedCondition::NotSign=>11};out.push_str(&format!("pc=if cpu.condition({kind})?{{{target}}}else{{{next}}};continue;"));controlled=true;},
 Op::Ordinary(Operation::Nop)=>{},
 Op::Ordinary(Operation::Increment(r)|Operation::Decrement(r))=>{let kind=if matches!(node.op,Op::Ordinary(Operation::Increment(_))){1}else{2};let o=register(*r);out.push_str(&format!("let carry=cpu.flags.cf;let a={};let v=cpu.binary(rt,{kind},a,CrtValue::scalar(1),{})?;cpu.flags.cf=carry;{}",read(&o,roles)?,r.width,write(&o,"v",roles)?));},
 Op::IncrementMemory(o)=>out.push_str(&format!("let carry=cpu.flags.cf;let a={};let v=cpu.binary(rt,1,a,CrtValue::scalar(1),32)?;cpu.flags.cf=carry;{}",read(o,roles)?,write(o,"v",roles)?)),
 Op::DecrementMemory(o)=>out.push_str(&format!("let carry=cpu.flags.cf;let a={};let v=cpu.binary(rt,2,a,CrtValue::scalar(1),32)?;cpu.flags.cf=carry;{}",read(o,roles)?,write(o,"v",roles)?)),
 Op::Ordinary(Operation::Negate(r))=>{let o=register(*r);out.push_str(&format!("let a={};let v=cpu.binary(rt,2,CrtValue::scalar(0),a,{})?;{}",read(&o,roles)?,r.width,write(&o,"v",roles)?));},
 Op::Ordinary(Operation::Not(r))=>{let o=register(*r);out.push_str(&format!("let v=CrtValue::scalar(!CrtCpu::number({})?);{}",read(&o,roles)?,write(&o,"v",roles)?));},
 Op::Ordinary(Operation::Shift{left,dst,count})=>{let o=register(*dst);out.push_str(&format!("let a={};let v=cpu.shift(a,{count},{},{})?;{}",read(&o,roles)?,if *left{0}else{1},dst.width,write(&o,"v",roles)?));},
 Op::ArithmeticShift{dst,count}=>{let o=register(*dst);out.push_str(&format!("let a={};let v=cpu.shift(a,{count},2,{})?;{}",read(&o,roles)?,dst.width,write(&o,"v",roles)?));},
 Op::MultiplyValue{dst,source:a}=>out.push_str(&format!("let a={};let b={};let v=cpu.multiply(a,CrtCpu::number(b)?)?;{}",read(&register(*dst),roles)?,read(a,roles)?,write(&register(*dst),"v",roles)?)),
 Op::Multiply{dst,source:a,factor}=>out.push_str(&format!("let a={};let v=cpu.multiply(a,{factor})?;{}",read(a,roles)?,write(&register(*dst),"v",roles)?)),
 Op::Ordinary(Operation::ZeroExtend(dst,o))|Op::SignExtend{dst,source:o}=>{let signed=matches!(node.op,Op::SignExtend{..});let w=width(o);out.push_str(&format!("let a=CrtCpu::number({})?;let v=CrtValue::scalar({});{}",read(o,roles)?,if signed{format!("(((a<<{})as i32)>>{})as u32",32-w,32-w)}else{format!("a&{}u32",if w==8{255}else{65535})},write(&register(*dst),"v",roles)?));},
 Op::Ordinary(Operation::Set(c,r))=>out.push_str(&format!("let v=CrtValue::scalar(u32::from(cpu.condition({})?));{}",condition(*c),write(&register(*r),"v",roles)?)),
 Op::Ordinary(Operation::ConditionalMove(c,dst,src))=>{let o=register(*src);out.push_str(&format!("let v={};if cpu.condition({})?{{{}}}",read(&o,roles)?,condition(*c),write(&register(*dst),"v",roles)?));},
 Op::SignedMove{condition:c,dst,source:o}=>{let kind=match c{SignedCondition::Less=>6,SignedCondition::Greater=>8,_=>return Err("CRT signed selection condition".into())};out.push_str(&format!("let v={};if cpu.condition({kind})?{{{}}}",read(o,roles)?,write(&register(*dst),"v",roles)?));},
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

#[cfg(test)]
mod indirect_rejection_tests {
    use super::*;
    #[test]
    fn indirect_register_and_table_calls_need_explicit_lowering_contract() {
        for code in [
            &[0xff, 0xd0, 0xc3][..],
            &[0xff, 0x14, 0x85, 0x84, 0x51, 0x41, 0, 0xc3][..],
        ] {
            assert!(Graph::decode(code, 0x710000).is_err());
            let call = Graph::decode_instruction(&code[..code.len() - 1], 0x710000).unwrap();
            let ret = Graph::decode_instruction(
                &code[code.len() - 1..],
                0x710000 + code.len() as u32 - 1,
            )
            .unwrap();
            let graph = Graph {
                origin: 0x710000,
                end: 0x710000 + code.len() as u32,
                nodes: BTreeMap::from([(0x710000, call), (0x710000 + code.len() as u32 - 1, ret)]),
            };
            assert!(Graph::decode_linear_fragment(code, 0x710000).is_err());
            let result = emit_body(
                &graph,
                |_, _| panic!("indirect call must not become a direct/import call"),
                &BTreeMap::from([(0x415184, "CrtRegionKind::Module".into())]),
                32,
            );
            assert_eq!(
                result.unwrap_err(),
                "CRT emit indirect call requires target proof"
            );
        }
    }
}
