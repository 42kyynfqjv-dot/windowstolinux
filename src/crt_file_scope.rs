//! Original FILE wrapper normal scope, including the actual lock/cleanup calls.
//! The formatter driver is an explicit component cut, NOT a no-escape proof.
//! Errors preserve the reached stack, lock and registry; no unwind is invented.
use super::{EpilogProof, PrologProof, Region};
use crate::crt_stream_ir::{Graph, Op, Target};
use crate::graph::{Address, Binary, Operand, Operation, Reg};
use std::collections::BTreeMap;

fn r(index: u8) -> Operand {
    Operand::Reg(Reg {
        index,
        width: 32,
        shift: 0,
    })
}
fn m(base: u8, displacement: i32) -> Operand {
    Operand::Memory(
        Address {
            base: Some(base),
            index: None,
            scale: 1,
            displacement: displacement as u32,
        },
        32,
    )
}
fn bin(op: Binary, a: Operand, b: Operand) -> Op {
    Op::Ordinary(Operation::Binary(op, a, b))
}
fn mov(a: Operand, b: Operand) -> Op {
    bin(Binary::Move, a, b)
}
fn push(a: Operand) -> Op {
    Op::Ordinary(Operation::Push(a))
}
fn pop(index: u8) -> Op {
    let Operand::Reg(reg) = r(index) else {
        unreachable!()
    };
    Op::Ordinary(Operation::Pop(reg))
}
fn exact_linear(graph: &Graph, expected: &[Op]) -> Result<(), String> {
    if graph.nodes.len() != expected.len() {
        return Err("FILE scope complete graph extent".into());
    }
    for ((pc, node), op) in graph.nodes.iter().zip(expected) {
        let next = pc
            .checked_add(node.length)
            .ok_or("FILE scope PC overflow")?;
        let end = next == graph.end;
        if &node.op != op
            || (!end && node.successors != [next])
            || (end && !node.successors.is_empty())
        {
            return Err(format!("FILE scope instruction/edge mismatch at {pc:#x}"));
        }
    }
    Ok(())
}

/// All code ranges are original immutable bytes. IAT identities must come from
/// separately validated imports. The normal cleanup entry is distinct from the
/// unwind entry that restores ESI; admitting one does not admit the other.
pub(crate) struct Input<'a> {
    pub wrapper: Region<'a>, // after the separately proved prolog through RET
    pub lock: Region<'a>,
    pub unlock: Region<'a>,
    pub cleanup: Region<'a>, // normal entry only
    pub enter_iat: u32,
    pub leave_iat: u32,
    pub driver: u32,
}
pub(crate) struct FileScopeProof {
    wrapper: Graph,
    lock: Graph,
    unlock: Graph,
    cleanup: Graph,
    epilog: EpilogProof,
    driver: u32,
    enter_iat: u32,
    leave_iat: u32,
    result_offset: i32,
}
impl FileScopeProof {
    pub fn prove(input: Input<'_>, prolog: &PrologProof) -> Result<Self, String> {
        if input.enter_iat == 0
            || input.leave_iat == 0
            || input.enter_iat == input.leave_iat
            || !input.enter_iat.is_multiple_of(4)
            || !input.leave_iat.is_multiple_of(4)
            || input.driver == 0
        {
            return Err("FILE scope distinct import/driver bindings".into());
        }
        let wrapper = Graph::decode(input.wrapper.bytes, input.wrapper.origin)?;
        let lock = Graph::decode(input.lock.bytes, input.lock.origin)?;
        let unlock = Graph::decode(input.unlock.bytes, input.unlock.origin)?;
        let cleanup = Graph::decode(input.cleanup.bytes, input.cleanup.origin)?;
        let regions = [&wrapper, &lock, &unlock, &cleanup];
        for (i, a) in regions.iter().enumerate() {
            for b in &regions[i + 1..] {
                if a.origin < b.end && b.origin < a.end {
                    return Err("FILE scope overlapping code ranges".into());
                }
            }
            if input.driver >= a.origin && input.driver < a.end {
                return Err("FILE scope recursive driver alias".into());
            }
            for iat in [input.enter_iat, input.leave_iat] {
                let end = iat.checked_add(4).ok_or("FILE scope import extent")?;
                if iat < a.end && a.origin < end {
                    return Err("FILE scope import/code alias".into());
                }
            }
        }
        let leaf = |iat| {
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                mov(r(0), m(5, 8)),
                bin(Binary::Add, r(0), Operand::Immediate(32)),
                push(r(0)),
                Op::Call(Target::Import(iat)),
                pop(5),
                Op::Ordinary(Operation::Return),
            ]
        };
        exact_linear(&lock, &leaf(input.enter_iat))?;
        exact_linear(&unlock, &leaf(input.leave_iat))?;
        exact_linear(
            &cleanup,
            &[
                mov(r(0), m(5, 16)),
                push(m(0, 0)),
                Op::Call(Target::Direct(unlock.origin)),
                pop(1),
                Op::Ordinary(Operation::Return),
            ],
        )?;
        let nodes: Vec<_> = wrapper.nodes.iter().collect();
        if nodes.len() != 21 {
            return Err("FILE scope wrapper extent".into());
        }
        if nodes.last().unwrap().1.op != Op::ReturnPop(12) {
            return Err("FILE scope three argument cleanup convention".into());
        }
        let epilog_origin = *nodes[13].0;
        let start = (epilog_origin - input.wrapper.origin) as usize;
        let epilog = EpilogProof::prove(
            Region {
                bytes: &input.wrapper.bytes[start..],
                origin: epilog_origin,
            },
            prolog,
        )?;
        let Op::Ordinary(Operation::Binary(
            Binary::And,
            Operand::Memory(a, 32),
            Operand::Immediate(0),
        )) = &nodes[0].1.op
        else {
            return Err("FILE scope original result initialization".into());
        };
        let result_offset = a.displacement as i32;
        let relative = result_offset
            .checked_add(prolog.layout.frame_pointer)
            .ok_or("FILE scope local offset overflow")?;
        // This private word must be inside allocated locals, outside all EH4
        // metadata, saved words and guard. Do not infer ownership from alignment.
        let locals_start = prolog
            .layout
            .low
            .checked_add(16)
            .ok_or("FILE scope local range")?;
        if a.base != Some(5)
            || a.index.is_some()
            || a.scale != 1
            || result_offset % 4 != 0
            || relative < locals_start
            || relative
                .checked_add(4)
                .is_none_or(|end| end > prolog.layout.saved_sp)
        {
            return Err("FILE scope result aliases metadata/saved state".into());
        }
        let level = prolog.layout.level_slot - prolog.layout.frame_pointer;
        let mut expected = vec![
            bin(Binary::And, m(5, result_offset), Operand::Immediate(0)),
            mov(r(0), m(5, 8)),
            push(m(0, 0)),
            Op::Call(Target::Direct(lock.origin)),
            pop(1),
            bin(Binary::And, m(5, level), Operand::Immediate(0)),
            mov(r(1), m(5, 12)),
            Op::Call(Target::Direct(input.driver)),
            mov(r(6), r(0)),
            mov(m(5, result_offset), r(6)),
            mov(m(5, level), Operand::Immediate((-2i32) as u32)),
            Op::Call(Target::Direct(cleanup.origin)),
            mov(r(0), r(6)),
        ];
        expected.extend(epilog.graph.nodes.values().map(|n| n.op.clone()));
        exact_linear(&wrapper, &expected)?;
        Ok(Self {
            wrapper,
            lock,
            unlock,
            cleanup,
            epilog,
            driver: input.driver,
            enter_iat: input.enter_iat,
            leave_iat: input.leave_iat,
            result_offset,
        })
    }

    /// Component lowering only. `driver` executes through the shared protected
    /// call mechanism, under the acquired lease. A Result::Err is an unsupported
    /// effect/domain failure, never a modeled Windows exception or termination.
    pub fn emit_component(&self, name: &str) -> Result<String, String> {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err("FILE scope emitted name".into());
        }
        let roles = BTreeMap::new();
        let mut source = self.epilog.emit(&format!("{name}_epilog"))?;
        for (graph, iat, acquire, suffix) in [
            (&self.lock, self.enter_iat, true, "lock"),
            (&self.unlock, self.leave_iat, false, "unlock"),
        ] {
            let body = crate::crt_stream_emit::emit_body(
                graph,
                |pc, target| {
                    if target != Target::Import(iat) {
                        return Err("FILE scope unbound lock effect".into());
                    }
                    let next = pc + graph.nodes[&pc].length;
                    let effect = if acquire {
                        "if lease.is_some(){return Err(\"FILE duplicate lock acquisition\");}*lease=Some(rt.lock_file(rt.thread,file)?);"
                    } else {
                        "let token=lease.ok_or(\"FILE cleanup without acquisition\")?;if token.record!=file.address(){return Err(\"FILE cleanup lock identity\");}rt.unlock(token)?;*lease=None;"
                    };
                    Ok(format!(
                        r#"cpu.call_activation(rt,{next},4,|rt,api|{{
 let sp=CrtCpu::pointer(api.r[4])?;let actual=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;
 if actual!=rt.offset(file,32)?{{return Err("FILE critical section identity");}}
 {effect}
 api.clobber(CrtValue::Scalar{{bits:0,known:0}});api.finish_pop(rt,4)
 }})?;"#
                    ))
                },
                &roles,
                32,
            )?;
            source.push_str(&format!("fn {name}_{suffix}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,file:CrtPointer,lease:&mut Option<CrtLock>)->Result<CrtValue,&'static str>{{{body}}}\n"));
        }
        let cleanup = crate::crt_stream_emit::emit_body(
            &self.cleanup,
            |pc, target| {
                if target != Target::Direct(self.unlock.origin) {
                    return Err("FILE cleanup unbound call".into());
                }
                Ok(format!(
                    "cpu.call_activation(rt,{},0,|rt,cpu|{name}_unlock(rt,cpu,file,lease))?;",
                    pc + self.cleanup.nodes[&pc].length
                ))
            },
            &roles,
            32,
        )?;
        source.push_str(&format!("fn {name}_cleanup(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,file:CrtPointer,lease:&mut Option<CrtLock>)->Result<CrtValue,&'static str>{{{cleanup}}}\n"));
        // Delegate the exact proved suffix as a block, rather than duplicating
        // its FS/POP/RET bookkeeping. This IR tail denotes the original epilog;
        // it is not a guest RET inserted into the original byte stream.
        let mut graph = self.wrapper.clone();
        let tail = self.epilog.graph.origin;
        graph.nodes.retain(|pc, _| *pc <= tail);
        let node = graph.nodes.get_mut(&tail).unwrap();
        node.op = Op::Ordinary(Operation::Return);
        node.successors.clear();
        let body = crate::crt_stream_emit::emit_body_with_hooks(
            &graph,
            |pc, target| {
                let next = pc + graph.nodes[&pc].length;
                if target == Target::Direct(self.lock.origin) {
                    Ok(format!("cpu.call_activation(rt,{next},0,|rt,cpu|{name}_lock(rt,cpu,file,&mut lease))?;"))
                } else if target == Target::Direct(self.driver) {
                    Ok(format!(
                        r#"binding.image(rt,cpu,epoch)?;
 if rt.load(binding.at(rt,binding.layout.level)?,32)?.known_scalar()?!=0{{return Err("FILE inactive formatter scope");}}
 let token=lease.ok_or("FILE body missing lock")?;rt.check_lock(token)?;
 let saved_locks=rt.locks.clone();
 cpu.call_activation(rt,{next},0,|rt,cpu|driver(rt,cpu,token))?;
 if rt.locks!=saved_locks{{return Err("FILE body altered lock lifetime");}}
 binding.image(rt,cpu,epoch)?;
 if rt.load(binding.at(rt,binding.layout.level)?,32)?.known_scalar()?!=0{{return Err("FILE body altered scope lifetime");}}
 "#
                    ))
                } else if target == Target::Direct(self.cleanup.origin) {
                    Ok(format!("cpu.call_activation(rt,{next},0,|rt,cpu|{name}_cleanup(rt,cpu,file,&mut lease))?;"))
                } else {
                    Err("FILE scope unknown callee".into())
                }
            },
            &roles,
            128,
            |_, _| Err("FILE scope unexpected FS outside epilog".into()),
            |_, _| Ok(String::new()),
            |pc, pop| {
                if pc != tail || pop != 0 {
                    return Err("FILE scope epilog delegation".into());
                }
                Ok(Some(format!("if lease.is_some(){{return Err(\"FILE epilog before cleanup\");}}return {name}_epilog(rt,cpu,epoch,binding);")))
            },
        )?;
        source.push_str(&format!(r#"
fn {name}<F>(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&mut CrtNormalBinding,mut driver:F)->Result<CrtValue,&'static str>
where F:FnMut(&mut CrtStreamRuntime,&mut CrtCpu,CrtLock)->Result<CrtValue,&'static str>{{
 let result=(||{{
 if binding.layout!={name}_epilog_layout(){{return Err("FILE scope certificate identity");}}
 binding.epilog_entry(rt,cpu,epoch)?;
 let bp=CrtCpu::pointer(cpu.r[5])?;
 let lock_holder=CrtCpu::pointer(rt.load(rt.offset(bp,8)?,32)?)?;
 let unlock_holder=CrtCpu::pointer(rt.load(rt.offset(bp,16)?,32)?)?;
 let file=CrtCpu::pointer(rt.load(lock_holder,32)?)?;
 if rt.load(unlock_holder,32)?!=CrtValue::Pointer(file){{return Err("FILE lock/cleanup argument alias mismatch");}}
 rt.file_record(file)?;
 if !rt.lock_objects.contains(&file.address()){{return Err("FILE uninitialized critical section");}}
 let local=rt.offset(bp,{result_offset})?;rt.valid(local,4)?;
 let mut lease=None;
 {body}
 }})();match result{{Ok(value)=>Ok(value),Err(error)=>epoch.fail(error)}}
}}
"#,result_offset=self.result_offset));
        Ok(source)
    }
}
