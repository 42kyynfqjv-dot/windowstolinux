//! Proof of a bounded original EH4 normal epilog. No body/exception certificate.
use super::{FrameLayout, PrologProof, Region};
use crate::crt_stream_ir::{Graph, Op};
use crate::graph::{Binary, Operand, Operation, Reg};

pub(crate) struct EpilogProof {
    graph: Graph,
    layout: FrameLayout,
    scope: u32,
    handler: u32,
    cookie_address: u32,
    pop: u16,
    chain_register: u8,
}

impl EpilogProof {
    pub fn prove(code: Region<'_>, prolog: &PrologProof) -> Result<Self, String> {
        let graph = Graph::decode(code.bytes, code.origin)?;
        let l = &prolog.layout;
        let nodes: Vec<_> = graph.nodes.iter().collect();
        // This initial domain has no separate normal-path guard check. The
        // original POP discards the guard; validation is a domain check, not a
        // synthesized guest security-check call.
        if nodes.len() != 8 {
            return Err("EH4 epilog complete linear instruction domain".into());
        }
        for (i, (pc, n)) in nodes.iter().enumerate() {
            let next = pc.checked_add(n.length).ok_or("EH4 epilog PC overflow")?;
            if i + 1 < nodes.len() {
                if next != *nodes[i + 1].0 || n.successors != [next] {
                    return Err("EH4 epilog edge/order".into());
                }
            } else if next != graph.end || !n.successors.is_empty() {
                return Err("EH4 epilog terminal extent".into());
            }
        }
        let Op::Ordinary(Operation::Binary(Binary::Move, Operand::Reg(r), Operand::Memory(a, 32))) =
            &nodes[0].1.op
        else {
            return Err("EH4 epilog original predecessor load".into());
        };
        if r.width != 32
            || r.shift != 0
            || r.index != 1
            || a.base != Some(5)
            || a.index.is_some()
            || a.scale != 1
            || a.displacement as i32 != l.record - l.frame_pointer
            || nodes[1].1.op != Op::FsWrite(*r)
        {
            return Err("EH4 epilog predecessor operand/FS binding".into());
        }
        let full = |index| Reg {
            index,
            width: 32,
            shift: 0,
        };
        let mut sp = l.low;
        if sp != l.guard || nodes[2].1.op != Op::Ordinary(Operation::Pop(full(1))) {
            return Err("EH4 epilog guard discard".into());
        }
        sp += 4;
        for (i, register) in [7, 6, 3].into_iter().enumerate() {
            if l.saved.get(&sp) != Some(&register)
                || nodes[i + 3].1.op != Op::Ordinary(Operation::Pop(full(register)))
            {
                return Err("EH4 epilog saved slot/order".into());
            }
            sp += 4;
        }
        if l.saved.len() != 4
            || l.saved.get(&l.frame_pointer) != Some(&5)
            || nodes[6].1.op != Op::Ordinary(Operation::Leave)
        {
            return Err("EH4 epilog LEAVE identity".into());
        }
        let Op::ReturnPop(pop) = nodes[7].1.op else {
            return Err("EH4 epilog callee cleanup form".into());
        };
        if pop > 256 || pop % 4 != 0 {
            return Err("EH4 epilog cleanup bounds".into());
        }
        let chain_register = r.index;
        Ok(Self {
            graph,
            layout: l.clone(),
            scope: prolog.scope,
            handler: prolog.handler,
            cookie_address: prolog.cookie_address,
            pop,
            chain_register,
        })
    }

    pub fn emit(&self, name: &str) -> Result<String, String> {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err("EH4 epilog name".into());
        }
        let l = &self.layout;
        let saved: Vec<_> = l.saved.iter().map(|(&o, &r)| (o, r)).collect();
        let mut code = format!("fn {name}_layout()->CrtNormalLayout{{CrtNormalLayout{{low:{},bp:{},record:{},scope_slot:{},level:{},saved_sp:{},guard:{},saved:vec!{:?},scope:{},handler:{},cookie_address:{},pop:{}}}}}\n",
            l.low,l.frame_pointer,l.record,l.scope_slot,l.level_slot,l.saved_sp,l.guard,saved,self.scope,self.handler,self.cookie_address,self.pop);
        code.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&mut CrtNormalBinding)->Result<CrtValue,&'static str>{{let result=(||{{if binding.layout!={name}_layout(){{return Err(\"EH4 epilog certificate/binding disagreement\");}}binding.epilog_entry(rt,cpu,epoch)?;"));
        let mut sp = l.low;
        for node in self.graph.nodes.values() {
            code.push_str("cpu.tick(u32::MAX)?;");
            match &node.op {
                Op::Ordinary(Operation::Binary(Binary::Move, _, _)) => code.push_str(&format!(
                    "binding.load_previous(rt,cpu,epoch,{})?;",
                    self.chain_register
                )),
                Op::FsWrite(r) => {
                    code.push_str(&format!("binding.unlink(rt,cpu,epoch,{})?;", r.index))
                }
                Op::Ordinary(Operation::Pop(r)) => {
                    code.push_str(&format!("binding.pop(rt,cpu,epoch,{sp},{})?;", r.index));
                    sp += 4;
                }
                Op::Ordinary(Operation::Leave) => code.push_str("binding.leave(rt,cpu,epoch)?;"),
                Op::ReturnPop(_) => code.push_str("return binding.finish(rt,cpu,epoch);"),
                _ => return Err("EH4 epilog proof/emission disagreement".into()),
            }
        }
        code.push_str("})();match result{Ok(v)=>Ok(v),Err(e)=>epoch.fail(e)}}\n");
        Ok(code)
    }
}
