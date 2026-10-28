//! The single-long modifier path, proven from the original branch graph.
//! Other modifier families and the external tail dispatch remain excluded by
//! the validated input grammar; no external edge is emitted as a success stub.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
pub(crate) struct ModifierProof {
    graph: Graph,
}
impl ModifierProof {
    pub fn prove(code: Region<'_>, integer_dispatch: u32) -> Result<Self, String> {
        let mut graph = Graph::decode_with_exits(code.bytes, code.origin, &[integer_dispatch])?;
        let p: Vec<_> = graph.nodes.keys().copied().collect();
        if p.len() != 120 {
            return Err("formatter modifier graph extent".into());
        }
        let branch = |c, i| ordinary(Operation::Branch(c, p[i]));
        let expected = BTreeMap::from([
            (p[0], mov(byte(0), mem8(1, 45))),
            (p[1], bin(Binary::Compare, byte(0), imm(70))),
            (p[2], branch(Condition::NotEqual, 9)),
            (p[9], bin(Binary::Xor, r(2), r(2))),
            (p[10], bin(Binary::Compare, byte(0), imm(78))),
            (p[11], branch(Condition::NotEqual, 31)),
            (p[31], bin(Binary::Compare, mem(1, 40), r(2))),
            (p[32], branch(Condition::NotEqual, 17)),
            (p[33], bin(Binary::Compare, byte(0), imm(106))),
            (
                p[34],
                Op::SignedBranch {
                    condition: SignedCondition::Greater,
                    target: p[94],
                },
            ),
            (p[94], bin(Binary::Compare, byte(0), imm(108))),
            (p[95], branch(Condition::Equal, 108)),
            (p[108], mov(r(0), mem(1, 12))),
            (p[109], bin(Binary::Compare, mem8(0, 0), imm(108))),
            (p[110], branch(Condition::NotEqual, 115)),
            (p[115], push(imm(3))),
            (p[116], pop(0)),
            (p[117], mov(mem(1, 40), r(0))),
            (p[118], mov(byte(0), imm(1))),
            (p[119], ordinary(Operation::Return)),
        ]);
        let forced = BTreeMap::from([
            (p[2], p[9]),
            (p[11], p[31]),
            (p[32], p[33]),
            (p[34], p[94]),
            (p[95], p[108]),
            (p[110], p[115]),
        ]);
        let mut todo = vec![graph.origin];
        let mut reached = BTreeSet::new();
        while let Some(pc) = todo.pop() {
            if reached.insert(pc) {
                let node = graph
                    .nodes
                    .get(&pc)
                    .ok_or("formatter unresolved modifier edge")?;
                if expected.get(&pc) != Some(&node.op) {
                    return Err(format!("formatter modifier unproved effect at {pc:#x}"));
                }
                todo.extend(
                    forced
                        .get(&pc)
                        .map(|v| vec![*v])
                        .unwrap_or_else(|| node.successors.clone()),
                );
            }
        }
        if reached.len() != expected.len() {
            return Err("formatter modifier unused proof node".into());
        }
        graph.nodes.retain(|pc, _| reached.contains(pc));
        for (pc, next) in forced {
            graph.nodes.get_mut(&pc).unwrap().successors = vec![next];
        }
        Ok(Self { graph })
    }
    pub fn origin(&self) -> u32 {
        self.graph.origin
    }
    pub fn emit(&self, name: &str) -> Result<String, String> {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err("formatter native name".into());
        }
        let body = super::super::crt_stream_emit::emit_body(
            &self.graph,
            |_, _| Err("formatter modifier unexpected call".into()),
            &BTreeMap::new(),
            32,
        )?;
        let preflight = r#"
rt.check_lock(lease)?;let object=CrtCpu::pointer(cpu.r[1])?;let entry=CrtCpu::pointer(cpu.r[4])?;
if !matches!(object.kind,CrtRegionKind::Stack|CrtRegionKind::Context|CrtRegionKind::Buffer)||cpu.r[4]!=cpu.entry[4]||entry.kind!=CrtRegionKind::Stack||rt.load(entry,32)?!=CrtValue::ProtectedReturn(cpu.return_id){return Err("formatter modifier owner/entry");}
rt.valid(object,46)?;let private=rt.offset(entry,-4)?;rt.valid(private,4)?;
if u64::from(object.address())<u64::from(entry.address())+4&&u64::from(private.address())<u64::from(object.address())+46||rt.overlapping_tags(private.address(),4).iter().any(|(_,v)|matches!(v,CrtValue::OpaqueSaved(_)|CrtValue::ProtectedReturn(_))){return Err("formatter modifier scratch alias");}
if rt.load(rt.offset(object,45)?,8)?.known_scalar()?!=108||rt.load(rt.offset(object,40)?,32)?.known_scalar()?!=0{return Err("formatter single-long domain");}
let following=CrtCpu::pointer(rt.load(rt.offset(object,12)?,32)?)?;if !matches!(rt.load(following,8)?.known_scalar()?,100|105|117){return Err("formatter single-long next directive");}
"#;
        Ok(format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock,backend:&mut impl CrtBackend)->Result<CrtValue,&'static str>{{{preflight}{body}}}"))
    }
}
