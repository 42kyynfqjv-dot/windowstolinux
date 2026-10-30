//! The original scalar32 operand-consumption/sign/magnitude path. Excluded
//! widths and explicit precision are rejected at entry, before effects. Original
//! signed branches remain runtime-dependent; no argument result is specialized.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
pub(crate) struct MagnitudeProof {
    graph: Graph,
    length: LengthProof,
    decimal: DecimalProof,
}
impl MagnitudeProof {
    pub fn prove(
        code: Region<'_>,
        length: LengthProof,
        decimal: DecimalProof,
    ) -> Result<Self, String> {
        if (
            decimal.inline_offset,
            decimal.precision_offset,
            decimal.result_pointer_offset,
            decimal.result_count_offset,
        ) != (60, 36, 48, 52)
        {
            return Err("formatter magnitude/decimal object layout".into());
        }
        let mut graph = Graph::decode(code.bytes, code.origin)?;
        let p: Vec<_> = graph.nodes.keys().copied().collect();
        if p.len() != 155 {
            return Err("formatter complete operand graph".into());
        }
        let mut expected = BTreeMap::new();
        let mut add = |start: usize, ops: Vec<Op>| {
            for (i, op) in ops.into_iter().enumerate() {
                expected.insert(p[start + i], op);
            }
        };
        let branch = |c, i| ordinary(Operation::Branch(c, p[i]));
        let jump = |i| ordinary(Operation::Jump(p[i]));
        let shift = |i, n| {
            ordinary(Operation::Shift {
                left: false,
                dst: reg(i),
                count: n,
            })
        };
        add(
            0,
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                bin(Binary::Sub, r(4), imm(12)),
                push(r(3)),
                push(r(6)),
                mov(r(6), r(1)),
                push(r(7)),
                push(mem(6, 40)),
                Op::Call(Target::Direct(length.origin())),
                pop(1),
                mov(r(1), r(0)),
                mov(mem(5, -12), r(0)),
                push(imm(0)),
                pop(3),
                bin(Binary::Sub, r(1), imm(1)),
                branch(Condition::Equal, 76),
                bin(Binary::Sub, r(1), imm(1)),
                branch(Condition::Equal, 64),
                ordinary(Operation::Decrement(reg(1))),
                bin(Binary::Sub, r(1), imm(1)),
                branch(Condition::Equal, 48),
            ],
        );
        add(
            48,
            vec![
                mov(r(7), mem(6, 28)),
                mov(r(0), r(7)),
                shift(0, 4),
                bin(Binary::Test, byte(0), imm(1)),
                branch(Condition::Equal, 58),
                mov(r(0), mem(6, 16)),
                lea(1, 0, 4),
                mov(mem(6, 16), r(1)),
                mov(r(0), mem(0, 0)),
                jump(87),
                mov(r(1), mem(6, 16)),
                mov(mem(5, -8), r(3)),
                lea(0, 1, 4),
                mov(mem(6, 16), r(0)),
                mov(r(0), mem(1, 0)),
                jump(89),
            ],
        );
        add(
            87,
            vec![
                Op::SignDividend,
                mov(mem(5, -8), r(2)),
                mov(r(2), mem(5, -8)),
                mov(mem(5, -4), r(0)),
                mov(r(0), r(7)),
                mov(r(1), mem(5, -4)),
                shift(0, 4),
                bin(Binary::Test, byte(0), imm(1)),
                branch(Condition::Equal, 106),
                bin(Binary::Compare, r(2), r(3)),
                Op::SignedBranch {
                    condition: SignedCondition::Greater,
                    target: p[106],
                },
                Op::SignedBranch {
                    condition: SignedCondition::Less,
                    target: p[101],
                },
                bin(Binary::Compare, r(1), r(3)),
                branch(Condition::AboveEqual, 106),
                ordinary(Operation::Negate(reg(1))),
                Op::AddCarry {
                    destination: r(2),
                    source: r(3),
                },
                ordinary(Operation::Negate(reg(2))),
                bin(Binary::Or, r(7), imm(64)),
                mov(mem(6, 28), r(7)),
                bin(Binary::Compare, mem(6, 36), imm(0)),
                mov(mem(5, -8), r(2)),
                mov(mem(5, -4), r(1)),
                Op::SignedBranch {
                    condition: SignedCondition::GreaterEqual,
                    target: p[112],
                },
                mov(mem(6, 36), imm(1)),
                jump(120),
            ],
        );
        add(
            120,
            vec![
                mov(r(0), r(1)),
                bin(Binary::Or, r(0), r(2)),
                branch(Condition::NotEqual, 124),
                bin(Binary::And, mem(6, 28), imm(!32)),
                bin(Binary::Compare, mem(5, -12), imm(8)),
                push(mem(5, 8)),
                mov(mem8(6, 56), byte(3)),
                branch(Condition::NotEqual, 133),
            ],
        );
        add(
            133,
            vec![
                push(r(1)),
                mov(r(1), r(6)),
                Op::Call(Target::Direct(decimal.graph.origin)),
                mov(r(0), mem(6, 28)),
                shift(0, 7),
                bin(Binary::Test, byte(0), imm(1)),
                branch(Condition::Equal, 149),
            ],
        );
        add(
            149,
            vec![
                mov(byte(0), imm(1)),
                pop(7),
                pop(6),
                pop(3),
                ordinary(Operation::Leave),
                Op::ReturnPop(4),
            ],
        );
        // Dominating original length classification establishes 4; default precision
        // is -1; the admitted flags are0 orSIGNED and can only add NEGATIVE. These
        // facts establish exactly these dead edges. No sampled scalar drives pruning.
        let forced = BTreeMap::from([
            (p[16], p[17]),
            (p[18], p[19]),
            (p[21], p[48]),
            (p[109], p[110]),
            (p[127], p[133]),
            (p[139], p[149]),
        ]);
        let mut reached = BTreeSet::new();
        let mut todo = vec![graph.origin];
        while let Some(pc) = todo.pop() {
            if reached.insert(pc) {
                let node = &graph.nodes[&pc];
                if expected.get(&pc) != Some(&node.op) {
                    return Err(format!(
                        "formatter magnitude unproved effect at {pc:#x}: {:?}",
                        node.op
                    ));
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
            return Err("formatter magnitude grammar has unused proof node".into());
        }
        graph.nodes.retain(|pc, _| reached.contains(pc));
        for (pc, next) in forced {
            graph.nodes.get_mut(&pc).unwrap().successors = vec![next];
        }
        Ok(Self {
            graph,
            length,
            decimal,
        })
    }
    pub fn emit(&self, name: &str) -> Result<String, String> {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err("formatter native name".into());
        }
        let length_name = format!("{name}_length");
        let decimal_name = format!("{name}_decimal");
        let capacity_name = format!("{name}_capacity");
        let mut source = self.length.emit(&length_name)?;
        source += &self.decimal.emit(&decimal_name, &capacity_name)?;
        let body = super::super::crt_stream_emit::emit_body(
            &self.graph,
            |pc, target| {
                let (callee, pop) = if target == Target::Direct(self.length.origin()) {
                    (&length_name, 0)
                } else if target == Target::Direct(self.decimal.graph.origin) {
                    (&decimal_name, 8)
                } else {
                    return Err("formatter magnitude unproved call".into());
                };
                Ok(format!(
                    "cpu.call_pop(rt,lease,backend,{},{pop},{callee})?;",
                    pc + self.graph.nodes[&pc].length
                ))
            },
            &BTreeMap::new(),
            256,
        )?;
        let preflight = r#"
rt.check_lock(lease)?;let entry=CrtCpu::pointer(cpu.r[4])?;let object=CrtCpu::pointer(cpu.r[1])?;
if cpu.returned||cpu.abi!=CrtAbi::Cdecl32Forward||cpu.r[4]!=cpu.entry[4]||entry.kind!=CrtRegionKind::Stack||entry.address()%4!=0||rt.load(entry,32)?!=CrtValue::ProtectedReturn(cpu.return_id){return Err("formatter magnitude entry ABI");}
if !matches!(object.kind,CrtRegionKind::Context|CrtRegionKind::Stack|CrtRegionKind::Buffer){return Err("formatter magnitude writable object role");}
let private=rt.offset(entry,-64)?;rt.valid(private,72)?;rt.valid(object,0x448)?;
let overlap=|a:u32,n:u32,b:u32,m:u32|u64::from(a)<u64::from(b)+u64::from(m)&&u64::from(b)<u64::from(a)+u64::from(n);
if overlap(object.address(),0x448,private.address(),72)||rt.overlapping_tags(private.address(),64).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_))){return Err("formatter magnitude private activation alias");}
let modifier=rt.load(rt.offset(object,40)?,32)?.known_scalar()?;let flags=rt.load(rt.offset(object,28)?,32)?.known_scalar()?;
if !matches!(modifier,0|3)||!matches!(flags,0|16)||rt.load(rt.offset(object,36)?,32)?.known_scalar()?!=u32::MAX||rt.load(rt.offset(object,0x440)?,32)?.known_scalar()?!=0{return Err("formatter magnitude scalar32/default precision domain");}
rt.load(rt.offset(entry,4)?,32)?.known_scalar()?;
let argument=CrtCpu::pointer(rt.load(rt.offset(object,16)?,32)?)?;rt.load(argument,32)?.known_scalar()?;rt.offset(argument,4)?;
if overlap(argument.address(),4,private.address(),72)||overlap(argument.address(),4,object.address(),0x448){return Err("formatter magnitude argument aliases mutable state");}
for(offset,width)in [(16,32),(28,32),(36,32),(48,32),(52,32),(56,8)]{let p=rt.offset(object,offset)?;if rt.overlapping_tags(p.address(),width/8).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_))){return Err("formatter magnitude result field protected");}}
"#;
        source+=&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock,backend:&mut impl CrtBackend)->Result<CrtValue,&'static str>{{{preflight}{body}}}");
        Ok(source)
    }
}
