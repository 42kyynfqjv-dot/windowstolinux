//! Complete original byte-classification/state transition body. The finite
//! source-table audit proves parser transitions for the bounded input grammar;
//! emitted code still performs the original loads, arithmetic and return.
use super::*;
pub(crate) struct StateProof {
    graph: Graph,
    pub table_address: u32,
    pub table: Vec<u8>,
}
impl StateProof {
    pub fn prove(code: Region<'_>, table: Region<'_>) -> Result<Self, String> {
        if table.bytes.len() != 256 {
            return Err("formatter state table extent".into());
        }
        let graph = Graph::decode(code.bytes, code.origin)?;
        let p: Vec<_> = graph.nodes.keys().copied().collect();
        if p.len() != 20 {
            return Err("formatter state graph extent".into());
        }
        let indexed = |offset: u32| {
            Operand::Memory(
                Address {
                    base: None,
                    index: Some(0),
                    scale: 2,
                    displacement: offset,
                },
                8,
            )
        };
        let field = Reg {
            index: 1,
            width: 8,
            shift: 0,
        };
        let al = Reg {
            index: 0,
            width: 8,
            shift: 0,
        };
        compare(
            &graph,
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                mov(byte(1), mem8(5, 8)),
                lea(0, 1, -32),
                bin(Binary::Compare, byte(0), imm(90)),
                ordinary(Operation::Branch(Condition::Above, p[12])),
                Op::SignExtend {
                    dst: reg(0),
                    source: Operand::Reg(field),
                },
                bin(Binary::Sub, r(0), imm(32)),
                bin(Binary::And, r(0), imm(127)),
                mov(byte(0), indexed(table.origin + 1)),
                ordinary(Operation::Jump(p[13])),
                bin(Binary::Xor, byte(0), byte(0)),
                ordinary(Operation::ZeroExtend(reg(1), Operand::Reg(al))),
                ordinary(Operation::ZeroExtend(reg(0), mem8(5, 12))),
                ordinary(Operation::Address(
                    reg(0),
                    Address {
                        base: Some(0),
                        index: Some(1),
                        scale: 8,
                        displacement: 0,
                    },
                )),
                bin(Binary::And, r(0), imm(127)),
                mov(byte(0), indexed(table.origin)),
                pop(5),
                Op::ReturnPop(8),
            ],
        )?;
        let transition = |byte: u8, state: u8| {
            let class = if (32..=122).contains(&byte) {
                table.bytes[usize::from(byte - 32) * 2 + 1]
            } else {
                0
            };
            table.bytes[((usize::from(state) + usize::from(class) * 8) & 127) * 2]
        };
        // All ordinary literal bytes, not just the fixed report's sampled literals.
        for byte in 1..=255u8 {
            for state in [0, 7] {
                if transition(byte, state) != if byte == b'%' { 1 } else { 0 } {
                    return Err("formatter literal-state transition".into());
                }
            }
        }
        for state in [1, 6] {
            for byte in *b"diu" {
                if transition(byte, state) != 7 {
                    return Err("formatter integer-state transition".into());
                }
            }
        }
        if transition(b'%', 1) != 0 || transition(b'l', 1) != 6 {
            return Err("formatter percent/long transition".into());
        }
        let end = table
            .origin
            .checked_add(256)
            .ok_or("formatter state table overflow")?;
        if table.origin < graph.end && graph.origin < end {
            return Err("formatter state code/table alias".into());
        }
        Ok(Self {
            graph,
            table_address: table.origin,
            table: table.bytes.to_vec(),
        })
    }
    pub fn origin(&self) -> u32 {
        self.graph.origin
    }
    pub fn emit(&self, name: &str) -> Result<String, String> {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err("formatter native name".into());
        }
        let roles = BTreeMap::from([
            (self.table_address, "CrtRegionKind::Module".into()),
            (self.table_address + 1, "CrtRegionKind::Module".into()),
        ]);
        let preflight=format!("let table=rt.resolve_absolute({},CrtRegionKind::Module)?;for(i,expected)in {:?}.into_iter().enumerate(){{if rt.load(rt.offset(table,i as i64)?,8)?.known_scalar()?!=expected{{return Err(\"formatter immutable state table changed\");}}}}",self.table_address,self.table.iter().map(|&v|u32::from(v)).collect::<Vec<_>>());
        let body = super::super::crt_stream_emit::emit_body(
            &self.graph,
            |_, _| Err("formatter state unexpected call".into()),
            &roles,
            32,
        )?;
        Ok(format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock,backend:&mut impl CrtBackend)->Result<CrtValue,&'static str>{{{preflight}{body}}}"))
    }
}
