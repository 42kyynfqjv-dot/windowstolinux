//! Original bounded length-enum classification and table provenance.
use super::*;

pub(crate) struct LengthProof {
    graph: Graph,
    pub classes_address: u32,
    pub classes: Vec<u8>,
    pub jumps_address: u32,
    pub jumps: Vec<u8>,
}
impl LengthProof {
    pub fn prove(code: Region<'_>, classes: Region<'_>, jumps: Region<'_>) -> Result<Self, String> {
        use super::super::crt_stream_ir::{ByteTable, JumpTable};
        if classes.bytes.len() != 12 || jumps.bytes.len() != 20 {
            return Err("formatter length table extent".into());
        }
        let graph = Graph::decode_with_table_maps(
            code.bytes,
            code.origin,
            &[JumpTable {
                address: jumps.origin,
                bytes: jumps.bytes,
            }],
            &[ByteTable {
                address: classes.origin,
                bytes: classes.bytes,
            }],
        )?;
        let p: Vec<_> = graph.nodes.keys().copied().collect();
        if p.len() != 23 {
            return Err(format!("formatter length graph nodes {}", p.len()));
        }
        let targets: Vec<_> = jumps
            .bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|n| u32::from_le_bytes(*n))
            .collect();
        // Only default and single-long enum meanings are needed by this entry
        // domain. All other original table cases remain faithfully emitted.
        if targets != vec![p[16], p[8], p[12], p[18], p[20]]
            || classes.bytes[0] != 0
            || classes.bytes[3] != 0
        {
            return Err("formatter default/long length proof".into());
        }
        let absolute = Operand::Memory(
            Address {
                base: Some(0),
                index: None,
                scale: 1,
                displacement: classes.origin,
            },
            8,
        );
        compare(
            &graph,
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                mov(r(0), mem(5, 8)),
                bin(Binary::Compare, r(0), imm(11)),
                ordinary(Operation::Branch(Condition::Above, p[20])),
                ordinary(Operation::ZeroExtend(reg(0), absolute)),
                Op::TableJump {
                    index: reg(0),
                    address: jumps.origin,
                    targets,
                },
                bin(Binary::Xor, r(0), r(0)),
                ordinary(Operation::Increment(reg(0))),
                pop(5),
                ordinary(Operation::Return),
                push(imm(2)),
                pop(0),
                pop(5),
                ordinary(Operation::Return),
                push(imm(4)),
                ordinary(Operation::Jump(p[13])),
                push(imm(8)),
                ordinary(Operation::Jump(p[13])),
                bin(Binary::Xor, r(0), r(0)),
                pop(5),
                ordinary(Operation::Return),
            ],
        )?;
        for region in [classes, jumps] {
            let end = region
                .origin
                .checked_add(region.bytes.len() as u32)
                .ok_or("formatter length data extent")?;
            if region.origin < graph.end && graph.origin < end {
                return Err("formatter length instruction/data alias".into());
            }
        }
        Ok(Self {
            graph,
            classes_address: classes.origin,
            classes: classes.bytes.to_vec(),
            jumps_address: jumps.origin,
            jumps: jumps.bytes.to_vec(),
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
            (self.classes_address, "CrtRegionKind::Module".into()),
            (self.jumps_address, "CrtRegionKind::Module".into()),
        ]);
        let mut preflight = String::new();
        for (address, bytes) in [
            (self.classes_address, &self.classes),
            (self.jumps_address, &self.jumps),
        ] {
            preflight+=&format!("let table=rt.resolve_absolute({address},CrtRegionKind::Module)?;for(i,expected)in {:?}.into_iter().enumerate(){{if rt.load(rt.offset(table,i as i64)?,8)?.known_scalar()?!=expected{{return Err(\"formatter immutable length table changed\");}}}}",bytes.iter().map(|v|u32::from(*v)).collect::<Vec<_>>());
        }
        let body = super::super::crt_stream_emit::emit_body(
            &self.graph,
            |_, _| Err("formatter length unexpected call".into()),
            &roles,
            32,
        )?;
        Ok(format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock,backend:&mut impl CrtBackend)->Result<CrtValue,&'static str>{{{preflight}{body}}}"))
    }
}
