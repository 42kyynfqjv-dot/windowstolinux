//! Original bounded byte-format parser, with explicit downstream proof duties.
//! The format grammar bounds reads/state transitions; original numeric values
//! and write outcomes remain runtime data. This certificate alone cannot bind
//! integer EH, locale, FILE validation or output effects.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParserEffect {
    Validate,
    Classify,
    WriteChar,
    Integer,
}
#[derive(Clone, Copy)]
pub(crate) struct ParserBindings {
    pub validate: u32,
    pub classify: u32,
    pub write_char: u32,
    pub integer: u32,
}
pub(crate) struct ParserProof {
    graph: Graph,
    state: StateProof,
    modifier: ModifierProof,
    bindings: ParserBindings,
    jumps_address: u32,
    jumps: Vec<u8>,
}
impl ParserProof {
    pub fn prove(
        code: Region<'_>,
        jumps: Region<'_>,
        state: StateProof,
        modifier: ModifierProof,
        b: ParserBindings,
    ) -> Result<Self, String> {
        use super::super::crt_stream_ir::JumpTable;
        if jumps.bytes.len() != 32 {
            return Err("formatter parser table extent".into());
        }
        let mut graph = Graph::decode_with_tables(
            code.bytes,
            code.origin,
            &[JumpTable {
                address: jumps.origin,
                bytes: jumps.bytes,
            }],
        )?;
        let p: Vec<_> = graph.nodes.keys().copied().collect();
        if p.len() != 216 {
            return Err("formatter parser complete graph".into());
        }
        let targets: Vec<_> = jumps
            .bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|b| u32::from_le_bytes(*b))
            .collect();
        if targets
            != vec![
                p[65], p[103], p[110], p[132], p[151], p[153], p[166], p[169],
            ]
        {
            return Err("formatter parser state dispatch".into());
        }
        let mut expected = BTreeMap::new();
        let mut add = |start: usize, ops: Vec<Op>| {
            for (i, op) in ops.into_iter().enumerate() {
                expected.insert(p[start + i], op);
            }
        };
        let br = |c, i| ordinary(Operation::Branch(c, p[i]));
        let jump = |i| ordinary(Operation::Jump(p[i]));
        add(
            0,
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                bin(Binary::Sub, r(4), imm(16)),
                push(r(3)),
                push(r(6)),
                mov(r(6), r(1)),
                push(r(7)),
                push(mem(6, 8)),
                lea(1, 6, 0x448),
                Op::Call(Target::Direct(b.validate)),
                bin(Binary::Test, byte(0), byte(0)),
                br(Condition::Equal, 28),
                mov(r(1), mem(6, 12)),
                bin(Binary::Test, r(1), r(1)),
                br(Condition::NotEqual, 34),
            ],
        );
        add(
            28,
            vec![
                bin(Binary::Or, r(0), imm(u32::MAX)),
                pop(7),
                pop(6),
                pop(3),
                ordinary(Operation::Leave),
                ordinary(Operation::Return),
            ],
        );
        add(
            34,
            vec![
                mov(r(0), mem(6, 0x450)),
                ordinary(Operation::Increment(reg(0))),
                mov(mem(6, 0x450), r(0)),
                bin(Binary::Compare, r(0), imm(2)),
                br(Condition::Equal, 186),
                bin(Binary::Xor, r(3), r(3)),
                mov(mem(6, 52), r(3)),
                mov(mem8(6, 24), byte(3)),
                mov(byte(2), mem8(1, 0)),
                ordinary(Operation::Increment(reg(1))),
                mov(mem8(5, -1), byte(2)),
                mov(mem(6, 12), r(1)),
                mov(mem8(6, 45), byte(2)),
                bin(Binary::Test, byte(2), byte(2)),
                br(Condition::Equal, 183),
                mov(mem8(5, -9), byte(2)),
                lea(0, 6, 20),
                bin(Binary::Compare, mem(0, 0), r(3)),
                Op::SignedBranch {
                    condition: SignedCondition::Less,
                    target: p[183],
                },
                ordinary(Operation::ZeroExtend(reg(0), mem8(6, 24))),
                mov(r(1), r(6)),
                push(r(0)),
                push(mem(5, -9)),
                Op::Call(Target::Direct(state.origin())),
                mov(mem8(6, 24), byte(0)),
                bin(Binary::Compare, byte(0), imm(8)),
                br(Condition::AboveEqual, 212),
                ordinary(Operation::ZeroExtend(reg(0), byte(0))),
                bin(Binary::Compare, r(0), imm(7)),
                br(Condition::Above, 28),
                Op::TableJump {
                    index: reg(0),
                    address: jumps.origin,
                    targets,
                },
            ],
        );
        add(
            65,
            vec![
                mov(r(7), mem(6, 8)),
                mov(mem8(6, 56), byte(3)),
                bin(Binary::Compare, mem8(7, 20), byte(3)),
                br(Condition::NotEqual, 71),
            ],
        );
        add(
            71,
            vec![
                mov(byte(0), mem8(6, 45)),
                mov(mem(5, -16), r(0)),
                mov(mem8(5, -5), byte(0)),
                Op::SignExtend {
                    dst: reg(0),
                    source: byte(0),
                },
                push(imm(0x8000)),
                push(r(0)),
                mov(r(0), mem(7, 12)),
                push(mem(0, 0)),
                Op::Call(Target::Direct(b.classify)),
                bin(Binary::Add, r(4), imm(12)),
                lea(7, 6, 20),
                bin(Binary::Test, r(0), r(0)),
                br(Condition::Equal, 97),
            ],
        );
        add(
            97,
            vec![
                push(mem(6, 8)),
                lea(1, 6, 0x448),
                push(r(7)),
                push(mem(5, -5)),
                Op::Call(Target::Direct(b.write_char)),
                jump(173),
            ],
        );
        add(
            103,
            vec![
                bin(Binary::Or, mem(6, 36), imm(u32::MAX)),
                mov(mem(6, 32), r(3)),
                mov(mem8(6, 44), byte(3)),
                mov(mem(6, 28), r(3)),
                mov(mem(6, 40), r(3)),
                mov(mem8(6, 56), byte(3)),
                jump(173),
            ],
        );
        add(
            166,
            vec![
                mov(r(1), r(6)),
                Op::Call(Target::Direct(modifier.origin())),
                jump(171),
                mov(r(1), r(6)),
                Op::Call(Target::Direct(b.integer)),
                bin(Binary::Test, byte(0), byte(0)),
                br(Condition::Equal, 28),
                mov(r(0), mem(6, 12)),
                mov(byte(2), mem8(0, 0)),
                lea(1, 0, 1),
                mov(mem(6, 12), r(1)),
                lea(0, 6, 20),
                mov(mem8(5, -1), byte(2)),
                mov(mem8(6, 45), byte(2)),
                mov(mem8(5, -9), byte(2)),
                bin(Binary::Test, byte(2), byte(2)),
                br(Condition::NotEqual, 51),
                Op::IncrementMemory(mem(6, 0x450)),
                bin(Binary::Compare, mem(6, 0x450), imm(2)),
                br(Condition::NotEqual, 40),
                mov(r(0), mem(6, 20)),
                jump(29),
            ],
        );
        // FormatDomain and the complete audited state table establish states0,1,6,7.
        // pass_counter enters0 and becomes1 then2 exactly; locale cache stays ready;
        // independently certified nonmultibyte classification always returns0.
        let forced: BTreeMap<u32, Vec<u32>> = BTreeMap::from([
            (p[15], vec![p[34]]),
            (p[38], vec![p[39]]),
            (p[60], vec![p[61]]),
            (p[63], vec![p[64]]),
            (p[64], vec![p[65], p[103], p[166], p[169]]),
            (p[68], vec![p[71]]),
            (p[83], vec![p[97]]),
            (p[185], vec![p[186]]),
        ]);
        let mut todo = vec![graph.origin];
        let mut reached = BTreeSet::new();
        while let Some(pc) = todo.pop() {
            if reached.insert(pc) {
                let node = &graph.nodes[&pc];
                if expected.get(&pc) != Some(&node.op) {
                    return Err(format!(
                        "formatter parser unproved effect at {pc:#x}: {:?}",
                        node.op
                    ));
                }
                todo.extend(
                    forced
                        .get(&pc)
                        .cloned()
                        .unwrap_or_else(|| node.successors.clone()),
                );
            }
        }
        if reached.len() != expected.len() {
            return Err("formatter parser unused proof nodes".into());
        }
        graph.nodes.retain(|pc, _| reached.contains(pc));
        for (pc, next) in forced {
            graph.nodes.get_mut(&pc).unwrap().successors = next;
        }
        Ok(Self {
            graph,
            state,
            modifier,
            bindings: b,
            jumps_address: jumps.origin,
            jumps: jumps.bytes.to_vec(),
        })
    }
    pub fn emit(
        &self,
        name: &str,
        mut effect: impl FnMut(ParserEffect, u32, u32) -> Result<String, String>,
    ) -> Result<String, String> {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err("formatter native name".into());
        }
        let state_name = format!("{name}_state");
        let modifier_name = format!("{name}_modifier");
        let mut source = self.state.emit(&state_name)?;
        source += &self.modifier.emit(&modifier_name)?;
        let body = super::super::crt_stream_emit::emit_body(
            &self.graph,
            |pc, target| {
                let continuation = pc + self.graph.nodes[&pc].length;
                let Target::Direct(target) = target else {
                    return Err("formatter parser import boundary".into());
                };
                if target == self.state.origin() {
                    return Ok(format!(
                        "cpu.call_pop(rt,lease,backend,{continuation},8,{state_name})?;"
                    ));
                }
                if target == self.modifier.origin() {
                    return Ok(format!(
                        "cpu.call(rt,lease,backend,{continuation},{modifier_name})?;"
                    ));
                }
                let kind = if target == self.bindings.validate {
                    ParserEffect::Validate
                } else if target == self.bindings.classify {
                    ParserEffect::Classify
                } else if target == self.bindings.write_char {
                    ParserEffect::WriteChar
                } else if target == self.bindings.integer {
                    ParserEffect::Integer
                } else {
                    return Err("formatter parser unbound effect".into());
                };
                effect(kind, continuation, target)
            },
            &BTreeMap::new(),
            self.graph.nodes.len() as u32 * 4098,
        )?;
        let preflight = self.entry_source();
        source+=&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock,backend:&mut impl CrtBackend)->Result<CrtValue,&'static str>{{{preflight}{body}}}");
        Ok(source)
    }
    fn entry_source(&self) -> String {
        let mut preflight=format!("let jumps=rt.resolve_absolute({},CrtRegionKind::Module)?;for(i,expected)in {:?}.into_iter().enumerate(){{if rt.load(rt.offset(jumps,i as i64)?,8)?.known_scalar()?!=expected{{return Err(\"formatter parser immutable jump table changed\");}}}}",self.jumps_address,self.jumps.iter().map(|&b|u32::from(b)).collect::<Vec<_>>());
        preflight += r#"
rt.check_lock(lease)?;let entry=CrtCpu::pointer(cpu.r[4])?;let object=CrtCpu::pointer(cpu.r[1])?;
if cpu.returned||cpu.abi!=CrtAbi::Cdecl32Forward||cpu.r[4]!=cpu.entry[4]||entry.kind!=CrtRegionKind::Stack||entry.address()%4!=0||rt.load(entry,32)?!=CrtValue::ProtectedReturn(cpu.return_id)||!matches!(object.kind,CrtRegionKind::Stack|CrtRegionKind::Context|CrtRegionKind::Buffer){return Err("formatter parser entry ownership");}
rt.valid(object,0x454)?;let private=rt.offset(entry,-64)?;rt.valid(private,68)?;
let overlaps=|a:u32,n:u32,b:u32,m:u32|u64::from(a)<u64::from(b)+u64::from(m)&&u64::from(b)<u64::from(a)+u64::from(n);
if overlaps(object.address(),0x454,private.address(),68)||rt.overlapping_tags(private.address(),64).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_))){return Err("formatter parser private frame alias");}
if rt.load(rt.offset(object,20)?,32)?.known_scalar()?!=0||rt.load(rt.offset(object,0x450)?,32)?.known_scalar()?!=0||rt.load(rt.offset(object,0x440)?,32)?.known_scalar()?!=0{return Err("formatter parser initial counters/inline domain");}
if object.kind==CrtRegionKind::Stack&&object.address()<entry.address()+4{return Err("formatter caller-owned parser object");}
let format=CrtCpu::pointer(rt.load(rt.offset(object,12)?,32)?)?;if !matches!(format.kind,CrtRegionKind::Input|CrtRegionKind::Module){return Err("formatter immutable format owner");}let mut bytes=Vec::new();for offset in 0..=4096{let value=rt.load(rt.offset(format,offset)?,8)?.known_scalar()?as u8;bytes.push(value);if value==0{break;}}
if bytes.last()!=Some(&0){return Err("formatter bounded terminator");}
let mut at=0usize;let mut consumed=0usize;while bytes[at]!=0{if bytes[at]!=b'%' {at+=1;continue;}at+=1;if bytes[at]==b'%' {at+=1;continue;}if bytes[at]==b'l'{at+=1;}if !matches!(bytes.get(at),Some(b'd'|b'i'|b'u')){return Err("formatter unproved input directive");}consumed+=1;if consumed>64{return Err("formatter argument cap");}at+=1;}
if overlaps(format.address(),bytes.len()as u32,object.address(),0x454)||overlaps(format.address(),bytes.len()as u32,private.address(),68){return Err("formatter immutable format alias");}
if consumed!=0{let arguments=CrtCpu::pointer(rt.load(rt.offset(object,16)?,32)?)?;if !matches!(arguments.kind,CrtRegionKind::Input|CrtRegionKind::Module|CrtRegionKind::Stack)||arguments.kind==CrtRegionKind::Stack&&arguments.address()<entry.address()+4{return Err("formatter caller-owned argument range");}let extent=consumed as u32*4;rt.valid(arguments,extent)?;rt.offset(arguments,i64::from(extent))?;if overlaps(arguments.address(),extent,object.address(),0x454)||overlaps(arguments.address(),extent,private.address(),68){return Err("formatter argument alias");}for i in 0..consumed{rt.load(rt.offset(arguments,i as i64*4)?,32)?.known_scalar()?;}}
let context=CrtCpu::pointer(rt.load(rt.offset(object,8)?,32)?)?;rt.validate_error_context(context)?;
if overlaps(context.address(),40,object.address(),0x454)||overlaps(context.address(),40,private.address(),68)||overlaps(context.address(),40,format.address(),bytes.len()as u32){return Err("formatter context alias");}
if rt.load(rt.offset(context,20)?,8)?.known_scalar()?!=1{return Err("formatter initialized locale cache premise");}
let locale=CrtCpu::pointer(rt.load(rt.offset(context,12)?,32)?)?;let ctype=CrtCpu::pointer(rt.load(locale,32)?)?;if locale.kind!=CrtRegionKind::Module||ctype.kind!=CrtRegionKind::Module{return Err("formatter immutable locale ownership");}
for index in -1i64..=127{if rt.load(rt.offset(ctype,index*2)?,16)?.known_scalar()?&0x8000!=0{return Err("formatter single-byte locale domain");}}
let adapter=CrtCpu::pointer(rt.load(rt.offset(object,0x448)?,32)?)?;rt.file_record(adapter)?;
"#;
        preflight
    }
}
