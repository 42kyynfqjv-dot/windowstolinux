//! Original character/count adapters. Actual buffer insertion remains a required
//! proved callee, not an invented successful write or host formatting shortcut.
use super::*;
pub(crate) struct OutputProof {
    count: Graph,
    character: Graph,
    pub insertion: u32,
}
impl OutputProof {
    pub fn prove(count: Region<'_>, character: Region<'_>, insertion: u32) -> Result<Self, String> {
        let count = Graph::decode(count.bytes, count.origin)?;
        let character = Graph::decode(character.bytes, character.origin)?;
        let p: Vec<_> = count.nodes.keys().copied().collect();
        if p.len() != 14 {
            return Err("formatter character count graph extent".into());
        }
        compare(
            &count,
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                push(mem(5, 16)),
                push(mem(5, 8)),
                Op::Call(Target::Direct(character.origin)),
                bin(Binary::Test, byte(0), byte(0)),
                mov(r(0), mem(5, 12)),
                ordinary(Operation::Branch(Condition::Equal, p[11])),
                Op::IncrementMemory(mem(0, 0)),
                ordinary(Operation::Jump(p[12])),
                bin(Binary::Or, mem(0, 0), imm(u32::MAX)),
                pop(5),
                Op::ReturnPop(12),
            ],
        )?;
        let p: Vec<_> = character.nodes.keys().copied().collect();
        if p.len() != 24 {
            return Err("formatter character adapter graph extent".into());
        }
        compare(
            &character,
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                mov(r(0), mem(1, 0)),
                mov(r(0), mem(0, 12)),
                ordinary(Operation::Nop),
                ordinary(Operation::Shift {
                    left: false,
                    dst: reg(0),
                    count: 12,
                }),
                bin(Binary::Test, byte(0), imm(1)),
                ordinary(Operation::Branch(Condition::Equal, p[14])),
                mov(r(0), mem(1, 0)),
                bin(Binary::Compare, mem(0, 4), imm(0)),
                ordinary(Operation::Branch(Condition::NotEqual, p[14])),
                mov(byte(0), imm(1)),
                ordinary(Operation::Jump(p[22])),
                push(mem(5, 12)),
                Op::SignExtend {
                    dst: reg(0),
                    source: mem8(5, 8),
                },
                push(mem(1, 0)),
                push(r(0)),
                Op::Call(Target::Direct(insertion)),
                bin(Binary::Add, r(4), imm(12)),
                bin(Binary::Compare, r(0), imm(u32::MAX)),
                ordinary(Operation::Set(
                    Condition::NotEqual,
                    Reg {
                        index: 0,
                        width: 8,
                        shift: 0,
                    },
                )),
                pop(5),
                Op::ReturnPop(8),
            ],
        )?;
        Ok(Self {
            count,
            character,
            insertion,
        })
    }
    pub fn emit(&self, prefix: &str, insertion_name: &str) -> Result<String, String> {
        if [prefix, insertion_name]
            .iter()
            .any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        {
            return Err("formatter native name".into());
        }
        let cname = format!("{prefix}_character");
        let nname = format!("{prefix}_count");
        let cbody = super::super::crt_stream_emit::emit_body(
            &self.character,
            |pc, target| {
                if target != Target::Direct(self.insertion) {
                    return Err("formatter insertion target".into());
                }
                Ok(format!(
                    "cpu.call(rt,lease,backend,{},{insertion_name})?;",
                    pc + self.character.nodes[&pc].length
                ))
            },
            &BTreeMap::new(),
            64,
        )?;
        let nbody = super::super::crt_stream_emit::emit_body(
            &self.count,
            |pc, target| {
                if target != Target::Direct(self.character.origin) {
                    return Err("formatter character target".into());
                }
                Ok(format!(
                    "cpu.call_pop(rt,lease,backend,{},8,{cname})?;",
                    pc + self.count.nodes[&pc].length
                ))
            },
            &BTreeMap::new(),
            32,
        )?;
        // The parent parser/dispatch proof supplies full scratch, disjoint source and
        // count ownership. These local guards bind the actual FILE lease and prevent
        // count wrap; neither validates the insertion's external effects by itself.
        let cpre = r#"rt.check_lock(lease)?;let adapter=CrtCpu::pointer(cpu.r[1])?;let file=CrtCpu::pointer(rt.load(adapter,32)?)?;rt.file_record(file)?;if lease.record!=file.address()||rt.load(rt.offset(file,12)?,32)?.known_scalar()?&0x1000!=0{return Err("formatter real narrow FILE output domain");}"#;
        let npre = r#"let entry=CrtCpu::pointer(cpu.r[4])?;let count=CrtCpu::pointer(rt.load(rt.offset(entry,8)?,32)?)?;let n=rt.load(count,32)?.known_scalar()?;if n>16383{return Err("formatter count initialized nonnegative bound");}"#;
        Ok(format!("fn {cname}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock,backend:&mut impl CrtBackend)->Result<CrtValue,&'static str>{{{cpre}{cbody}}}\nfn {nname}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock,backend:&mut impl CrtBackend)->Result<CrtValue,&'static str>{{{npre}{nbody}}}"))
    }
}

/// Original span adapter, including temporary errno preservation and the
/// EILSEQ fallback branch. No successful-write assumption prunes those effects.
pub(crate) struct SpanProof {
    graph: Graph,
    character: u32,
}
impl SpanProof {
    pub fn prove(code: Region<'_>, character: u32) -> Result<Self, String> {
        let graph = Graph::decode(code.bytes, code.origin)?;
        let p: Vec<_> = graph.nodes.keys().copied().collect();
        if p.len() != 73 {
            return Err("formatter span complete graph".into());
        }
        let br = |c, i| ordinary(Operation::Branch(c, p[i]));
        let jump = |i| ordinary(Operation::Jump(p[i]));
        compare(
            &graph,
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                mov(r(0), mem(1, 0)),
                mov(r(0), mem(0, 12)),
                ordinary(Operation::Nop),
                ordinary(Operation::Shift {
                    left: false,
                    dst: reg(0),
                    count: 12,
                }),
                bin(Binary::Test, byte(0), imm(1)),
                br(Condition::Equal, 17),
                mov(r(0), mem(1, 0)),
                bin(Binary::Compare, mem(0, 4), imm(0)),
                br(Condition::NotEqual, 17),
                mov(r(1), mem(5, 16)),
                mov(r(0), mem(5, 12)),
                bin(Binary::Add, mem(1, 0), r(0)),
                pop(5),
                Op::ReturnPop(16),
                pop(5),
                jump(19),
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                bin(Binary::Sub, r(4), imm(16)),
                push(r(3)),
                mov(r(3), mem(5, 8)),
                push(r(6)),
                mov(r(6), mem(5, 20)),
                mov(mem(5, -4), r(1)),
                mov(r(0), mem(6, 24)),
                mov(mem(5, -12), r(0)),
                mov(r(0), mem(6, 28)),
                mov(mem(5, -16), r(0)),
                mov(r(0), mem(5, 12)),
                bin(Binary::Add, r(0), r(3)),
                mov(mem(5, -8), r(0)),
                bin(Binary::Compare, r(3), r(0)),
                br(Condition::Equal, 65),
                push(r(7)),
                mov(r(7), mem(5, 16)),
                ordinary(Operation::ZeroExtend(reg(0), mem8(3, 0))),
                push(r(6)),
                push(r(0)),
                Op::Call(Target::Direct(character)),
                bin(Binary::Test, byte(0), byte(0)),
                br(Condition::NotEqual, 55),
                bin(Binary::Compare, mem8(6, 28), byte(0)),
                br(Condition::Equal, 63),
                bin(Binary::Compare, mem(6, 24), imm(42)),
                br(Condition::NotEqual, 63),
                mov(r(1), mem(5, -4)),
                push(r(6)),
                push(imm(63)),
                Op::Call(Target::Direct(character)),
                bin(Binary::Test, byte(0), byte(0)),
                br(Condition::Equal, 57),
                Op::IncrementMemory(mem(7, 0)),
                jump(58),
                bin(Binary::Or, mem(7, 0), imm(u32::MAX)),
                ordinary(Operation::Increment(reg(3))),
                bin(Binary::Compare, r(3), mem(5, -8)),
                br(Condition::Equal, 64),
                mov(r(1), mem(5, -4)),
                jump(39),
                bin(Binary::Or, mem(7, 0), imm(u32::MAX)),
                pop(7),
                mov(r(0), mem(5, -12)),
                mov(mem(6, 24), r(0)),
                mov(r(0), mem(5, -16)),
                mov(mem(6, 28), r(0)),
                pop(6),
                pop(3),
                ordinary(Operation::Leave),
                Op::ReturnPop(16),
            ],
        )?;
        Ok(Self { graph, character })
    }
    pub fn emit(&self, name: &str, character_name: &str) -> Result<String, String> {
        if [name, character_name]
            .iter()
            .any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        {
            return Err("formatter native name".into());
        }
        let body = super::super::crt_stream_emit::emit_body(
            &self.graph,
            |pc, target| {
                if target != Target::Direct(self.character) {
                    return Err("formatter span character binding".into());
                }
                Ok(format!(
                    "cpu.call_pop(rt,lease,backend,{},8,{character_name})?;",
                    pc + self.graph.nodes[&pc].length
                ))
            },
            &BTreeMap::new(),
            73 * (16384 + 1),
        )?;
        let preflight = r#"
rt.check_lock(lease)?;let entry=CrtCpu::pointer(cpu.r[4])?;if cpu.returned||cpu.r[4]!=cpu.entry[4]||entry.kind!=CrtRegionKind::Stack||rt.load(entry,32)?!=CrtValue::ProtectedReturn(cpu.return_id){return Err("formatter span entry");}
let adapter=CrtCpu::pointer(cpu.r[1])?;let file=CrtCpu::pointer(rt.load(adapter,32)?)?;rt.file_record(file)?;
if lease.record!=file.address()||rt.load(rt.offset(file,12)?,32)?.known_scalar()?&0x1000!=0{return Err("formatter span narrow FILE domain");}
let input=CrtCpu::pointer(rt.load(rt.offset(entry,4)?,32)?)?;let length=rt.load(rt.offset(entry,8)?,32)?.known_scalar()?;
let count=CrtCpu::pointer(rt.load(rt.offset(entry,12)?,32)?)?;let oldcount=rt.load(count,32)?.known_scalar()?;
let context=CrtCpu::pointer(rt.load(rt.offset(entry,16)?,32)?)?;rt.validate_error_context(context)?;
if length>16384||oldcount>16384||oldcount.checked_add(length).is_none_or(|n|n>16384){return Err("formatter span count range");}
rt.valid(input,length)?;rt.offset(input,i64::from(length))?;for i in 0..length{rt.load(rt.offset(input,i64::from(i))?,8)?.known_scalar()?;}
let private=rt.offset(entry,-44)?;rt.valid(private,64)?;
let overlap=|a:u32,n:u32,b:u32,m:u32|u64::from(a)<u64::from(b)+u64::from(m)&&u64::from(b)<u64::from(a)+u64::from(n);
for(p,n)in[(input,length),(count,4),(context,40),(adapter,4),(file,56)]{if overlap(p.address(),n,private.address(),64){return Err("formatter span caller/private alias");}}
if overlap(count.address(),4,input.address(),length)||overlap(context.address(),40,input.address(),length)||overlap(context.address(),40,count.address(),4)||overlap(file.address(),56,count.address(),4)||overlap(file.address(),56,input.address(),length)||rt.overlapping_tags(private.address(),44).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_))){return Err("formatter span effect alias");}
"#;
        Ok(format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock,backend:&mut impl CrtBackend)->Result<CrtValue,&'static str>{{{preflight}{body}}}"))
    }
}
