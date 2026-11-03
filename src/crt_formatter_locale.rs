//! Original FILE/encoding validation and ctype word lookup.
//!
//! These are typed component entry domains, not CRT initialization. The actual
//! original graphs execute; no validation or multibyte result is substituted.
//! Null FILE/unknown descriptor/invalid-parameter callbacks remain outside this
//! certificate and are rejected before its first original effect.
use super::*;

fn direct(graph: &Graph, index: usize) -> Result<u32, String> {
    match graph.nodes.values().nth(index).map(|node| &node.op) {
        Some(Op::Call(Target::Direct(target))) => Ok(*target),
        _ => Err("formatter locale original direct dependency".into()),
    }
}
fn name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err("formatter locale native identifier".into());
    }
    Ok(())
}

pub(crate) struct ValidationProof {
    adapter: Graph,
    encoding: Graph,
    fileno: Graph,
    pub descriptor_table: u32,
    pub invalid_descriptor: u32,
}
impl ValidationProof {
    pub fn prove(
        adapter: Region<'_>,
        encoding: Region<'_>,
        fileno: Region<'_>,
    ) -> Result<Self, String> {
        let adapter = Graph::decode(adapter.bytes, adapter.origin)?;
        let encoding = Graph::decode(encoding.bytes, encoding.origin)?;
        let fileno = Graph::decode(fileno.bytes, fileno.origin)?;
        let a: Vec<_> = adapter.nodes.keys().copied().collect();
        let e: Vec<_> = encoding.nodes.keys().copied().collect();
        let f: Vec<_> = fileno.nodes.keys().copied().collect();
        if (a.len(), e.len(), f.len()) != (25, 51, 16) {
            return Err("formatter locale complete original graph extent".into());
        }
        let null_parameter = direct(&adapter, 16)?;
        let errno = direct(&fileno, 6)?;
        let invalid_parameter = direct(&fileno, 8)?;
        let Op::Ordinary(Operation::Binary(
            Binary::Move,
            Operand::Reg(destination),
            Operand::Immediate(invalid_descriptor),
        )) = encoding.nodes[&e[14]].op
        else {
            return Err("formatter invalid-descriptor source operand".into());
        };
        if destination != reg(1) {
            return Err("formatter invalid-descriptor register".into());
        }
        let Op::Ordinary(Operation::Binary(Binary::Add, _, Operand::Memory(table, 32))) =
            &encoding.nodes[&e[24]].op
        else {
            return Err("formatter descriptor table source operand".into());
        };
        if table.base.is_some()
            || table.index != Some(2)
            || table.scale != 4
            || !table.displacement.is_multiple_of(4)
        {
            return Err("formatter descriptor table addressing".into());
        }
        let descriptor_table = table.displacement;
        let table = Operand::Memory(table.clone(), 32);
        compare(
            &adapter,
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                mov(r(0), mem(1, 0)),
                bin(Binary::Test, r(0), r(0)),
                ordinary(Operation::Branch(Condition::NotEqual, a[20])),
                mov(r(0), mem(5, 8)),
                push(r(0)),
                mov(mem8(0, 28), imm(1)),
                mov(mem(0, 24), imm(22)),
                bin(Binary::Xor, r(0), r(0)),
                push(r(0)),
                push(r(0)),
                push(r(0)),
                push(r(0)),
                push(r(0)),
                Op::Call(Target::Direct(null_parameter)),
                bin(Binary::Add, r(4), imm(24)),
                bin(Binary::Xor, byte(0), byte(0)),
                ordinary(Operation::Jump(a[23])),
                push(r(0)),
                Op::Call(Target::Direct(encoding.origin)),
                pop(1),
                pop(5),
                Op::ReturnPop(4),
            ],
        )?;
        compare(
            &fileno,
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                mov(r(0), mem(5, 8)),
                bin(Binary::Test, r(0), r(0)),
                ordinary(Operation::Branch(Condition::NotEqual, f[12])),
                Op::Call(Target::Direct(errno)),
                mov(mem(0, 0), imm(22)),
                Op::Call(Target::Direct(invalid_parameter)),
                bin(Binary::Or, r(0), imm(u32::MAX)),
                pop(5),
                ordinary(Operation::Return),
                mov(r(0), mem(0, 16)),
                ordinary(Operation::Nop),
                pop(5),
                ordinary(Operation::Return),
            ],
        )?;
        compare(
            &encoding,
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                mov(r(1), mem(5, 8)),
                push(r(6)),
                mov(r(0), mem(1, 12)),
                ordinary(Operation::Nop),
                ordinary(Operation::Shift {
                    left: false,
                    dst: reg(0),
                    count: 12,
                }),
                bin(Binary::Test, byte(0), imm(1)),
                ordinary(Operation::Branch(Condition::NotEqual, e[47])),
                push(r(7)),
                push(r(1)),
                Op::Call(Target::Direct(fileno.origin)),
                pop(1),
                mov(r(1), imm(invalid_descriptor)),
                bin(Binary::Compare, r(0), imm(u32::MAX)),
                ordinary(Operation::Branch(Condition::Equal, e[26])),
                bin(Binary::Compare, r(0), imm(u32::MAX - 1)),
                ordinary(Operation::Branch(Condition::Equal, e[26])),
                mov(r(6), r(0)),
                mov(r(2), r(0)),
                bin(Binary::And, r(6), imm(63)),
                Op::ArithmeticShift {
                    dst: reg(2),
                    count: 6,
                },
                Op::Multiply {
                    dst: reg(7),
                    source: r(6),
                    factor: 56,
                },
                bin(Binary::Add, r(7), table.clone()),
                ordinary(Operation::Jump(e[31])),
                mov(r(2), r(0)),
                mov(r(6), r(0)),
                Op::ArithmeticShift {
                    dst: reg(2),
                    count: 6,
                },
                mov(r(7), r(1)),
                bin(Binary::And, r(6), imm(63)),
                bin(Binary::Compare, mem8(7, 41), imm(0)),
                pop(7),
                ordinary(Operation::Branch(Condition::NotEqual, e[42])),
                bin(Binary::Compare, r(0), imm(u32::MAX)),
                ordinary(Operation::Branch(Condition::Equal, e[40])),
                bin(Binary::Compare, r(0), imm(u32::MAX - 1)),
                ordinary(Operation::Branch(Condition::Equal, e[40])),
                Op::Multiply {
                    dst: reg(1),
                    source: r(6),
                    factor: 56,
                },
                bin(Binary::Add, r(1), table),
                bin(Binary::Test, mem8(1, 45), imm(1)),
                ordinary(Operation::Branch(Condition::Equal, e[47])),
                Op::Call(Target::Direct(errno)),
                mov(mem(0, 0), imm(22)),
                Op::Call(Target::Direct(invalid_parameter)),
                bin(Binary::Xor, byte(0), byte(0)),
                ordinary(Operation::Jump(e[48])),
                mov(byte(0), imm(1)),
                pop(6),
                pop(5),
                ordinary(Operation::Return),
            ],
        )?;
        for (i, left) in [&adapter, &encoding, &fileno].into_iter().enumerate() {
            for right in [&adapter, &encoding, &fileno].into_iter().skip(i + 1) {
                if left.origin < right.end && right.origin < left.end {
                    return Err("formatter validation code alias".into());
                }
            }
            for cell in [descriptor_table, invalid_descriptor] {
                let end = cell
                    .checked_add(4)
                    .ok_or("formatter descriptor address overflow")?;
                if cell < left.end && left.origin < end {
                    return Err("formatter validation code/module alias".into());
                }
            }
        }
        Ok(Self {
            adapter,
            encoding,
            fileno,
            descriptor_table,
            invalid_descriptor,
        })
    }
    pub fn origin(&self) -> u32 {
        self.adapter.origin
    }
    pub fn encoding_origin(&self) -> u32 {
        self.encoding.origin
    }
    pub fn fileno_origin(&self) -> u32 {
        self.fileno.origin
    }
    pub fn emit(&self, prefix: &str) -> Result<String, String> {
        name(prefix)?;
        let roles = BTreeMap::from([(self.descriptor_table, "CrtRegionKind::Module".into())]);
        let fileno_body = super::super::crt_stream_emit::emit_body(
            &self.fileno,
            |_, _| Ok("return Err(\"formatter null FILE callback escaped entry proof\");".into()),
            &roles,
            4_000_000,
        )?;
        let encoding_body = super::super::crt_stream_emit::emit_body(
            &self.encoding,
            |pc, target| {
                if target == Target::Direct(self.fileno.origin) {
                    Ok(format!(
                        "cpu.call(rt,lease,backend,{}, {prefix}_fileno)?;",
                        pc + self.encoding.nodes[&pc].length
                    ))
                } else {
                    Ok(
                        "return Err(\"formatter invalid encoding callback escaped entry proof\");"
                            .into(),
                    )
                }
            },
            &roles,
            4_000_000,
        )?;
        let adapter_body = super::super::crt_stream_emit::emit_body(
            &self.adapter,
            |pc, target| {
                if target == Target::Direct(self.encoding.origin) {
                    Ok(format!(
                        "cpu.call(rt,lease,backend,{}, {prefix}_encoding)?;",
                        pc + self.adapter.nodes[&pc].length
                    ))
                } else {
                    Ok("return Err(\"formatter null FILE callback escaped entry proof\");".into())
                }
            },
            &roles,
            4_000_000,
        )?;
        Ok(format!(
            r#"
// The decoded original checks execute after this owned-input domain is proved.
// No invalid-parameter/PTD callback is assigned success semantics.
fn {prefix}_frame(rt:&CrtStreamRuntime,cpu:&CrtCpu,lease:CrtLock,depth:u32,args:u32)->Result<CrtPointer,&'static str>{{
 rt.check_lock(lease)?;let sp=CrtCpu::pointer(cpu.r[4])?;
 if cpu.returned||cpu.r[4]!=cpu.entry[4]||sp.kind!=CrtRegionKind::Stack||sp.address()%4!=0||rt.load(sp,32)?!=CrtValue::ProtectedReturn(cpu.return_id){{return Err("formatter validation original stack entry");}}
 let bottom=rt.offset(sp,-i64::from(depth))?;rt.valid(bottom,depth+4+args)?;
 if rt.overlapping_tags(bottom.address(),depth).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_))){{return Err("formatter validation protected scratch");}}
 Ok(sp)
}}
fn {prefix}_file(rt:&CrtStreamRuntime,file:CrtPointer,lease:CrtLock)->Result<(),&'static str>{{
 rt.check_lock(lease)?;rt.file_record(file)?;
 if file.address()!=lease.record{{return Err("formatter validation FILE lease identity");}}
 let flags=rt.load(rt.offset(file,12)?,32)?.known_scalar()?;
 if flags&0x1000==0{{
  let fd=rt.load(rt.offset(file,16)?,32)?.known_scalar()?;
  if fd>2047{{return Err("formatter validation descriptor index domain");}}
  let id=rt.descriptors.iter().find(|d|d.live&&d.id.number==fd).ok_or("formatter validation descriptor identity")?.id;
  let expected=rt.descriptor_record(id)?;
  let table=rt.resolve_absolute({table},CrtRegionKind::Module)?;
  let base=CrtCpu::pointer(rt.load(rt.offset(table,i64::from(fd>>6)*4)?,32)?)?;
  let actual=rt.offset(base,i64::from(fd&63)*56)?;
  if actual!=expected{{return Err("formatter validation descriptor table/owner mismatch");}}
  if rt.load(rt.offset(actual,41)?,8)?.known_scalar()?!=0||rt.load(rt.offset(actual,45)?,8)?.known_scalar()?&1!=0{{return Err("formatter invalid encoding outside effect closure");}}
 }}
 Ok(())
}}
fn {prefix}_fileno(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock,backend:&mut impl CrtBackend)->Result<CrtValue,&'static str>{{
 let sp={prefix}_frame(rt,cpu,lease,4,4)?;let file=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;
 rt.file_record(file)?;if file.address()!=lease.record{{return Err("formatter fileno FILE ownership");}}
 rt.load(rt.offset(file,16)?,32)?.known_scalar()?;
 {fileno_body}
}}
fn {prefix}_encoding(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock,backend:&mut impl CrtBackend)->Result<CrtValue,&'static str>{{
 let sp={prefix}_frame(rt,cpu,lease,24,4)?;let file=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;{prefix}_file(rt,file,lease)?;
 {encoding_body}
}}
fn {prefix}_validate(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock,backend:&mut impl CrtBackend)->Result<CrtValue,&'static str>{{
 let sp={prefix}_frame(rt,cpu,lease,36,4)?;let holder=CrtCpu::pointer(cpu.r[1])?;rt.valid(holder,4)?;
 let bottom=rt.offset(sp,-36)?;
 if u64::from(holder.address())<u64::from(sp.address())+8&&u64::from(bottom.address())<u64::from(holder.address())+4{{return Err("formatter validation holder/frame alias");}}
 let file=CrtCpu::pointer(rt.load(holder,32)?)?;{prefix}_file(rt,file,lease)?;
 let context=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;rt.validate_error_context(context)?;
 if u64::from(context.address())<u64::from(sp.address())+8&&u64::from(bottom.address())<u64::from(context.address())+40{{return Err("formatter validation context/frame alias");}}
 {adapter_body}
}}
"#,
            table = self.descriptor_table
        ))
    }
}

/// Actual bounded ctype-array read. Returned bits are data-dependent; the parser
/// separately proves no lead-byte path for its admitted format storage. A table
/// is never constructed from the assumption that a particular byte is ASCII.
pub(crate) struct ClassificationProof {
    graph: Graph,
}
impl ClassificationProof {
    pub fn prove(code: Region<'_>) -> Result<Self, String> {
        let graph = Graph::decode(code.bytes, code.origin)?;
        let p: Vec<_> = graph.nodes.keys().copied().collect();
        if p.len() != 15 {
            return Err("formatter classification complete graph".into());
        }
        compare(
            &graph,
            vec![
                mov(r(7), r(7)),
                push(r(5)),
                mov(r(5), r(4)),
                mov(r(1), mem(5, 12)),
                lea(0, 1, 1),
                bin(Binary::Compare, r(0), imm(256)),
                ordinary(Operation::Branch(Condition::Above, p[12])),
                mov(r(0), mem(5, 8)),
                ordinary(Operation::ZeroExtend(
                    reg(0),
                    Operand::Memory(
                        Address {
                            base: Some(0),
                            index: Some(1),
                            scale: 2,
                            displacement: 0,
                        },
                        16,
                    ),
                )),
                bin(Binary::And, r(0), mem(5, 16)),
                pop(5),
                ordinary(Operation::Return),
                bin(Binary::Xor, r(0), r(0)),
                pop(5),
                ordinary(Operation::Return),
            ],
        )?;
        Ok(Self { graph })
    }
    pub fn origin(&self) -> u32 {
        self.graph.origin
    }
    pub fn emit(&self, name_: &str) -> Result<String, String> {
        name(name_)?;
        let body = super::super::crt_stream_emit::emit_body(
            &self.graph,
            |_, _| Err("formatter classification unexpected call".into()),
            &BTreeMap::new(),
            4_000_000,
        )?;
        Ok(format!(
            r#"
fn {name_}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lease:CrtLock,backend:&mut impl CrtBackend)->Result<CrtValue,&'static str>{{
 rt.check_lock(lease)?;let sp=CrtCpu::pointer(cpu.r[4])?;
 if cpu.returned||cpu.r[4]!=cpu.entry[4]||sp.kind!=CrtRegionKind::Stack||rt.load(sp,32)?!=CrtValue::ProtectedReturn(cpu.return_id){{return Err("formatter classification stack entry");}}
 let saved=rt.offset(sp,-4)?;rt.valid(saved,20)?;
 if rt.overlapping_tags(saved.address(),4).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_))){{return Err("formatter classification saved slot");}}
 let character=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;
 if character.wrapping_add(1)<=256{{
  let table=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;
  if table.kind!=CrtRegionKind::Module&&table.kind!=CrtRegionKind::Input{{return Err("formatter classification owned table role");}}
  let slot=rt.offset(table,i64::from(character as i32)*2)?;rt.valid(slot,2)?;rt.load(slot,16)?.known_scalar()?;
  rt.load(rt.offset(sp,12)?,32)?.known_scalar()?;
 }}
 {body}
}}
"#
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn raw(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn adapter() -> Vec<u8> {
        raw("8bff558bec8b0185c075228b450850c6401c01c740181600000033c05050505050e85618000083c41832c0eb0750e805000000595dc20400")
    }
    fn encoding() -> Vec<u8> {
        raw("8bff558bec8b4d08568b410c90c1e80ca801756e5751e8c23a000059b938c1410083f8ff741b83f8fe74168bf08bd083e63fc1fa066bfe38033c9508cf4100eb0c8bd08bf0c1fa068bf983e63f807f29005f751a83f8ff740f83f8fe740a6bce38030c9508cf4100f6412d017414e8cc190000c70016000000e84318000032c0eb02b0015e5dc3")
    }
    fn fileno() -> Vec<u8> {
        raw("8bff558bec8b450885c07515e851dfffffc70016000000e8c8ddffff83c8ff5dc38b4010905dc3")
    }
    fn classifier() -> Vec<u8> {
        raw("8bff558bec8b4d0c8d41013d00010000770c8b45080fb704482345105dc333c05dc3")
    }
    fn prove(a: &[u8], e: &[u8], f: &[u8]) -> Result<ValidationProof, String> {
        ValidationProof::prove(
            Region {
                bytes: a,
                origin: 0x406256,
            },
            Region {
                bytes: e,
                origin: 0x40628e,
            },
            Region {
                bytes: f,
                origin: 0x409d6b,
            },
        )
    }
    fn native(extra: &str, body: &str, label: &str) {
        let memory = include_str!("guest_memory.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("//!"))
            .collect::<Vec<_>>()
            .join("\n");
        let source=format!("#![allow(dead_code)]\nmod guest_memory{{{memory}}}\n{}\n{}\n{extra}\nstruct Backend;impl CrtBackend for Backend{{fn write_once(&mut self,_:CrtDescriptorId,_:&[u8])->Result<CrtWriteResult,&'static str>{{panic!(\"classification must not perform I/O\")}}}}\nfn main(){{{body}}}",super::super::super::crt_stream_runtime::EMITTED_TYPES,super::super::super::crt_stream_cpu::EMITTED_TYPES);
        let dir = std::env::temp_dir().join(format!(
            "w2l-formatter-locale-{}-{label}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("run.rs");
        let binary = dir.join(if cfg!(windows) { "run.exe" } else { "run" });
        std::fs::write(&file, source).unwrap();
        let built = std::process::Command::new("rustc")
            .args(["--edition=2021"])
            .arg(&file)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        let run = std::process::Command::new(binary).output().unwrap();
        assert!(
            run.status.success(),
            "{}",
            String::from_utf8_lossy(&run.stderr)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn original_validation_requires_all_mode_tests_and_exact_call_abis() {
        let (a, e, f) = (adapter(), encoding(), fileno());
        let proof = prove(&a, &e, &f).unwrap();
        assert_eq!(proof.descriptor_table, 0x41cf08);
        assert_eq!(proof.invalid_descriptor, 0x41c138);
        for (which, offset, value) in [
            (0, 55, 0xc3),
            (1, 0x40629d - 0x40628e, 11),
            (1, 0x4062dd - 0x40628e, 40),
            (1, 0x4062f8 - 0x40628e, 44),
            (2, 0x409d8e - 0x409d6b, 12),
        ] {
            let (mut aa, mut ee, mut ff) = (a.clone(), e.clone(), f.clone());
            match which {
                0 => aa[offset] = value,
                1 => ee[offset] = value,
                _ => ff[offset] = value,
            };
            assert!(prove(&aa, &ee, &ff).is_err(), "{which}/{offset}");
        }
        let mut changed = classifier();
        changed[12] = 0xff;
        assert!(ClassificationProof::prove(Region {
            bytes: &changed,
            origin: 0x40641c
        })
        .is_err());
    }
    #[test]
    fn native_validation_preserves_registers_and_observes_descriptor_modes() {
        let extra = prove(&adapter(), &encoding(), &fileno())
            .unwrap()
            .emit("bound")
            .unwrap();
        native(
            &extra,
            r#"
for(fd,mode,mask,bad)in[(0u32,0u32,0u32,0u32),(1,0,0x80,0),(63,0,0,0),(64,0,0,0),(65,0,0xfe,0),(2047,0,0,0),(1,1,0,1),(1,0,1,1),(1,0,0,2),(1,0,0,3),(1,0,0,4),(1,0,0,5)]{
 let mut rt=CrtStreamRuntime::new(9,7,0x2000,1<<20).unwrap();let lease=rt.lock(7).unwrap();let file=rt.file();rt.store(rt.offset(file,12).unwrap(),32,CrtValue::scalar(2)).unwrap();rt.store(rt.offset(file,16).unwrap(),32,CrtValue::scalar(fd)).unwrap();
 let id=rt.bind_descriptor(fd,77).unwrap();let block=rt.map_region(0x50000,64*56,CrtRegionKind::Descriptor,None).unwrap();let record=rt.offset(block,i64::from(fd&63)*56).unwrap();let descriptor_lease=rt.claim_descriptor_record(7,id,record).unwrap();rt.store(rt.offset(record,24).unwrap(),32,CrtValue::Handle(id)).unwrap();rt.store(rt.offset(record,40).unwrap(),8,CrtValue::scalar(0x81)).unwrap();rt.store(rt.offset(record,41).unwrap(),8,CrtValue::scalar(mode)).unwrap();rt.store(rt.offset(record,45).unwrap(),8,CrtValue::scalar(mask)).unwrap();rt.bind_descriptor_record(lease,id,record).unwrap();
 let table=rt.map_region(0x41cf08,128,CrtRegionKind::Module,None).unwrap();rt.store(rt.offset(table,i64::from(fd>>6)*4).unwrap(),32,CrtValue::Pointer(block)).unwrap();
 let stack=rt.map_region(0x10000,65536,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,0xf000).unwrap();let context=rt.map_region(0x40000,40,CrtRegionKind::Context,None).unwrap();let holder=rt.map_region(0x60000,4,CrtRegionKind::Module,None).unwrap();rt.store(holder,32,CrtValue::Pointer(file)).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::Pointer(context)).unwrap();
 if bad==2{rt.store(rt.offset(record,45).unwrap(),8,CrtValue::Scalar{bits:0,known:0}).unwrap();}
 if bad==3{rt.store(rt.offset(table,i64::from(fd>>6)*4).unwrap(),32,CrtValue::Pointer(record)).unwrap();}
 if bad==4{rt.unlock_descriptor(descriptor_lease).unwrap();}
 if bad==5{rt.store(holder,32,CrtValue::scalar(file.address())).unwrap();}
 let mut cpu=CrtCpu::new(sp,1).unwrap();cpu.return_pop=4;cpu.r[1]=CrtValue::Pointer(holder);cpu.entry=cpu.r;let before=cpu.r;let result=bound_validate(&mut rt,&mut cpu,lease,&mut Backend);
 if bad!=0{assert!(result.is_err(),"bad {bad}");assert!(!cpu.returned);assert_eq!(cpu.r,before);assert_eq!(rt.load(sp,32).unwrap(),CrtValue::ProtectedReturn(1));}
 else{assert_eq!(CrtCpu::number(result.unwrap()).unwrap()&255,1);assert!(cpu.returned);assert_eq!(CrtCpu::pointer(cpu.r[4]).unwrap().address(),sp.address()+8);for i in[3,5,6,7]{assert_eq!(cpu.r[i],before[i]);}}
}
"#,
            "validation",
        );
    }
    #[test]
    fn native_classification_reads_real_words_and_handles_eof_and_unknown_boundaries() {
        let extra = ClassificationProof::prove(Region {
            bytes: &classifier(),
            origin: 0x40641c,
        })
        .unwrap()
        .emit("classify")
        .unwrap();
        native(
            &extra,
            r#"
for(character,mask,expected)in[(u32::MAX,0xffff,0xa55a),(0,0x8000,0x8000),(65,0x80ff,0x8042),(255,0xffffffff,0x1234),(256,0xffffffff,0),(257,0xffffffff,0),(0xfffffffe,0xffff,0),(0x80000000,0xffff,0)]{
 let mut rt=CrtStreamRuntime::new(1,2,0x2000,65536).unwrap();let lease=rt.lock(2).unwrap();let mut values=vec![0u8;514];for(index,value)in[(0usize,0xa55au16),(1,0x8001),(66,0x8142),(256,0x1234)]{values[index*2..index*2+2].copy_from_slice(&value.to_le_bytes());}
 let storage=rt.map_region(0x5000,514,CrtRegionKind::Input,Some(&values)).unwrap();let table=rt.offset(storage,2).unwrap();let stack=rt.map_region(0x10000,8192,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,4096).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();for(i,arg)in[CrtValue::Pointer(table),CrtValue::scalar(character),CrtValue::scalar(mask)].into_iter().enumerate(){rt.store(rt.offset(sp,4+i as i64*4).unwrap(),32,arg).unwrap();}
 if !matches!(character,u32::MAX|0..=255){rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::Scalar{bits:0,known:0}).unwrap();rt.store(rt.offset(sp,12).unwrap(),32,CrtValue::Scalar{bits:0,known:0}).unwrap();}
 let mut cpu=CrtCpu::new(sp,1).unwrap();let previous=cpu.r;let result=classify(&mut rt,&mut cpu,lease,&mut Backend).unwrap();assert_eq!(result,CrtValue::scalar(expected));for i in[3,5,6,7]{assert_eq!(cpu.r[i],previous[i]);}
}
"#,
            "classification",
        );
    }
    #[test]
    fn native_classification_rejects_unknown_stale_and_incomplete_words() {
        let extra = ClassificationProof::prove(Region {
            bytes: &classifier(),
            origin: 0x40641c,
        })
        .unwrap()
        .emit("classify")
        .unwrap();
        native(
            &extra,
            r#"
for bad in 0..5{
 let mut rt=CrtStreamRuntime::new(1,2,0x2000,65536).unwrap();let lease=rt.lock(2).unwrap();let table=rt.map_region(0x5000,4,CrtRegionKind::Input,if bad==0{None}else{Some(&[0,0,1,0])}).unwrap();let stack=rt.map_region(0x10000,8192,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,4096).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();
 let pointer=if bad==1{rt.offset(table,3).unwrap()}else if bad==2{rt.subrange(rt.offset(table,2).unwrap(),2).unwrap()}else{table};
 rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::Pointer(pointer)).unwrap();rt.store(rt.offset(sp,8).unwrap(),32,if bad==2{CrtValue::scalar(u32::MAX)}else if bad==3{CrtValue::Scalar{bits:0,known:0}}else{CrtValue::scalar(0)}).unwrap();rt.store(rt.offset(sp,12).unwrap(),32,CrtValue::scalar(0xffff)).unwrap();
 if bad==4{rt.retire_region(table).unwrap();}
 let mut cpu=CrtCpu::new(sp,1).unwrap();let before=cpu.r;assert!(classify(&mut rt,&mut cpu,lease,&mut Backend).is_err());assert_eq!(cpu.r,before);assert!(!cpu.returned);assert_eq!(rt.load(sp,32).unwrap(),CrtValue::ProtectedReturn(1));
}
"#,
            "negative",
        );
    }
}
