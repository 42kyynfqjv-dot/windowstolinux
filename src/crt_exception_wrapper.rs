//! Original normal-path CRT EH4 wrappers. A completed exception event may lend
//! its thread chain to these ordinary calls; this does not give C++ records EH4
//! semantics or admit new exception delivery during a formatter call.
use super::crt_stream_ir::{Graph, Op};
use super::graph::{Address, Binary, Operand, Operation, Reg};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy)]
pub(crate) struct Region<'a> {
    pub bytes: &'a [u8],
    pub origin: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Scalar(u32),
    Saved(u8),
    Stack(i32),
    Cookie,
    EncodedScope,
    Guard(i32),
    Head,
    HelperReturn,
    CallerReturn,
    Unknown,
}

/// Every offset is relative to the original wrapper CALL entry, not the
/// prolog helper's lower entry. Saved slots identify registers without inventing
/// their bits; the runtime bridge checks the actual shared-memory tokens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FrameLayout {
    pub allocation: u32,
    pub frame_pointer: i32,
    pub low: i32,
    pub record: i32,
    pub scope_slot: i32,
    pub level_slot: i32,
    pub saved_sp: i32,
    pub guard: i32,
    pub saved: BTreeMap<i32, u8>,
}

pub(crate) struct PrologProof {
    pub graph: Graph,
    pub layout: FrameLayout,
    pub scope: u32,
    pub handler: u32,
    pub cookie_address: u32,
    pub install_pc: u32,
    pub relocation_pc: u32,
    pub return_pc: u32,
    pub temporary_bytes: u32,
}

struct State {
    r: [Value; 8],
    words: BTreeMap<i32, Value>,
    low: i32,
    fs_read: bool,
    installed: Option<(u32, i32)>,
    relocation: Option<u32>,
}
impl State {
    fn stack(&self) -> Result<i32, String> {
        if let Value::Stack(at) = self.r[4] {
            Ok(at)
        } else {
            Err("EH4 prolog ESP provenance".into())
        }
    }
    fn address(&self, a: &Address) -> Result<i32, String> {
        if a.index.is_some() || a.scale != 1 {
            return Err("EH4 prolog indexed stack address".into());
        }
        let Some(base) = a.base else {
            return Err("EH4 prolog unbound absolute memory".into());
        };
        let Value::Stack(at) = self.r[base as usize] else {
            return Err("EH4 prolog stack-address provenance".into());
        };
        at.checked_add(a.displacement as i32)
            .ok_or_else(|| "EH4 prolog address overflow".into())
    }
    fn read(&self, o: &Operand, cookie: u32) -> Result<Value, String> {
        match o {
            Operand::Immediate(n) => Ok(Value::Scalar(*n)),
            Operand::Reg(r) if r.width == 32 && r.shift == 0 => {
                Ok(self.r[r.index as usize].clone())
            }
            Operand::Memory(a, 32)
                if a.base.is_none() && a.index.is_none() && a.displacement == cookie =>
            {
                Ok(Value::Cookie)
            }
            Operand::Memory(a, 32) => self
                .words
                .get(&self.address(a)?)
                .cloned()
                .ok_or_else(|| "EH4 prolog uninitialized/full-word stack read".into()),
            _ => Err("EH4 prolog partial or unbound operand".into()),
        }
    }
    fn store(&mut self, pc: u32, at: i32, value: Value) -> Result<(), String> {
        if at % 4 != 0 || at < self.low || at > 12 {
            return Err("EH4 prolog complete store bounds".into());
        }
        match self.words.get(&at) {
            Some(Value::CallerReturn | Value::Saved(_) | Value::Head) => {
                return Err("EH4 prolog protected word overwrite".into())
            }
            Some(Value::HelperReturn) => {
                if value != Value::EncodedScope
                    || self.relocation.is_some()
                    || self.words.get(&self.stack()?) != Some(&Value::HelperReturn)
                    || self.stack()? == at
                    || self
                        .words
                        .values()
                        .filter(|v| **v == Value::HelperReturn)
                        .count()
                        != 2
                {
                    return Err("EH4 prolog unproved continuation relocation".into());
                }
                self.relocation = Some(pc);
            }
            _ => {}
        }
        self.words.insert(at, value);
        Ok(())
    }
    fn write(&mut self, pc: u32, o: &Operand, value: Value) -> Result<(), String> {
        match o {
            Operand::Reg(Reg {
                index,
                width: 32,
                shift: 0,
            }) => {
                if *index == 4 {
                    let Value::Stack(next) = value else {
                        return Err("EH4 prolog ESP type".into());
                    };
                    if next % 4 != 0 || !(-4096..=0).contains(&next) {
                        return Err("EH4 prolog stack budget/alignment".into());
                    }
                    let old = self.stack()?;
                    if next > old {
                        return Err("EH4 prolog unexplained stack cleanup".into());
                    }
                    for at in (next..old).step_by(4) {
                        if self.words.insert(at, Value::Unknown).is_some() {
                            return Err("EH4 prolog allocation aliases live slot".into());
                        }
                    }
                    self.low = self.low.min(next);
                    self.r[4] = Value::Stack(next);
                } else {
                    self.r[*index as usize] = value;
                }
                Ok(())
            }
            Operand::Memory(a, 32) => self.store(pc, self.address(a)?, value),
            _ => Err("EH4 prolog partial/nonwritable destination".into()),
        }
    }
    fn push(&mut self, value: Value) -> Result<(), String> {
        let next = self
            .stack()?
            .checked_sub(4)
            .filter(|n| *n >= -4096)
            .ok_or("EH4 prolog push bound")?;
        if self.words.contains_key(&next) {
            return Err("EH4 prolog push aliases owned word".into());
        }
        self.words.insert(next, value);
        self.low = self.low.min(next);
        self.r[4] = Value::Stack(next);
        Ok(())
    }
}

impl PrologProof {
    /// Lower only the original helper. The caller supplies its separately
    /// minted CALL token and a registry installation callback; this is not a
    /// certificate for an enclosing formatter or exception delivery. The
    /// callback must validate and perform the actual registry installation;
    /// its successful return alone supplies no registry or exception proof.
    pub fn emit(&self, name: &str) -> Result<String, String> {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err("EH4 native helper name".into());
        }
        let l = &self.layout;
        let mut check = format!(
            r#"
if cpu.entry!=outer_entry||cpu.return_id!=outer_return||cpu.returned!=outer_returned{{return Err("EH4 outer activation changed");}}
if cpu.r[4]!=CrtValue::Pointer(relocated)||cpu.r[5]!=CrtValue::Pointer(frame){{return Err("EH4 native frame/continuation stack");}}
if rt.load(caller,32)?!=CrtValue::ProtectedReturn(outer_return){{return Err("EH4 native caller return changed");}}
if rt.load(record,32)?!=CrtValue::ThreadHead(predecessor)
 ||rt.load(rt.offset(record,4)?,32)?.known_scalar()? != {handler}
 ||rt.load(rt.offset(record,8)?,32)?.known_scalar()? != ({scope}u32^cookie)
 ||rt.load(rt.offset(record,12)?,32)?.known_scalar()? != (-2i32)as u32
 ||rt.load(rt.offset(caller,{guard})?,32)?.known_scalar()? != (cookie^frame.address())
 ||rt.load(rt.offset(caller,{saved_sp})?,32)? != CrtValue::Pointer(final_sp){{return Err("EH4 native record/guard changed");}}
"#,
            handler = self.handler,
            scope = self.scope,
            guard = l.guard,
            saved_sp = l.saved_sp
        );
        for (offset, register) in &l.saved {
            check.push_str(&format!("if rt.load(rt.offset(caller,{offset})?,32)?!=saved[{register}]{{return Err(\"EH4 native saved identity\");}}"));
        }
        let check_return = check.clone();
        let relocation = self.relocation_pc;
        let install_pc = self.install_pc;
        let return_pc = self.return_pc;
        let body = super::crt_stream_emit::emit_body_with_hooks(
            &self.graph,
            |_, _| Err("EH4 helper unexpected call".into()),
            &BTreeMap::from([(self.cookie_address, "CrtRegionKind::Module".into())]),
            self.graph.nodes.len() as u32,
            |pc, op| {
                Ok(match op {
                Op::FsPush => "cpu.push(rt,CrtValue::ThreadHead(predecessor))?;".into(),
                Op::FsRead(r) => format!("cpu.set({},32,0,CrtValue::ThreadHead(predecessor))?;",r.index),
                Op::FsWrite(r) if pc == install_pc => format!("{check}if cpu.r[{}]!=CrtValue::Pointer(record){{return Err(\"EH4 native installation pointer\");}}install(rt,record,predecessor)?;installed=true;",r.index),
                _ => return Err("EH4 native unbound FS effect".into()),
            })
            },
            |pc, _| {
                Ok(if pc == relocation {
                    r#"if rt.load(helper,32)?!=token||rt.load(relocated,32)?!=token||cpu.r[4]!=CrtValue::Pointer(relocated)
 ||rt.tags.values().filter(|v|**v==token).count()!=2{return Err("EH4 native continuation relocation identity");}
rt.consume_stack(helper,token)?;"#.into()
                } else {
                    String::new()
                })
            },
            |pc, pop| {
                if pc != return_pc || pop != 0 {
                    return Err("EH4 native unproved return".into());
                }
                Ok(Some(format!(
                    r#"{check_return}
if !installed||rt.load(relocated,32)?!=token||rt.tags.values().filter(|v|**v==token).count()!=1{{return Err("EH4 native relocated RET identity");}}
if cpu.pop(rt)?!=token||cpu.r[4]!=CrtValue::Pointer(final_sp){{return Err("EH4 native relocated RET stack");}}
return Ok(());"#
                )))
            },
        )?;
        Ok(format!(
            r#"
fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,helper_id:u64,predecessor:CrtThreadHead,
 mut install:impl FnMut(&mut CrtStreamRuntime,CrtPointer,CrtThreadHead)->Result<(),&'static str>)->Result<(),&'static str>{{
if cpu.returned||helper_id==0||helper_id==cpu.return_id{{return Err("EH4 native helper activation");}}
rt.validate_thread_head(predecessor)?;
let outer_entry=cpu.entry;let outer_return=cpu.return_id;let outer_returned=cpu.returned;
let saved=cpu.r.map(|v|match v{{CrtValue::Scalar{{bits,known}}=>CrtValue::Scalar{{bits:bits&known,known}},other=>other}});
let helper=CrtCpu::pointer(cpu.r[4])?;
if helper.kind!=CrtRegionKind::Stack||helper.address()%4!=0{{return Err("EH4 native helper stack");}}
let caller=rt.offset(helper,12)?;
if cpu.entry[4]!=CrtValue::Pointer(caller){{return Err("EH4 native enclosing activation");}}
let token=CrtValue::ProtectedReturn(helper_id);
if rt.load(helper,32)?!=token||rt.tags.values().filter(|v|**v==token).count()!=1
 ||rt.load(caller,32)?!=CrtValue::ProtectedReturn(outer_return)
 ||rt.load(rt.offset(helper,4)?,32)?.known_scalar()? != {scope}
 ||rt.load(rt.offset(helper,8)?,32)?.known_scalar()? != {allocation}{{return Err("EH4 native entry words");}}
let scratch=rt.offset(caller,-{temporary})?;rt.valid(scratch,{temporary}-12)?;
if rt.overlapping_tags(scratch.address(),{temporary}-12).iter().any(|(_,v)|matches!(v,CrtValue::OpaqueSaved(_)|CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_))){{return Err("EH4 native occupied scratch");}}
let frame=rt.offset(caller,{bp})?;let record=rt.offset(caller,{record})?;
let final_sp=rt.offset(caller,{low})?;let relocated=rt.offset(final_sp,-4)?;
let cookie=rt.load(rt.resolve_absolute({cookie_address},CrtRegionKind::Module)?,32)?.known_scalar()?;
let mut installed=false;
{body}
}}
"#,
            scope = self.scope,
            allocation = l.allocation,
            temporary = self.temporary_bytes,
            bp = l.frame_pointer,
            record = l.record,
            low = l.low,
            cookie_address = self.cookie_address
        ))
    }

    /// Allocation and scope come from the independently proved original
    /// wrapper PUSH arguments. No function name or artifact identity is used.
    pub fn prove(
        code: Region<'_>,
        allocation: u32,
        scope: u32,
        cookie_address: u32,
        handler: u32,
    ) -> Result<Self, String> {
        if allocation == 0
            || allocation > 2048
            || !allocation.is_multiple_of(4)
            || scope == 0
            || !scope.is_multiple_of(4)
            || cookie_address == 0
            || !cookie_address.is_multiple_of(4)
            || handler == 0
            || scope == cookie_address
        {
            return Err("EH4 prolog argument/metadata domain".into());
        }
        let graph = Graph::decode(code.bytes, code.origin)?;
        if graph.nodes.len() > 128 {
            return Err("EH4 prolog instruction budget".into());
        }
        let mut s = State {
            r: std::array::from_fn(|i| Value::Saved(i as u8)),
            words: BTreeMap::from([
                (0, Value::HelperReturn),
                (4, Value::Scalar(scope)),
                (8, Value::Scalar(allocation)),
                (12, Value::CallerReturn),
            ]),
            low: 0,
            fs_read: false,
            installed: None,
            relocation: None,
        };
        s.r[4] = Value::Stack(0);
        let mut returned = None;
        for (&pc, node) in &graph.nodes {
            if returned.is_some() {
                return Err("EH4 prolog trailing reachable/code ambiguity".into());
            }
            match &node.op {
                Op::Ordinary(Operation::Push(o)) => s.push(s.read(o, cookie_address)?)?,
                Op::FsPush => {
                    if s.fs_read {
                        return Err("EH4 prolog repeated predecessor capture".into());
                    }
                    s.fs_read = true;
                    s.push(Value::Head)?;
                }
                Op::FsRead(r) => {
                    if s.fs_read || r.index == 4 || r.width != 32 || r.shift != 0 {
                        return Err("EH4 prolog predecessor capture type".into());
                    }
                    s.fs_read = true;
                    s.r[r.index as usize] = Value::Head;
                }
                Op::FsWrite(r) => {
                    let Value::Stack(record) = s.r[r.index as usize] else {
                        return Err("EH4 prolog installation pointer".into());
                    };
                    if s.installed.is_some()
                        || s.relocation.is_none()
                        || s.words.get(&record) != Some(&Value::Head)
                        || s.words.get(&(record + 4)) != Some(&Value::Scalar(handler))
                        || s.words.get(&(record + 8)) != Some(&Value::EncodedScope)
                        || s.words.get(&(record + 12)) != Some(&Value::Scalar((-2i32) as u32))
                    {
                        return Err("EH4 prolog incomplete original record installation".into());
                    }
                    s.installed = Some((pc, record));
                }
                Op::Ordinary(Operation::Address(r, a)) => {
                    let at = s.address(a)?;
                    s.write(pc, &Operand::Reg(*r), Value::Stack(at))?;
                }
                Op::Ordinary(Operation::Binary(b, dst, src)) => {
                    let right = s.read(src, cookie_address)?;
                    let value = if *b == Binary::Move {
                        right
                    } else {
                        let left = s.read(dst, cookie_address)?;
                        match (b, left, right) {
                            (Binary::Sub, Value::Stack(at), Value::Scalar(n)) => Value::Stack(
                                at.checked_sub(n as i32).ok_or("EH4 prolog subtraction")?,
                            ),
                            (Binary::Xor, Value::Scalar(n), Value::Cookie) if n == scope => {
                                Value::EncodedScope
                            }
                            (Binary::Xor, Value::Cookie, Value::Stack(at))
                            | (Binary::Xor, Value::Stack(at), Value::Cookie) => Value::Guard(at),
                            (Binary::Xor, Value::Scalar(a), Value::Scalar(b)) => {
                                Value::Scalar(a ^ b)
                            }
                            _ => return Err("EH4 prolog unproved scalar/pointer effect".into()),
                        }
                    };
                    s.write(pc, dst, value)?;
                }
                Op::Ordinary(Operation::Return) => {
                    let sp = s.stack()?;
                    if s.installed.is_none()
                        || s.words.get(&sp) != Some(&Value::HelperReturn)
                        || s.words
                            .values()
                            .filter(|v| **v == Value::HelperReturn)
                            .count()
                            != 1
                    {
                        return Err("EH4 prolog missing exact relocated continuation".into());
                    }
                    s.words.remove(&sp);
                    s.r[4] = Value::Stack(sp + 4);
                    returned = Some(pc);
                }
                _ => return Err(format!("EH4 prolog unsupported original effect at {pc:#x}")),
            }
            if !matches!(node.op, Op::Ordinary(Operation::Return))
                && node.successors != [pc + node.length]
            {
                return Err("EH4 prolog unproved control edge".into());
            }
        }
        let return_pc = returned.ok_or("EH4 prolog original return missing")?;
        let (install_pc, record) = s.installed.ok_or("EH4 prolog original FS store missing")?;
        let Value::Stack(bp) = s.r[5] else {
            return Err("EH4 prolog frame pointer type".into());
        };
        let sp = s.stack()?;
        if bp != 8 || record + 16 != bp || s.words.get(&12) != Some(&Value::CallerReturn) {
            return Err("EH4 prolog caller/frame relation".into());
        }
        let mut saved = BTreeMap::new();
        let mut seen = BTreeSet::new();
        let mut guards = Vec::new();
        let mut saved_sp = Vec::new();
        for (&at, value) in &s.words {
            match value {
                Value::Saved(r) => {
                    if !matches!(r, 3 | 5 | 6 | 7) || !seen.insert(*r) {
                        return Err("EH4 prolog saved-register alias".into());
                    }
                    saved.insert(at - 12, *r);
                }
                Value::Guard(frame) if *frame == bp => guards.push(at - 12),
                Value::Stack(value) if *value == sp => saved_sp.push(at - 12),
                _ => {}
            }
        }
        if seen != BTreeSet::from([3, 5, 6, 7])
            || guards.len() != 1
            || saved_sp.len() != 1
            || guards[0] != sp - 12
            || s.words.get(&bp) != Some(&Value::Saved(5))
        {
            return Err("EH4 prolog complete saved/guard layout".into());
        }
        Ok(Self {
            graph,
            layout: FrameLayout {
                allocation,
                frame_pointer: bp - 12,
                low: sp - 12,
                record: record - 12,
                scope_slot: record + 8 - 12,
                level_slot: record,
                saved_sp: saved_sp[0],
                guard: guards[0],
                saved,
            },
            scope,
            handler,
            cookie_address,
            install_pc,
            relocation_pc: s
                .relocation
                .ok_or("EH4 prolog continuation relocation missing")?,
            return_pc,
            temporary_bytes: u32::try_from(12 - s.low).map_err(|_| "EH4 prolog depth")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn bytes() -> Vec<u8> {
        // Retained authored compiler output; addresses are passed as bound
        // roles, not used as application identity or a result selection key.
        [
            0x68, 0x10, 0x22, 0x40, 0x00, 0x64, 0xff, 0x35, 0, 0, 0, 0, 0x8b, 0x44, 0x24, 0x10,
            0x89, 0x6c, 0x24, 0x10, 0x8d, 0x6c, 0x24, 0x10, 0x2b, 0xe0, 0x53, 0x56, 0x57, 0xa1,
            0x00, 0xc0, 0x41, 0, 0x31, 0x45, 0xfc, 0x33, 0xc5, 0x50, 0x89, 0x65, 0xe8, 0xff, 0x75,
            0xf8, 0x8b, 0x45, 0xfc, 0xc7, 0x45, 0xfc, 0xfe, 0xff, 0xff, 0xff, 0x89, 0x45, 0xf8,
            0x8d, 0x45, 0xf0, 0x64, 0xa3, 0, 0, 0, 0, 0xc3,
        ]
        .to_vec()
    }
    fn prove(bytes: &[u8], allocation: u32) -> Result<PrologProof, String> {
        PrologProof::prove(
            Region {
                bytes,
                origin: 0x401e60,
            },
            allocation,
            0x41b400,
            0x41c000,
            0x402210,
        )
    }
    #[test]
    fn original_prolog_derives_file_and_descriptor_frames_and_return_move() {
        for allocation in [12, 20, 44] {
            let p = prove(&bytes(), allocation).unwrap();
            assert_eq!(p.layout.frame_pointer, -4);
            assert_eq!(p.layout.record, -20);
            assert_eq!(p.layout.scope_slot, -12);
            assert_eq!(p.layout.level_slot, -8);
            assert_eq!(p.layout.saved_sp, -28);
            assert_eq!(p.layout.low, -36 - allocation as i32);
            assert_eq!(p.temporary_bytes, 40 + allocation);
            assert_eq!(p.layout.saved.get(&-4), Some(&5));
            assert_eq!(
                (p.install_pc, p.relocation_pc, p.return_pc),
                (0x401e9e, 0x401e98, 0x401ea4)
            );
        }
    }
    #[test]
    fn protected_return_scope_predecessor_and_word_bounds_mutations_reject() {
        for (offset, value) in [
            (15, 12),
            (19, 12),
            (36, 0xf8),
            (45, 0xf4),
            (58, 0xf4),
            (61, 0xf4),
            (64, 4),
            (68, 0xc2),
        ] {
            let mut b = bytes();
            b[offset] = value;
            assert!(prove(&b, 12).is_err(), "mutation {offset}");
        }
        for size in [0, 2, 4096, u32::MAX] {
            assert!(prove(&bytes(), size).is_err());
        }
    }
}

#[cfg(test)]
#[path = "crt_exception_wrapper_native_tests.rs"]
mod native_tests;
