//! Composition of proved original text instructions and documented OS effects.
//! The entry is a declared owned CRT component state, never original PE startup.
use super::crt_stream_callees;
use super::crt_stream_ir::Target;
use super::crt_stream_proof::{self, AbsoluteRole, Bindings, CallEffect};
use std::collections::BTreeMap;

pub(crate) struct Region<'a> {
    pub bytes: &'a [u8],
    pub origin: u32,
}
pub(crate) struct Input<'a> {
    pub writer: Region<'a>,
    pub stack_probe: Region<'a>,
    pub security: Region<'a>,
    pub cookie: u32,
    pub descriptor_table: u32,
    pub write_iat: u32,
    pub error_iat: u32,
    pub max_input: u32,
}

/// The component constructs these explicit guest objects. Original executable
/// bytes, immutable tables, IAT words and mutable module cells must have distinct
/// address ranges. Host compilation must not hide self-modifying guest aliases.
pub(crate) fn validate_layout(
    regions: &[(u32, usize)],
    cells: &[u32],
    max_input: u32,
) -> Result<(), String> {
    if max_input == 0 || max_input > 16384 {
        return Err("CRT component input extent".into());
    }
    let mut ranges = vec![
        (0x2000u64, 0x2038u64), // owned FILE
        (0x10000, 0x20000),     // committed stack
        (0x30000, 0x30000 + u64::from(max_input)),
        (0x40000, 0x40028), // result or pending-error context
        (0x50000, 0x50038), // descriptor
    ];
    for (start, length) in regions
        .iter()
        .copied()
        .chain(cells.iter().map(|&cell| (cell, 4)))
    {
        let length = u32::try_from(length).map_err(|_| "CRT original extent overflow")?;
        let end = start
            .checked_add(length)
            .ok_or("CRT original extent overflow")?;
        if start == 0 || length == 0 {
            return Err("CRT original empty region".into());
        }
        let current = (u64::from(start), u64::from(end));
        if ranges
            .iter()
            .any(|&(lo, hi)| current.0 < hi && lo < current.1)
        {
            return Err("CRT original code/data aliases component storage".into());
        }
        ranges.push(current);
    }
    if cells.iter().any(|cell| !cell.is_multiple_of(4)) {
        return Err("CRT original module word alignment".into());
    }
    Ok(())
}
pub(crate) fn emit(input: Input<'_>) -> Result<String, String> {
    validate_layout(
        &[
            (input.writer.origin, input.writer.bytes.len()),
            (input.stack_probe.origin, input.stack_probe.bytes.len()),
            (input.security.origin, input.security.bytes.len()),
        ],
        &[
            input.cookie,
            input.descriptor_table,
            input.write_iat,
            input.error_iat,
        ],
        input.max_input,
    )?;
    let probe =
        crt_stream_callees::prove_stack_probe(input.stack_probe.bytes, input.stack_probe.origin)?;
    let security = crt_stream_callees::prove_security(input.security.bytes, input.security.origin)?;
    if security.cookie() != input.cookie {
        return Err("CRT original writer/security cookie identity".into());
    }
    let proof = crt_stream_proof::prove_text(
        input.writer.bytes,
        input.writer.origin,
        Bindings {
            calls: BTreeMap::from([
                (Target::Direct(probe.target()), CallEffect::StackProbe),
                (Target::Direct(security.target()), CallEffect::SecurityCheck),
                (Target::Import(input.write_iat), CallEffect::WriteFile),
                (Target::Import(input.error_iat), CallEffect::LastError),
            ]),
            absolute: BTreeMap::from([
                (input.cookie, AbsoluteRole::Cookie),
                (input.descriptor_table, AbsoluteRole::DescriptorTable),
            ]),
        },
        input.max_input,
    )?;
    let body=proof.emit("original_text",|pc,target|{
  let continuation=pc+proof.graph().nodes[&pc].length;
  Ok(match proof.bindings().calls.get(&target).ok_or("CRT missing proved callee")?{
   CallEffect::StackProbe=>probe.call_source(continuation),
   CallEffect::SecurityCheck=>security.call_source(continuation),
   CallEffect::WriteFile=>format!(r#"
let before=CrtCpu::pointer(cpu.r[4])?;
let args:Vec<_>=(0..5).map(|i|rt.load(rt.offset(before,i*4)?,32)).collect::<Result<_,_>>()?;
let CrtValue::Handle(handle)=args[0] else{{return Err("CRT WriteFile typed handle");}};
let source=CrtCpu::pointer(args[1])?;let count=CrtCpu::number(args[2])?;
let count_out=CrtCpu::pointer(args[3])?;
if CrtCpu::number(args[4])?!=0||count_out.kind!=CrtRegionKind::Stack{{return Err("CRT synchronous count-out ownership");}}
rt.valid(count_out,4)?;
if source.cap==count_out.cap&&u64::from(source.address())<u64::from(count_out.address())+4&&u64::from(count_out.address())<u64::from(source.address())+u64::from(count){{return Err("CRT count-out aliases source");}}
let call_word=rt.offset(before,-4)?;let token=CrtValue::ProtectedReturn({continuation}u64);
rt.store(call_word,32,token)?;
rt.store(count_out,32,CrtValue::scalar(0))?;
let result=rt.write_once(handle,source,count,backend)?;
rt.store(count_out,32,if result.success{{CrtValue::scalar(result.written)}}else{{CrtValue::Scalar{{bits:0,known:0}}}})?;
rt.consume_stack(call_word,token)?;
cpu.discard(rt,20)?;cpu.clobber(CrtValue::scalar(u32::from(result.success)));
"#),
   CallEffect::LastError=>format!(r#"
let call_word=rt.offset(CrtCpu::pointer(cpu.r[4])?,-4)?;
let token=CrtValue::ProtectedReturn({continuation}u64);rt.store(call_word,32,token)?;
let error=rt.last_os_error.ok_or("CRT unknown thread last error")?;
rt.consume_stack(call_word,token)?;cpu.clobber(CrtValue::scalar(error));
"#),
   _=>return Err("CRT unexpected text callee".into()),
  })
 })?;
    let memory = include_str!("guest_memory.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap()
        .lines()
        .filter(|line| !line.starts_with("//!"))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(format!(
        r#"#![allow(dead_code)]
// Original instruction-derived CRT text component; no whole-PE eligibility.
mod guest_memory{{{memory}}}
{runtime}
{cpu}
{body}
fn run_crt_text(data:&[u8],backend:&mut impl CrtBackend)->Result<[u32;3],&'static str>{{
 if data.len()>{max_input}{{return Err("CRT certified input bound");}}
 let mut rt=CrtStreamRuntime::new(1,1,0x2000,1048576)?;
 let lease=rt.lock(1)?;
 let stack=rt.map_region(0x10000,65536,CrtRegionKind::Stack,None)?;
 let sp=rt.offset(stack,0xf000)?;
 let initialized=if data.is_empty(){{vec![0]}}else{{data.to_vec()}};
 let source=rt.map_region(0x30000,initialized.len() as u32,CrtRegionKind::Input,Some(&initialized))?;
 let result=rt.map_region(0x40000,12,CrtRegionKind::Result,None)?;
 let descriptor=rt.map_region(0x50000,56,CrtRegionKind::Descriptor,None)?;
 let handle=rt.bind_descriptor(0,7)?;
 rt.store(rt.offset(descriptor,24)?,32,CrtValue::Handle(handle))?;
 rt.store(rt.offset(descriptor,40)?,8,CrtValue::scalar(0x81))?;
 rt.store(rt.offset(descriptor,41)?,8,CrtValue::scalar(0))?;
 rt.bind_descriptor_record(lease,handle,descriptor)?;rt.require_narrow_descriptor(handle)?;
 let table=rt.map_region({table},4,CrtRegionKind::Module,None)?;
 rt.store(table,32,CrtValue::Pointer(descriptor))?;
 let cookie=rt.map_region({cookie},4,CrtRegionKind::Module,Some(&0x319a472du32.to_le_bytes()))?;
 let _=cookie;
 rt.store(sp,32,CrtValue::ProtectedReturn(1))?;
 for (i,arg) in [CrtValue::Pointer(result),CrtValue::scalar(0),CrtValue::Pointer(source),CrtValue::scalar(data.len()as u32)].into_iter().enumerate(){{
  rt.store(rt.offset(sp,4+i as i64*4)?,32,arg)?;
 }}
 let mut cpu=CrtCpu::new(sp,1)?;
 let returned=original_text(&mut rt,&mut cpu,lease,backend)?;
 if returned!=CrtValue::Pointer(result){{return Err("CRT original result object");}}
 let values=std::array::from_fn(|i|rt.load(rt.offset(result,i as i64*4).unwrap(),32).and_then(CrtValue::known_scalar));
 let [a,b,c]=values;let triple=[a?,b?,c?];rt.unlock(lease)?;Ok(triple)
}}
"#,
        runtime = super::crt_stream_runtime::EMITTED_TYPES,
        cpu = super::crt_stream_cpu::EMITTED_TYPES,
        max_input = input.max_input,
        table = input.descriptor_table,
        cookie = input.cookie
    ))
}
