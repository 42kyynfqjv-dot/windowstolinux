//! Compose original descriptor selection with separately certified writer and
//! errno helpers. Entry is an explicit owned CRT state, not the unproved EH4
//! descriptor-lock wrapper at the caller's target or whole-process startup.
use super::{crt_error_map, crt_stream_worker};

#[derive(Clone, Copy)]
pub(crate) struct Region<'a> {
    pub origin: u32,
    pub bytes: &'a [u8],
}
pub(crate) struct Input<'a> {
    pub selector: Region<'a>,
    pub console: Region<'a>,
    pub isatty: Region<'a>,
    pub mapper: Region<'a>,
    pub search: Region<'a>,
    pub updater: Region<'a>,
    pub error_table: Region<'a>,
    pub descriptor_table: u32,
    pub descriptor_limit_address: u32,
    pub descriptor_limit: u32,
    pub text_writer: Region<'a>,
    pub stack_probe: Region<'a>,
    pub security: Region<'a>,
    pub write_iat: u32,
    pub error_iat: u32,
    pub cookie: u32,
    pub max_input: u32,
    pub module: (u32, u32),
}
fn error_region(r: Region<'_>) -> crt_error_map::Region<'_> {
    crt_error_map::Region {
        va: r.origin,
        bytes: r.bytes,
    }
}
fn worker_region(r: Region<'_>) -> crt_stream_worker::Region<'_> {
    crt_stream_worker::Region {
        origin: r.origin,
        bytes: r.bytes,
    }
}
/// Append to the instruction-derived text-writer bundle, which provides
/// original_text and the checked CPU/memory types. No external target address
/// is aliased to this entry: selector and EH4 wrapper remain distinct.
pub(crate) fn emit(input: Input<'_>) -> Result<String, String> {
    if input.max_input == 0
        || input.max_input > 16384
        || input.descriptor_limit == 0
        || input.descriptor_limit > 2048
        || input.module.0 == 0
        || input.module.0 >= input.module.1
    {
        return Err("CRT worker component entry extent".into());
    }
    let regions = [
        input.selector,
        input.console,
        input.isatty,
        input.mapper,
        input.search,
        input.updater,
        input.error_table,
        input.text_writer,
        input.stack_probe,
        input.security,
    ];
    super::crt_stream_bundle::validate_layout(
        &regions
            .iter()
            .map(|r| (r.origin, r.bytes.len()))
            .collect::<Vec<_>>(),
        &[
            input.descriptor_table,
            input.descriptor_limit_address,
            input.cookie,
            input.write_iat,
            input.error_iat,
        ],
        input.max_input,
    )?;
    for (i, region) in regions.iter().enumerate() {
        let end = region
            .origin
            .checked_add(region.bytes.len() as u32)
            .ok_or("CRT worker region overflow")?;
        if region.origin < input.module.0 || region.origin >= end || end > input.module.1 {
            return Err("CRT worker original module extent".into());
        }
        for other in regions.iter().skip(i + 1) {
            let other_end = other
                .origin
                .checked_add(other.bytes.len() as u32)
                .ok_or("CRT worker overlap overflow")?;
            if region.origin < other_end && other.origin < end {
                return Err("CRT worker regions alias".into());
            }
        }
        for data in [
            input.descriptor_table,
            input.descriptor_limit_address,
            input.cookie,
            input.write_iat,
            input.error_iat,
        ] {
            if !data.is_multiple_of(4)
                || data < input.module.0
                || data.checked_add(4).is_none_or(|n| n > input.module.1)
                || data < end && region.origin < data + 4
            {
                return Err("CRT worker data/code binding".into());
            }
        }
    }
    if input.cookie == input.descriptor_table
        || input.cookie == input.descriptor_limit_address
        || input.descriptor_table == input.descriptor_limit_address
    {
        return Err("CRT worker module cells alias".into());
    }
    let errors = crt_error_map::prove(
        error_region(input.mapper),
        error_region(input.search),
        error_region(input.updater),
        error_region(input.error_table),
        input.module,
    )?;
    let worker = crt_stream_worker::Proof::prove(
        worker_region(input.selector),
        worker_region(input.console),
        worker_region(input.isatty),
        crt_stream_worker::Bindings {
            descriptor_number: 0,
            descriptor_limit: input.descriptor_limit,
            descriptor_table: input.descriptor_table,
            descriptor_limit_address: input.descriptor_limit_address,
            text_writer: input.text_writer.origin,
            errno_update: errors.updater,
        },
    )?;
    let error_depth = errors.temporary_bytes();
    let mut source = errors.source("original_errno")?;
    source += &worker.emit("original_worker", |effect, pc| {
        let graph = [&worker.selector, &worker.console, &worker.isatty]
            .into_iter()
            .find(|g| g.nodes.contains_key(&pc))
            .ok_or("CRT worker call graph ownership")?;
        let continuation = pc
            .checked_add(graph.nodes[&pc].length)
            .ok_or("CRT worker continuation overflow")?;
        Ok(match effect {
            crt_stream_worker::Effect::Console => {
                format!("cpu.call(rt,lease,backend,{continuation},original_worker_console)?;")
            }
            crt_stream_worker::Effect::Isatty => {
                format!("cpu.call(rt,lease,backend,{continuation},original_worker_isatty)?;")
            }
            crt_stream_worker::Effect::TextWriter => {
                format!("cpu.call(rt,lease,backend,{continuation},original_text)?;")
            }
            crt_stream_worker::Effect::ErrnoUpdate => format!(
                r#"
cpu.call(rt,lease,backend,{continuation},|rt,child,_lease,_backend|{{
 let sp=CrtCpu::pointer(child.r[4])?;
 let scratch=rt.offset(sp,-i64::from({error_depth}u32))?;rt.valid(scratch,{error_depth})?;
 if rt.overlapping_tags(scratch.address(),{error_depth}).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_))){{return Err("CRT errno private scratch crosses protected activation");}}
 let error=CrtCpu::number(rt.load(rt.offset(sp,4)?,32)?)?;
 let context=CrtCpu::pointer(rt.load(rt.offset(sp,8)?,32)?)?;
 let mapped=original_errno_apply(rt,context,error)?;
 child.clobber(CrtValue::scalar(mapped));child.finish(rt)
}})?;
"#
            ),
        })
    })?;
    source += &format!(
        r#"
// These fields are the original context object's pending effects, not committed
// Windows PTD errno/doserrno and not a claim of complete CRT/FILE initialization.
#[derive(Debug)]
struct CrtWriteOutcome{{logical:u32,context:[u32;4]}}
fn run_crt_write(data:&[u8],backend:&mut impl CrtBackend)->Result<CrtWriteOutcome,&'static str>{{
 if data.len()>{max_input}{{return Err("CRT worker certified complete source bound");}}
 let mut rt=CrtStreamRuntime::new(1,1,0x2000,1048576)?;
 let lease=rt.lock(1)?;
 let stack=rt.map_region(0x10000,65536,CrtRegionKind::Stack,None)?;
 let sp=rt.offset(stack,0xf000)?;
 let initialized=if data.is_empty(){{vec![0]}}else{{data.to_vec()}};
 let source=rt.map_region(0x30000,initialized.len()as u32,CrtRegionKind::Input,Some(&initialized))?;
 rt.valid(source,data.len()as u32)?;
 let context=rt.map_region(0x40000,40,CrtRegionKind::Context,Some(&[0u8;40]))?;
 // Distinct initial sentinels make preservation of uncommitted fields visible.
 rt.store(rt.offset(context,0x18)?,32,CrtValue::scalar(19))?;
 rt.store(rt.offset(context,0x20)?,32,CrtValue::scalar(23))?;
 rt.validate_error_context(context)?;
 let descriptor=rt.map_region(0x50000,56,CrtRegionKind::Descriptor,None)?;
 let handle=rt.bind_descriptor(0,7)?;
 rt.store(rt.offset(descriptor,24)?,32,CrtValue::Handle(handle))?;
 rt.store(rt.offset(descriptor,40)?,8,CrtValue::scalar(0x81))?;
 rt.store(rt.offset(descriptor,41)?,8,CrtValue::scalar(0))?;
 rt.bind_descriptor_record(lease,handle,descriptor)?;rt.require_narrow_descriptor(handle)?;
 let table=rt.map_region({table},4,CrtRegionKind::Module,None)?;
 rt.store(table,32,CrtValue::Pointer(descriptor))?;
 rt.map_region({limit_address},4,CrtRegionKind::Module,Some(&{limit}u32.to_le_bytes()))?;
 rt.map_region({cookie},4,CrtRegionKind::Module,Some(&0x319a472du32.to_le_bytes()))?;
 rt.store(sp,32,CrtValue::ProtectedReturn(1))?;
 for (i,arg) in [CrtValue::scalar(0),CrtValue::Pointer(source),CrtValue::scalar(data.len()as u32),CrtValue::Pointer(context)].into_iter().enumerate(){{
  rt.store(rt.offset(sp,4+i as i64*4)?,32,arg)?;
 }}
 let mut cpu=CrtCpu::new(sp,1)?;
 let logical=CrtCpu::number(original_worker_selector(&mut rt,&mut cpu,lease,backend)?)?;
 let fields=[(0x18,32),(0x1c,8),(0x20,32),(0x24,8)];let mut values=[0u32;4];
 for (i,(offset,width)) in fields.into_iter().enumerate(){{values[i]=CrtCpu::number(rt.load(rt.offset(context,offset)?,width)?)?;}}
 rt.unlock(lease)?;Ok(CrtWriteOutcome{{logical,context:values}})
}}
"#,
        max_input = input.max_input,
        table = input.descriptor_table,
        limit_address = input.descriptor_limit_address,
        limit = input.descriptor_limit,
        cookie = input.cookie
    );
    Ok(source)
}
