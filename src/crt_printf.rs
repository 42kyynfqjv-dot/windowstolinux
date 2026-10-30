//! Original printf routing and accessor execution on the shared checked runtime.
//! The formatter callback is a distinct, named remaining admission boundary.
use super::{
    crt_stream_emit,
    crt_stream_ir::{Graph, Target},
    stdio_effect,
};
use std::collections::BTreeMap;
pub(crate) fn emit(
    wrapper: stdio_effect::Region<'_>,
    iob: stdio_effect::Region<'_>,
    options: stdio_effect::Region<'_>,
    formatter: u32,
    module: (u32, u32),
) -> Result<String, String> {
    let proof = stdio_effect::prove_wrapper(wrapper, iob, options, formatter, module)?;
    let stdout = proof.stdout_address();
    let options_word = proof.options_address();
    let iob_graph = Graph::decode(iob.code, iob.origin)?;
    let iob_body = crt_stream_emit::emit_body_with_hooks(
        &iob_graph,
        |_, _| Err("printf iob unexpected call".into()),
        &BTreeMap::new(),
        64,
        |_, _| Err("printf iob thread effect".into()),
        |_, _| Ok(String::new()),
        |_, pop| {
            if pop != 0 {
                return Err("printf iob return ABI".into());
            }
            Ok(Some(format!("let file=rt.resolve_absolute({stdout},CrtRegionKind::File)?;rt.file_record(file)?;if CrtCpu::number(cpu.r[0])?!=file.address(){{return Err(\"printf iob computed FILE mismatch\");}}cpu.r[0]=CrtValue::Pointer(file);return cpu.finish(rt);")))
        },
    )?;
    let options_graph = Graph::decode(options.code, options.origin)?;
    let options_body = crt_stream_emit::emit_body_with_hooks(
        &options_graph,
        |_, _| Err("printf options unexpected call".into()),
        &BTreeMap::new(),
        32,
        |_, _| Err("printf options thread effect".into()),
        |_, _| Ok(String::new()),
        |_, pop| {
            if pop != 0 {
                return Err("printf options return ABI".into());
            }
            Ok(Some(format!("let p=rt.resolve_absolute({options_word},CrtRegionKind::Module)?;rt.valid(p,8)?;if CrtCpu::number(cpu.r[0])?!=p.address(){{return Err(\"printf options pointer provenance\");}}cpu.r[0]=CrtValue::Pointer(p);return cpu.finish(rt);")))
        },
    )?;
    let graph = Graph::decode(wrapper.code, wrapper.origin)?;
    let body = crt_stream_emit::emit_body(
        &graph,
        |pc, target| {
            let Target::Direct(target) = target else {
                return Err("printf unproved indirect call".into());
            };
            let next = pc + graph.nodes[&pc].length;
            Ok(if target == iob.origin {
                format!("cpu.call_activation(rt,{next},0,original_printf_iob)?;")
            } else if target == options.origin {
                format!("cpu.call_activation(rt,{next},0,original_printf_options)?;")
            } else if target == formatter {
                format!("cpu.call_activation(rt,{next},0,|rt,cpu|formatter_body(rt,cpu,session))?;")
            } else {
                return Err("printf call binding mismatch".into());
            })
        },
        &BTreeMap::new(),
        128,
    )?;
    let check = |at: u32, bytes: &[u8]| {
        format!("let p=rt.resolve_absolute({at},CrtRegionKind::Module)?;for(i,b)in {bytes:?}.into_iter().enumerate(){{if rt.load(rt.offset(p,i as i64)?,8)?.known_scalar()?!=b as u32{{return Err(\"printf changed original instructions\");}}}}")
    };
    let iob_check = check(iob.origin, iob.code);
    let options_check = check(options.origin, options.code);
    let wrapper_check = check(wrapper.origin, wrapper.code);
    Ok(format!(
        r#"
fn original_printf_iob(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{cpu.validate_active(rt)?;let sp=CrtCpu::pointer(cpu.r[4])?;if rt.load(rt.offset(sp,4)?,32)?.known_scalar()?!=1{{return Err("printf original stdout index");}}{iob_check}{iob_body}}}
fn original_printf_options(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{cpu.validate_active(rt)?;{options_check}{options_body}}}
fn original_printf<'a,F>(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,session:&mut NormalReturnSession<'a>,mut formatter_body:F)->RegistryResult<CrtValue> where F:FnMut(&mut CrtStreamRuntime,&mut CrtCpu,&mut NormalReturnSession<'a>)->RegistryResult<CrtValue>{{cpu.validate_active(rt)?;{wrapper_check}{body}}}
"#
    ))
}

/// Execute the actual formatter entry and complete locale constructor. No
/// default locale state is invented; absent initialized globals reject.
pub(crate) fn emit_context_entry(entry: &[u8], constructor: &[u8]) -> Result<String, String> {
    let graph = Graph::decode_linear_fragment(
        entry.get(..15).ok_or("formatter entry prefix extent")?,
        0x40643e,
    )?;
    // Caller edge identity and the complete constructor are checked separately.
    if entry.get(15..20) != Some(&[0xe8, 0x8e, 0xed, 0xff, 0xff][..]) {
        return Err("formatter constructor original edge".into());
    }
    let prefix = crt_stream_emit::emit_linear_fragment(&graph, &BTreeMap::new())?;
    let ctor = Graph::decode(constructor, 0x4051e0)?;
    let roles = BTreeMap::from([
        (0x41ce7c, "CrtRegionKind::Module".into()),
        (0x41c230, "CrtRegionKind::Module".into()),
        (0x41c234, "CrtRegionKind::Module".into()),
    ]);
    let ctor_body = crt_stream_emit::emit_body(
        &ctor,
        |_, _| Err("formatter context unproved call".into()),
        &roles,
        128,
    )?;
    Ok(format!(
        r#"
fn original_formatter_entry_prefix(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{{prefix}}}
fn original_formatter_context(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{let code=rt.resolve_absolute(0x4051e0,CrtRegionKind::Module)?;for(i,b)in {constructor:?}.into_iter().enumerate(){{if rt.load(rt.offset(code,i as i64)?,8)?.known_scalar()?!=b as u32{{return Err("formatter changed context constructor");}}}}{ctor_body}}}
fn original_formatter_to_locale_state(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{cpu.validate_active(rt)?;let entry=CrtCpu::pointer(cpu.r[4])?;let low=rt.offset(entry,-112)?;rt.valid(low,112)?;if rt.overlapping_tags(low.address(),112).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_))){{return Err("formatter entry private stack alias");}}let code=rt.resolve_absolute(0x40643e,CrtRegionKind::Module)?;for(i,b)in {entry:?}.into_iter().enumerate(){{if rt.load(rt.offset(code,i as i64)?,8)?.known_scalar()?!=b as u32{{return Err("formatter changed entry instructions");}}}}original_formatter_entry_prefix(rt,cpu)?;cpu.call_activation(rt,0x406452,4,original_formatter_context)?;Err("formatter remaining body requires live locale/FILE/handler proof")}}
"#
    ))
}
