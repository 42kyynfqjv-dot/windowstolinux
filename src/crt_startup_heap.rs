//! Original process-heap publication, sharing Space's process-owned authority.
use crate::crt_stream_ir::{Graph, Target};
pub(crate) const CODE: &str = "ff15f850410085c0a3c8d241000f95c0c3";
pub(crate) fn source() -> Result<String, String> {
    let bytes = crate::crt_startup_table::raw(CODE);
    let g = Graph::decode(&bytes, 0x40c8f0)?;
    let body = crate::crt_stream_emit::emit_body(
        &g,
        |pc, t| {
            if t != Target::Import(0x4150f8) {
                return Err("startup heap import target".into());
            }
            let next = pc + g.nodes[&pc].length;
            Ok(format!("rt.process_image_import(inputs.image,0x4150f8,\"kernel32.dll\",\"GetProcessHeap\")?;cpu.call_activation(rt,{next},0,|rt,c|effect(rt,c,inputs))?;"))
        },
        &std::collections::BTreeMap::from([(0x41d2c8, "CrtRegionKind::Module".into())]),
        64,
    )?;
    Ok(format!(
        r#"
fn startup_heap_api(rt:&mut CrtStreamRuntime,c:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{
 inputs.validate(rt)?;c.validate_active(rt)?;
 if c.return_pop!=0||c.r[4]!=c.entry[4]||[3,5,6,7].iter().any(|&i|c.r[i]!=c.entry[i]){{return Err("startup heap API frame");}}
 let value=rt.native_process_heap(inputs.init)?;c.clobber(value);c.finish(rt)
}}
fn startup_heap_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,effect:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,&CrtEntropyInputs)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{
 inputs.validate(rt)?;cpu.validate_active(rt)?;let code=rt.process_image_code(inputs.image,0x40c8f0,{len})?;
 if rt.memory.read(code.address(),{len}).map_err(|_|"startup heap code read")?!=&{bytes:?}{{return Err("startup heap code changed");}}{body}
}}
"#,
        len = bytes.len()
    ))
}
#[test]
fn original_heap_callback_decodes() {
    source().unwrap();
}
