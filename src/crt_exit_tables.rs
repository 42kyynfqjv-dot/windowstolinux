//! Original exit-table cookie initialization; encoded scalar bits grant no pointer authority.
use crate::crt_stream_ir::{Graph, Target};
pub(crate) const HELPER: &str =
    "8bff558bec8b4d0885c9750583c8ff5dc38b013b4108750da100c04100890189410489410833c05dc3";
pub(crate) const WRAPPER: &str = "6888ce4100e88dffffffc7042494ce4100e881ffffff59b001c3";
pub(crate) fn source() -> Result<String, String> {
    let bytes = crate::crt_ptd::raw(HELPER);
    let g = Graph::decode(&bytes, 0x4074fc)?;
    let body = crate::crt_stream_emit::emit_body_with_hooks(
        &g,
        |_, _| Err("exit-table helper unexpected call".into()),
        &std::collections::BTreeMap::from([(0x41c000, "CrtRegionKind::Module".into())]),
        128,
        |_, _| Err("exit-table thread effect unbound".into()),
        |pc, _| {
            Ok(match pc {
            // The original null check has already executed. Canonical module
            // identity/range is a bounded consumer domain, never a heap retag.
            0x40750d => "cpu.r[1]=CrtValue::Pointer(rt.module_word_pointer(inputs.image,cpu.r[1])?);let table=CrtCpu::pointer(cpu.r[1])?;rt.valid(table,12)?;if !matches!(rt.load(table,32)?,CrtValue::Scalar{..}){return Err(\"exit-table encoded scalar word\");}".into(),
            0x40750f => "let table=CrtCpu::pointer(cpu.r[1])?;if !matches!(rt.load(rt.offset(table,8)?,32)?,CrtValue::Scalar{..}){return Err(\"exit-table encoded scalar word\");}".into(),
            0x407514 => "rt.load(rt.process_image_pointer(inputs.image,0x41c000,4)?,32)?.known_scalar().map_err(|_|\"exit-table scalar cookie\")?;".into(),
            _ => String::new(),
        })
        },
        |_, _| Ok(None),
    )?;
    let mut out=format!("fn startup_exit_table_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{} {body}}}",guard(0x4074fc,&bytes));
    let bytes = crate::crt_ptd::raw(WRAPPER);
    let g = Graph::decode(&bytes, 0x407565)?;
    let body = crate::crt_stream_emit::emit_body(
        &g,
        |pc, t| {
            if t != Target::Direct(0x4074fc) {
                return Err("exit-table wrapper target".into());
            }
            Ok(format!(
                "cpu.call_activation(rt,{},0,|rt,c|startup_exit_table_original(rt,c,inputs))?;",
                pc + g.nodes[&pc].length
            ))
        },
        &Default::default(),
        128,
    )?;
    out.push_str(&format!("fn startup_exit_tables_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{} {body}}}",guard(0x407565,&bytes)));
    out.push_str(&format!("fn startup_exit_helper_bytes()->Vec<u8>{{vec!{:?}}}fn startup_exit_wrapper_bytes()->Vec<u8>{{vec!{:?}}}",crate::crt_ptd::raw(HELPER),bytes));
    Ok(out)
}
fn guard(origin: u32, bytes: &[u8]) -> String {
    format!("let code=rt.process_image_code(inputs.image,{origin},{})?;if rt.memory.read(code.address(),{}).map_err(|_|\"exit-table code read\")?!=&{bytes:?}{{return Err(\"exit-table code changed\");}}",bytes.len(),bytes.len())
}
#[test]
fn original_exit_tables_bind_complete_calls_and_no_free_effects() {
    let helper = Graph::decode(&crate::crt_ptd::raw(HELPER), 0x4074fc).unwrap();
    assert!(!helper
        .nodes
        .values()
        .any(|n| matches!(n.op, crate::crt_stream_ir::Op::Call(_))));
    let g = Graph::decode(&crate::crt_ptd::raw(WRAPPER), 0x407565).unwrap();
    let calls: Vec<_> = g
        .nodes
        .iter()
        .filter_map(|(&pc, n)| {
            if let crate::crt_stream_ir::Op::Call(t) = n.op {
                Some((pc, t))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        calls,
        vec![
            (0x40756a, Target::Direct(0x4074fc)),
            (0x407576, Target::Direct(0x4074fc))
        ]
    );
    source().expect("original exit-table bodies must lower");
}
