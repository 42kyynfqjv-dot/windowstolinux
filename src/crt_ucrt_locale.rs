//! Original locale acquisition with registered EH4 cleanup.
use crate::crt_stream_ir::{Graph, Op, Target};
pub(crate) const PROLOG: &str = "681022400064ff35000000008b442410896c24108d6c24102be0535657a100c041003145fc33c5508965e8ff75f88b45fcc745fcfeffffff8945f88d45f064a300000000c3";
pub(crate) const BODY: &str = "6a0868e0b54100e8597fffff8b4508ff30e8be1e0000598365fc008b450c8b008b008b4048f0ff00c745fcfeffffffe812000000";
pub(crate) const EPILOG: &str = "8b4df064890d00000000595f5e5bc9c20c00";
pub(crate) const CLEANUP: &str = "8b4510ff30e8cc1e000059c3";
pub(crate) fn source() -> Result<String, String> {
    let raw = crate::crt_ptd::raw;
    let helper = raw(PROLOG);
    let p = crate::crt_exception_wrapper::PrologProof::prove(
        crate::crt_exception_wrapper::Region {
            bytes: &helper,
            origin: 0x401e60,
        },
        8,
        0x41b5e0,
        0x41c000,
        0x402210,
    )
    .map_err(|e| format!("locale prolog: {e}"))?;
    let eb = raw(EPILOG);
    let ep = crate::crt_exception_wrapper::EpilogProof::prove(
        crate::crt_exception_wrapper::Region {
            bytes: &eb,
            origin: 0x409f2f,
        },
        &p,
    )
    .map_err(|e| format!("locale epilog: {e}"))?;
    let mut out = format!(
        "{}{}",
        p.emit("ucrt_mb_prolog")?,
        ep.emit("ucrt_mb_epilog")?
    );
    let cleanup = raw(CLEANUP);
    let cg = Graph::decode(&cleanup, 0x409f41).map_err(|e| format!("locale cleanup: {e}"))?;
    let cb = crate::crt_stream_emit::emit_body(
        &cg,
        |pc, t| {
            if t != Target::Direct(0x40be17) {
                return Err("locale cleanup target".into());
            }
            let next = pc + cg.nodes[&pc].length;
            Ok(format!("cpu.call_activation(rt,{next},0,|rt,c|startup_second_lock(rt,c,inputs,false,held))?;"))
        },
        &Default::default(),
        64,
    )?;
    out.push_str(&format!("fn ucrt_mb_cleanup(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,held:&mut Option<CrtGlobalLock>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let q=rt.process_image_code(inputs.image,0x409f41,{})?;if rt.memory.read(q.address(),{}).map_err(|_|\"locale cleanup code read\")?!=&{cleanup:?}{{return Err(\"locale cleanup code changed\");}}{cb}}}",cleanup.len(),cleanup.len()));
    let bytes = raw(BODY);
    let mut decoder =
        iced_x86::Decoder::with_ip(32, &bytes, 0x409efb, iced_x86::DecoderOptions::NONE);
    let mut nodes = std::collections::BTreeMap::new();
    while decoder.can_decode() {
        let ins = decoder.decode();
        let pc = ins.ip() as u32;
        let at = (pc - 0x409efb) as usize;
        let n = Graph::decode_instruction(&bytes[at..at + ins.len()], pc)?;
        if n.successors != [pc + n.length] {
            return Err("locale prefix nonlinear cut".into());
        }
        nodes.insert(pc, n);
    }
    let g = Graph {
        origin: 0x409efb,
        end: 0x409f2f,
        nodes,
    };
    let body = crate::crt_stream_emit::emit_body_with_exit(
        &g,
        |pc, t| {
            let next = pc + g.nodes[&pc].length;
            Ok(match t{
 Target::Direct(0x401e60)=>("let id=rt.generation.checked_add(1).filter(|n|*n<1u64<<63).ok_or(\"locale helper identity budget\")?|(1u64<<63);if rt.tags.values().any(|v|*v==CrtValue::ProtectedReturn(id)){return Err(\"locale helper identity collision\");}rt.generation=id&!(1u64<<63);cpu.push(rt,CrtValue::ProtectedReturn(id))?;ucrt_mb_prolog(rt,cpu,id,b.token,|rt,c,record,head|b.install(rt,c,epoch,record,head))?;").to_string(),
 Target::Direct(0x40bdcf)=>format!("cpu.call_activation(rt,{next},0,|rt,c|startup_second_lock(rt,c,inputs,true,&mut held))?;"),
 Target::Direct(0x409f41)=>format!("cpu.call_activation(rt,{next},0,|rt,c|ucrt_mb_cleanup(rt,c,inputs,&mut held))?;"),
 _=>return Err("locale helper unexpected call".into())})
        },
        &Default::default(),
        128,
        |pc, op| {
            if pc != 0x409f20 || !matches!(op, Op::LockedIncrement(_)) {
                return Err("locale helper unbound thread/atomic effect".into());
            }
            Ok("b.authority(rt,epoch)?;let lease=held.ok_or(\"locale reference lock missing\")?;rt.check_global(lease)?;let value=cpu.r[0];let pointer=match value{CrtValue::Scalar{bits,known:u32::MAX}=>rt.process_image_pointer(inputs.image,bits,4)?,CrtValue::Pointer(p)=>{if rt.process_image_pointer(inputs.image,p.address(),4)?!=p{return Err(\"locale reference module alias\");}p},_=>return Err(\"locale reference address knowledge\")};cpu.increment_reference(rt,inputs.init,inputs.image,lease,pointer)?;".into())
        },
        |_, _| Ok(String::new()),
        |_, _| Ok(None),
        Some(0x409f2f),
    )?;
    // The original normal epilog is independently proved; the body ends exactly
    // before its predecessor load, with no structural-success return bypass.
    let actual = format!("if pc=={}{{return Ok(cpu.r[0]);}}", 0x409f2fu32);
    if !body.contains(&actual) {
        return Err("locale body terminal missing".into());
    }
    let body=body.replace(&actual,&format!("if pc=={}{{if held.is_some(){{return Err(\"locale epilog with held lock\");}}return ucrt_mb_epilog(rt,cpu,epoch,&mut b);}}",0x409f2fu32));
    out.push_str(&format!("fn ucrt_mb_acquire(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let q=rt.process_image_code(inputs.image,0x409efb,{})?;if rt.memory.read(q.address(),{}).map_err(|_|\"locale body code read\")?!=&{bytes:?}{{return Err(\"locale body code changed\");}}for(address,expected)in [(0x401e60u32,&{helper:?}[..]),(0x409f2f,&{eb:?}[..])]{{let q=rt.process_image_code(inputs.image,address,expected.len()as u32)?;if rt.memory.read(q.address(),expected.len()as u32).map_err(|_|\"locale helper code read\")?!=expected{{return Err(\"locale helper code changed\");}}}}let mut b=CrtNormalBinding::bind_initializing(rt,cpu,epoch,ucrt_mb_epilog_layout(),inputs.init)?;let mut held=None;{body}}}",bytes.len(),bytes.len()));
    Ok(out)
}

#[test]
fn locked_increment_needs_a_consumer_effect_contract() {
    let g = Graph::decode(&[0xf0, 0xff, 0x00, 0xc3], 0x1000).unwrap();
    assert!(crate::crt_stream_emit::emit_body(
        &g,
        |_, _| Err("unexpected call".into()),
        &Default::default(),
        16
    )
    .is_err());
    for bytes in [
        &[0xf0, 0x66, 0xff, 0x00, 0xc3][..],
        &[0xf0, 0xff, 0xc0, 0xc3],
        &[0xf0, 0x0f, 0xc1, 0x00, 0xc3],
    ] {
        assert!(Graph::decode(bytes, 0x1000).is_err());
    }
}
