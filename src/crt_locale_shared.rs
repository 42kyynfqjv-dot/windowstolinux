//! Original shared multibyte publication under a live registered EH4 frame.
use crate::crt_stream_ir::{Graph, Target};
pub(crate) const WRAPPER:&str="6a086880b64100e8a66fffff8b4508ff30e80b0f0000598365fc008b4d0ce82a000000c745fcfeffffffe8120000008b4df064890d00000000595f5e5bc9c20c00";
pub(crate) const CLEANUP: &str = "8b4510ff30e81e0f000059c3";
pub(crate) const BODY:&str="8bff568bf1b901010000518b068b008b404883c0185051ff3538d14100e86d0700008b06b900010000518b008b404805190100005051ff353cd14100e84e0700008b460483c42083c9ff8b008b00f00fc10875158b46048b00813840c241007408ff30e8edcdffff598b068b108b46048b088b424889018b068b008b4048f0ff005ec3";
pub(crate) const COPY_S:&str="8bff558bec568b751485f6750433c0eb6d8b450885c07513e826c6ffff6a165e8930e89ec4ffff8bc6eb53578b7d1085ff741439750c720f565750e87679ffff83c40c33c0eb36ff750c6a0050e8946cffff83c40c85ff7509e8e5c5ffff6a16eb0c39750c7313e8d7c5ffff6a225e8930e84fc4ffff8bc6eb036a16585f5e5dc3";

pub(crate) fn source() -> Result<String, String> {
    let raw = crate::crt_ptd::raw;
    let helper = raw(crate::crt_ucrt_locale::PROLOG);
    let proof = crate::crt_exception_wrapper::PrologProof::prove(
        crate::crt_exception_wrapper::Region {
            bytes: &helper,
            origin: 0x401e60,
        },
        8,
        0x41b680,
        0x41c000,
        0x402210,
    )?;
    let ep_bytes = raw(crate::crt_ucrt_locale::EPILOG);
    let ep = crate::crt_exception_wrapper::EpilogProof::prove(
        crate::crt_exception_wrapper::Region {
            bytes: &ep_bytes,
            origin: 0x40aedd,
        },
        &proof,
    )?;
    let mut out = format!(
        "{}{}",
        proof.emit("locale_shared_prolog")?,
        ep.emit("locale_shared_epilog")?
    );
    let cleanup = raw(CLEANUP);
    let cg = Graph::decode(&cleanup, 0x40aeef)?;
    let cb = crate::crt_stream_emit::emit_body(
        &cg,
        |pc, t| {
            if t != Target::Direct(0x40be17) {
                return Err("shared cleanup target".into());
            }
            Ok(format!(
                "cpu.call_activation(rt,{},0,|rt,c|startup_second_lock(rt,c,inputs,false,held))?;",
                pc + cg.nodes[&pc].length
            ))
        },
        &Default::default(),
        64,
    )?;
    out.push_str(&format!("fn locale_shared_cleanup(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,held:&mut Option<CrtGlobalLock>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{} {cb}}}",guard(0x40aeef,&cleanup,"cleanup")));
    let bytes = raw(WRAPPER);
    let g = Graph::decode(&bytes, 0x40aeae)?;
    let body = crate::crt_stream_emit::emit_body_with_hooks(
        &g,
        |pc, t| {
            let next = pc + g.nodes[&pc].length;
            Ok(match t{
  Target::Direct(0x401e60)=>"let id=rt.generation.checked_add(1).filter(|n|*n<1u64<<63).ok_or(\"shared helper identity\")?|(1u64<<63);if rt.tags.values().any(|v|*v==CrtValue::ProtectedReturn(id)){return Err(\"shared helper collision\");}rt.generation=id&!(1u64<<63);cpu.push(rt,CrtValue::ProtectedReturn(id))?;locale_shared_prolog(rt,cpu,id,b.token,|rt,c,record,head|b.install(rt,c,epoch,record,head))?;".into(),
  Target::Direct(0x40bdcf)=>format!("cpu.call_activation(rt,{next},0,|rt,c|startup_second_lock(rt,c,inputs,true,&mut held))?;"),
  Target::Direct(0x40aefb)=>format!("b.authority(rt,epoch)?;let lease=held.ok_or(\"shared body missing lock\")?;cpu.call_activation(rt,{next},0,|rt,c|locale_shared_body(rt,c,inputs,platform,epoch,&b,lease))?;"),
  Target::Direct(0x40aeef)=>format!("b.authority(rt,epoch)?;cpu.call_activation(rt,{next},0,|rt,c|locale_shared_cleanup(rt,c,inputs,&mut held))?;"),
  _=>return Err(format!("shared wrapper call {pc:x} {t:?}")),
 })
        },
        &Default::default(),
        512,
        |_, _| Ok("return Err(\"shared unbound FS effect\");".into()),
        |pc, _| {
            Ok(if pc == 0x40aedd {
                "if held.is_some(){return Err(\"shared epilog held lock\");}return locale_shared_epilog(rt,cpu,epoch,&mut b);".into()
            } else {
                String::new()
            })
        },
        |_, _| Ok(None),
    )?;
    out.push_str(&format!("fn locale_shared_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;platform.validate(rt,inputs.init)?;cpu.validate_active(rt)?;epoch.state()?;{}{}{}let mut b=CrtNormalBinding::bind_initializing(rt,cpu,epoch,locale_shared_epilog_layout(),inputs.init)?;let mut held=None;{body}}}",guard(0x40aeae,&bytes,"wrapper"),guard(0x401e60,&helper,"prolog"),guard(0x40aedd,&ep_bytes,"epilog")));
    let bytes = raw(BODY);
    let g = Graph::decode(&bytes, 0x40aefb)?;
    let body = crate::crt_stream_emit::emit_body_with_hooks(
        &g,
        |pc, t| {
            let next = pc + g.nodes[&pc].length;
            Ok(match t{
  Target::Direct(0x40b68a)=>format!("b.authority(rt,epoch)?;rt.check_global(lease)?;let sp=CrtCpu::pointer(cpu.r[4])?;if let CrtValue::Pointer(p)=rt.load(sp,32)?{{if p.kind!=CrtRegionKind::Module||rt.process_image_pointer(inputs.image,p.address(),1)?!=p{{return Err(\"shared global byte table owner\");}}}}cpu.call_activation(rt,{next},0,|rt,c|locale_copy_s_original(rt,c,inputs))?;"),
  Target::Direct(0x407d50)=>format!("b.authority(rt,epoch)?;rt.check_global(lease)?;cpu.call_activation(rt,{next},0,|rt,c|locale_free_original(rt,c,inputs))?;"),
  _=>return Err(format!("shared body call {pc:x} {t:?}")),
 })
        },
        &std::collections::BTreeMap::from([
            (0x41d138, "CrtRegionKind::Module".into()),
            (0x41d13c, "CrtRegionKind::Module".into()),
        ]),
        4096,
        |pc, op| {
            use crate::crt_stream_ir::Op;
            let code=match op{Op::LockedExchangeAdd{source,..}if pc==0x40af49=>format!("cpu.exchange_initializing_scalar(rt,inputs.init,inputs.image,CrtCpu::pointer(cpu.r[0])?,{},true)?;",source.index),Op::LockedIncrement(_)if pc==0x40af79=>"cpu.increment_initializing_scalar(rt,inputs.init,inputs.image,CrtCpu::pointer(cpu.r[0])?)?;".into(),_=>return Err("shared thread effect".into())};
            Ok(format!(
                "b.authority(rt,epoch)?;rt.check_global(lease)?;{code}"
            ))
        },
        |pc, _| {
            Ok(match pc{
  0x40af0a|0x40af27|0x40af76=>"locale_required_view(rt,platform,cpu.r[0])?;".into(),
  0x40af47|0x40af54=>"cpu.r[0]=CrtValue::Pointer(rt.module_word_pointer(inputs.image,cpu.r[0])?);".into(),
  0x40af6d=>"locale_required_view(rt,platform,cpu.r[2])?;".into(),
  0x40af70=>"cpu.r[1]=CrtValue::Pointer(rt.module_word_pointer(inputs.image,cpu.r[1])?);".into(),
  0x40af49|0x40af79=>"cpu.r[0]=CrtValue::Pointer(rt.initializing_scalar_pointer(inputs.init,inputs.image,cpu.r[0])?);".into(),
  _=>String::new(),
 })
        },
        |_, _| Ok(None),
    )?;
    out.push_str(&format!("fn locale_shared_body(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform,epoch:&mut NormalCallEpoch<'_>,b:&CrtNormalBinding,lease:CrtGlobalLock)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;b.authority(rt,epoch)?;rt.check_global(lease)?;{} {body}}}",guard(0x40aefb,&bytes,"body")));
    let bytes = raw(COPY_S);
    let g = Graph::decode(&bytes, 0x40b68a)?;
    let body = crate::crt_stream_emit::emit_body(
        &g,
        |pc, t| {
            Ok(match t {
                Target::Direct(0x403040) => format!(
                    "cpu.call_activation(rt,{},0,|rt,c|locale_memcpy_original(rt,c,inputs))?;",
                    pc + g.nodes[&pc].length
                ),
                Target::Direct(0x402370 | 0x407ccd | 0x407b4f) => {
                    "return Err(\"locale checked-copy invalid-argument/errno effect unbound\");"
                        .into()
                }
                _ => return Err(format!("checked-copy call {pc:x} {t:?}")),
            })
        },
        &Default::default(),
        1024,
    )?;
    out.push_str(&format!("fn locale_copy_s_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{} {body}}}",guard(0x40b68a,&bytes,"checked-copy")));
    out.push_str(&crate::crt_locale_memcpy::source()?);
    Ok(out)
}
fn guard(address: u32, bytes: &[u8], name: &str) -> String {
    format!("let q=rt.process_image_code(inputs.image,{address},{})?;if rt.memory.read(q.address(),{}).map_err(|_|\"locale shared {name} read\")?!=&{bytes:?}{{return Err(\"locale shared {name} code changed\");}}",bytes.len(),bytes.len())
}
