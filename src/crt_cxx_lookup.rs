//! Original cached backend selection; TLS acquisition remains an explicit effect.
use crate::crt_stream_ir::{Graph, Target};
use std::collections::BTreeMap;
pub(crate) const PREFIX: &str =
    "558bec51518b4508578d048514cd41008945f88b009083cfff3bc7750433c0eb5685c07552";
pub(crate) const EPILOG: &str = "5fc9c3";
pub(crate) const WRAPPER:&str="558bec5668545d4100684c5d410068545d41006a02e885feffff83c4108bf0ff750885f6740c8bceff1528514100ffd6eb06ff15605041005e5dc3";
pub(crate) fn source(prefix: &[u8], epilog: &[u8], wrapper: &[u8]) -> Result<String, String> {
    if prefix != crate::crt_ptd::raw(PREFIX)
        || epilog != crate::crt_ptd::raw(EPILOG)
        || wrapper != crate::crt_ptd::raw(WRAPPER)
    {
        return Err("C++ resolver/backend code binding".into());
    }
    // Only the complete original cached fast path is admitted. Cold resolution
    // is an explicit external exit, not a successful function-pointer result.
    let mut nodes = BTreeMap::new();
    for (bytes, origin) in [(prefix, 0x402a53), (epilog, 0x402aca)] {
        let mut d = iced_x86::Decoder::with_ip(
            32,
            bytes,
            u64::from(origin),
            iced_x86::DecoderOptions::NONE,
        );
        while d.can_decode() {
            let i = d.decode();
            let offset = (i.ip32() - origin) as usize;
            nodes.insert(
                i.ip32(),
                Graph::decode_instruction(&bytes[offset..offset + i.len()], i.ip32())?,
            );
        }
    }
    let graph = Graph {
        origin: 0x402a53,
        end: 0x402acd,
        nodes,
    };
    let roles = BTreeMap::from([(0x41cd14, "CrtRegionKind::Module".into())]);
    let body = crate::crt_stream_emit::emit_body_with_exit(
        &graph,
        |_, _| Err("C++ cached resolver cannot call".into()),
        &roles,
        4096,
        |_, _| Err("C++ resolver thread effect".into()),
        |_, _| Ok(String::new()),
        |_, pop| {
            if pop != 0 {
                return Err("C++ resolver cleanup".into());
            }
            Ok(Some("if CrtCpu::number(cpu.r[0])?!=0{return Err(\"C++ dynamic FLS backend ownership unbound\");}return cpu.finish(rt);".into()))
        },
        Some(0x402a78),
    )?;
    let mut out=format!("fn cxx_cached_resolver(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{let value=(||->Result<CrtValue,&'static str>{{{body}}})()?;if cpu.returned{{return Ok(value);}}Err(\"C++ cold resolver module/API effects unbound\")}}");
    let mut nodes = BTreeMap::new();
    let mut d = iced_x86::Decoder::with_ip(32, wrapper, 0x402bb4, iced_x86::DecoderOptions::NONE);
    while d.can_decode() {
        let i = d.decode();
        let offset = (i.ip32() - 0x402bb4) as usize;
        nodes.insert(
            i.ip32(),
            Graph::decode_instruction(&wrapper[offset..offset + i.len()], i.ip32())?,
        );
    }
    let graph = Graph {
        origin: 0x402bb4,
        end: 0x402bef,
        nodes,
    };
    if graph
        .nodes
        .values()
        .flat_map(|n| &n.successors)
        .any(|p| !graph.nodes.contains_key(p))
    {
        return Err("C++ wrapper CFG edge".into());
    }
    let body = crate::crt_stream_emit::emit_body_with_indirect(
        &graph,
        |pc, target| {
            let next = pc + graph.nodes[&pc].length;
            Ok(match target{
 Target::Direct(0x402a53)=>format!("cpu.call_activation(rt,{next},0,|rt,child|cxx_cached_resolver(rt,child))?;"),
 Target::Import(0x415060)=>format!("let selected=rt.resolve_absolute(0x41cd1c,CrtRegionKind::Module)?;if rt.load(selected,32)?.known_scalar()?!=u32::MAX{{return Err(\"C++ TLS fallback cache identity\");}}cpu.call_activation(rt,{next},4,|rt,child|backend(rt,child))?;"),
 _=>"return Err(\"C++ dynamic backend guard/effects unbound\");".into()})
        },
        &BTreeMap::new(),
        4096,
        |_, _| Err("C++ lookup thread effect".into()),
        |_, _| Ok(String::new()),
        |_, pop| {
            if pop != 0 {
                return Err("C++ lookup cleanup".into());
            }
            Ok(None)
        },
        None,
        |_, _, _| Ok(None),
        |_, _| Ok("return Err(\"C++ indirect backend ownership unbound\");".into()),
    )?;
    out.push_str(&format!("fn cxx_original_lookup(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,backend:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{{body}}}"));
    Ok(out)
}
