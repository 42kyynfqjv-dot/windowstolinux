//! Original selector and locale-view constructor. Unsupported mutation helpers
//! remain explicit effect boundaries; no default locale bytes are synthesized.
use crate::crt_stream_ir::{Graph, Target};
pub(crate) const SELECTOR: &str = "8bff558bec83ec108d4df06a00e8f0faffff832544d14100008b450883f8fe7512c70544d1410001000000ff15d4504100eb2c83f8fd7512c70544d1410001000000ff15d0504100eb1583f8fc75108b45f4c70544d14100010000008b4008807dfc00740a8b4df083a150030000fdc9c3";
pub(crate) const VIEW: &str = "8bff558bec53578bf98b4d08c6470c008d5f0485c974078b018b4904eb14833d7cce4100007512a130c241008b0d34c241008903894b04eb4156e8e4f7ffff89078d770853508b484c890b8b4848890ee8b2dfffff56ff37e808e0ffff8b0f83c4108b81500300005ea802750d83c802898150030000c6470c018bc75f5b5dc20400";
pub(crate) fn source() -> Result<String, String> {
    let raw = crate::crt_ptd::raw;
    let roles = std::collections::BTreeMap::from([
        (0x41ce7c, "CrtRegionKind::Module".into()),
        (0x41c230, "CrtRegionKind::Module".into()),
        (0x41c234, "CrtRegionKind::Module".into()),
        (0x41d144, "CrtRegionKind::Module".into()),
    ]);
    let mut out = String::new();
    for (name, address, hex) in [
        ("locale_view_original", 0x40aabe, VIEW),
        ("locale_code_page_original", 0x40afbc, SELECTOR),
    ] {
        let bytes = raw(hex);
        let g = Graph::decode(&bytes, address)?;
        let body = crate::crt_stream_emit::emit_body_with_hooks(
            &g,
            |pc, t| {
                let next = pc + g.nodes[&pc].length;
                Ok(match t {
                    Target::Direct(0x40aabe) => format!("cpu.call_activation(rt,{next},4,|rt,c|locale_view_original(rt,c,inputs,platform))?;"),
                    Target::Import(0x4150d0) => format!("rt.process_image_import(inputs.image,0x4150d0,\"kernel32.dll\",\"GetACP\")?;cpu.call_activation(rt,{next},0,|rt,c|platform.ansi_code_page_call(rt,c,inputs.init))?;"),
                    Target::Import(0x4150d4) => "return Err(\"locale OEM code-page producer unbound\");".into(),
                    Target::Direct(0x40a2e1 | 0x408ac5 | 0x408b23) => "return Err(\"locale view mutation helper unbound\");".into(),
                    _ => return Err(format!("locale selector unexpected call {pc:x}: {t:?}")),
                })
            },
            &roles,
            256,
            |_, _| Err("locale selector thread effect".into()),
            |pc, _| {
                // A numeric image address is promoted only at this actual read,
                // through canonical checked mapping; unknown bits never qualify.
                Ok(if pc == 0x40b018 {
                    "cpu.r[0]=CrtValue::Pointer(rt.module_word_pointer(inputs.image,cpu.r[0])?);"
                        .into()
                } else {
                    String::new()
                })
            },
            |_, _| Ok(None),
        )?;
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,{address},{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"locale selector code read\")?!=&{bytes:?}{{return Err(\"locale selector code changed\");}}{body}}}",bytes.len(),bytes.len()));
    }
    Ok(out)
}
