//! Original cookie stores on canonical image storage. Entropy acquisition is
//! deliberately unresolved; a supplied established cookie is not its producer.
use crate::crt_stream_ir::{Graph, Target};
pub(crate) const CODE:&str="8b0d00c041005657bf4ee640bbbe0000ffff3bcf740485ce7526e894ffffff8bc83bcf7507b94fe640bbeb0e85ce750a0d11470000c1e0100bc8890d00c04100f7d15f890d40c041005ec3";
pub(crate) fn source(bytes: &[u8]) -> Result<String, String> {
    let expected: Vec<u8> = CODE
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    if bytes != expected {
        return Err("cookie initializer original code binding".into());
    }
    let graph = Graph::decode(bytes, 0x401b71)?;
    let body = crate::crt_stream_emit::emit_body(
        &graph,
        |pc, target| {
            if pc != 0x401b8b || target != Target::Direct(0x401b24) {
                return Err("cookie initializer call binding".into());
            }
            Ok("return Err(\"cookie entropy producer unbound\");".into())
        },
        &std::collections::BTreeMap::from([
            (0x41c000, "CrtRegionKind::Module".into()),
            (0x41c040, "CrtRegionKind::Module".into()),
        ]),
        128,
    )?;
    Ok(format!("fn original_cookie_init(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{cpu.validate_active(rt)?;let token=rt.main_image.ok_or(\"cookie process image missing\")?;let p=rt.process_image_pointer(token,0x401b71,75)?;if rt.memory.read(p.address(),75).map_err(|_|\"cookie code lifetime\")?!=&{bytes:?}{{return Err(\"cookie live code changed\");}}{body}}}"))
}
#[test]
fn cookie_initializer_binds_every_original_byte_and_retains_entropy_rejection() {
    let code = crate::crt_ptd::raw(CODE);
    let text = source(&code).unwrap();
    assert!(text.contains("cookie entropy producer unbound"));
    for i in 0..code.len() {
        let mut mutant = code.clone();
        mutant[i] ^= 1;
        assert!(source(&mutant).is_err(), "changed cookie code {i}");
    }
}
