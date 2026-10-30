//! Original entry-to-initializer slice; bounded CPU observation stops before downstream ISA consumers.
use crate::crt_stream_ir::{Graph, Target};
pub(crate) const REGIONS: [(&str, u32, &str); 4] = [
    ("entry-shim", 0x4017a4, "e8c8030000e971feffff"),
    (
        "startup-prefix",
        0x40161f,
        "6a146838b24100e8350800006a01e813030000",
    ),
    (
        "startup-initializer",
        0x401945,
        "558bec837d08007507c60584cc410001e84b050000e86b0b0000",
    ),
    (
        "startup-cpu-prefix",
        0x401ea5,
        "558bec830d58c041000183ec28c705b8cc4100000000006a0aff151c504100",
    ),
];
pub(crate) fn source(regions: &[Vec<u8>], helper: &[u8]) -> Result<String, String> {
    if regions.len() != 4 {
        return Err("startup slice region count".into());
    }
    for (bytes, (_, _, literal)) in regions.iter().zip(REGIONS) {
        if *bytes
            != literal
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                .collect::<Vec<_>>()
        {
            return Err("startup slice original bytes".into());
        }
    }
    let p = crate::crt_exception_wrapper::PrologProof::prove(
        crate::crt_exception_wrapper::Region {
            bytes: helper,
            origin: 0x401e60,
        },
        20,
        0x41b238,
        0x41c000,
        0x402210,
    )?;
    let l = &p.layout;
    let saved: Vec<_> = l.saved.iter().map(|(&o, &r)| (o, r)).collect();
    let layout=format!("fn startup_layout()->CrtNormalLayout{{CrtNormalLayout{{low:{},bp:{},record:{},scope_slot:{},level:{},saved_sp:{},guard:{},saved:vec!{:?},scope:0x41b238,handler:0x402210,cookie_address:0x41c000,pop:0}}}}",l.low,l.frame_pointer,l.record,l.scope_slot,l.level_slot,l.saved_sp,l.guard,saved);
    let mut out = p.emit("startup_helper")?;
    out.push_str(&format!(
        "fn startup_helper_code()->Vec<u8>{{vec!{helper:?}}}"
    ));
    out.push_str(&layout);
    let roles = std::collections::BTreeMap::from([
        (0x41cc84, "CrtRegionKind::Module".into()),
        (0x41c058, "CrtRegionKind::Module".into()),
        (0x41ccb8, "CrtRegionKind::Module".into()),
    ]);
    for (i, bytes) in regions.iter().enumerate() {
        let (_, origin, _) = REGIONS[i];
        let graph = if i == 0 {
            Graph::decode_with_exits(bytes, origin, &[0x40161f])?
        } else {
            // Exact original fragment with an explicitly unbound final call, never
            // treated as a closed function. The emitter validates all internal edges.
            let mut d = iced_x86::Decoder::with_ip(
                32,
                bytes,
                u64::from(origin),
                iced_x86::DecoderOptions::NONE,
            );
            let mut nodes = std::collections::BTreeMap::new();
            while d.can_decode() {
                let ins = d.decode();
                let pc = ins.ip() as u32;
                let at = (pc - origin) as usize;
                nodes.insert(
                    pc,
                    Graph::decode_instruction(&bytes[at..at + ins.len()], pc)?,
                );
            }
            Graph {
                origin,
                end: origin + bytes.len() as u32,
                nodes,
            }
        };
        let body = crate::crt_stream_emit::emit_body_with_store(
            &graph,
            |pc, target| {
                Ok(match(pc,target){
   (0x4017a4,Target::Direct(0x401b71))=>"cpu.call_activation(rt,0x4017a9,0,|rt,c|original_cookie_init_connected(rt,c,inputs,backend))?;".into(),
   (0x401626,Target::Direct(0x401e60))=>r#"let n=rt.generation.checked_add(1).filter(|n|*n<1u64<<63).ok_or("startup helper identity exhausted")?;let id=n|(1u64<<63);if rt.tags.values().any(|v|*v==CrtValue::ProtectedReturn(id)){return Err("startup helper identity collision");}cpu.push(rt,CrtValue::ProtectedReturn(id))?;rt.generation=n;startup_helper(rt,cpu,id,binding.token,|rt,c,record,head|binding.install(rt,c,epoch,record,head))?;"#.into(),
   (0x40162d,Target::Direct(0x401945))=>"cpu.call_activation(rt,0x401632,0,|rt,c|startup_initializer(rt,c,inputs,backend,features,platform))?;".into(),
   (0x401955,Target::Direct(0x401ea5))=>"cpu.call_activation(rt,0x40195a,0,|rt,c|startup_cpu_prefix(rt,c,inputs,backend,features,platform))?;".into(),
   (0x401ebe,Target::Import(0x41501c))=>r#"cpu.call_activation(rt,0x401ec4,4,|rt,c|features.ok_or("startup processor feature contract unbound at 0x401ebe")?.api(rt,c))?;return startup_cpu_tail(rt,cpu,inputs,features.ok_or("startup feature scope missing")?);"#.into(),
   (0x40195a,Target::Direct(0x4024ca))=>"cpu.call_activation(rt,0x40195f,0,|rt,c|startup_modules_platform(rt,c,inputs,platform))?;".into(),
   _=>return Err("startup slice call binding".into())
  })
            },
            &roles,
            128,
            |_, _| Err("startup slice unexpected FS".into()),
            |pc, _| {
                Ok(if pc == 0x401626 {
                    format!("let hp=rt.process_image_code(inputs.image,0x401e60,{})?;if rt.memory.read(hp.address(),{}).map_err(|_|\"startup helper code read\")?!=startup_helper_code().as_slice(){{return Err(\"startup helper live code changed\");}}",helper.len(),helper.len())
                } else {
                    String::new()
                })
            },
            |_, _| Ok(None),
            Some(if i == 0 {
                0x40161f
            } else {
                origin + bytes.len() as u32
            }),
            |_, _, _| Ok(None),
        )?;
        let body = if i == 2 {
            format!("let value=(||->Result<CrtValue,&'static str>{{{body}}})()?;if !cpu.returned{{return Err(\"startup initializer continuation unbound at 0x40195f\");}}Ok(value)")
        } else {
            body
        };
        let (name, params) = match i {
            0 => ("startup_shim", ""),
            1 => (
                "startup_prefix",
                ",epoch:&mut NormalCallEpoch<'_>,binding:&mut CrtNormalBinding",
            ),
            2 => ("startup_initializer", ""),
            _ => ("startup_cpu_prefix", ""),
        };
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,backend:&mut impl CrtEntropyBackend,features:Option<&CrtFeatureObservation>,platform:Option<&CrtNativePlatform>{params})->Result<CrtValue,&'static str>{{cpu.validate_active(rt)?;inputs.validate(rt)?;let p=rt.process_image_code(inputs.image,{origin},{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"startup code read\")?!=&{bytes:?}{{return Err(\"startup live code changed\");}}{body}}}",bytes.len(),bytes.len()));
    }
    out.push_str(r#"fn startup_connected(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,backend:&mut impl CrtEntropyBackend,features:Option<&CrtFeatureObservation>,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{
 startup_connected_platform(rt,cpu,inputs,backend,features,None,epoch)
}
fn startup_connected_platform(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,backend:&mut impl CrtEntropyBackend,features:Option<&CrtFeatureObservation>,platform:Option<&CrtNativePlatform>,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{
 if let Some(p)=platform{p.validate(rt,inputs.init)?;}
 inputs.validate(rt)?;let root=rt.process_image(inputs.image)?;let nt=rt.load(rt.offset(root,0x3c)?,32)?.known_scalar()?;let rva=rt.load(rt.offset(root,i64::from(nt)+40)?,32)?.known_scalar()?;
 if root.address().checked_add(rva)!=Some(0x4017a4){return Err("startup original PE entry identity");}
 startup_shim(rt,cpu,inputs,backend,features,platform)?;let mut binding=CrtNormalBinding::bind_initializing(rt,cpu,epoch,startup_layout(),inputs.init)?;startup_prefix(rt,cpu,inputs,backend,features,platform,epoch,&mut binding)
}"#);
    Ok(out)
}
#[test]
fn original_startup_slice_rejects_all_changed_code() {
    let regions: Vec<_> = REGIONS
        .iter()
        .map(|(_, _, s)| crate::crt_ptd::raw(s))
        .collect();
    let helper=crate::crt_ptd::raw("681022400064ff35000000008b442410896c24108d6c24102be0535657a100c041003145fc33c5508965e8ff75f88b45fcc745fcfeffffff8945f88d45f064a300000000c3");
    source(&regions, &helper).expect("original entry and initializer lower");
    for n in 0..4 {
        for j in 0..regions[n].len() {
            let mut r = regions.clone();
            r[n][j] ^= 1;
            assert!(source(&r, &helper).is_err());
        }
    }
}
