//! Original locale callback prefix and registered required-PTD acquisition.
//! The aligned multibyte frame remains rejected before entry.
use crate::crt_stream_ir::{Graph, Target};
pub(crate) const CALLBACK:&str="803d48d1410000753cc70540d1410040c24100c7053cd1410068c54100c70538d1410060c44100e899eeffff6840d14100506a016afde8d0fdffff83c410c60548d1410001b001c3";
pub(crate) const GETTER:&str="6a00b84a4b4100e86d9f00008365fc00a170c1410083f8ff741550e852ddffff85c0740b83f8ff740fe8379f0000c3e8cbfeffff85c075f1e8d3d4ffff";
pub(crate) const HANDLER: &str = "90908b5424088d420c8b4af033c8e8efc9feffb8dcb44100e99be4feff";
pub(crate) fn source() -> Result<String, String> {
    let bytes = crate::crt_ptd::raw(CALLBACK);
    let g = Graph::decode(&bytes, 0x40b42a)?;
    let body = crate::crt_stream_emit::emit_body(
        &g,
        |pc, target| {
            let next = pc + g.nodes[&pc].length;
            Ok(match target{Target::Direct(0x40a2ef)=>format!("cpu.call_activation(rt,{next},0,|rt,c|locale_required_ptd(rt,c,inputs,platform,epoch))?;"),Target::Direct(0x40b235)=>"return Err(\"locale aligned multibyte frame unbound at 0x40b460\");".into(),_=>return Err("locale callback unexpected target".into())})
        },
        &std::collections::BTreeMap::from([
            (0x41d148, "CrtRegionKind::Module".into()),
            (0x41d140, "CrtRegionKind::Module".into()),
            (0x41d13c, "CrtRegionKind::Module".into()),
            (0x41d138, "CrtRegionKind::Module".into()),
        ]),
        512,
    )?;
    let mut out=format!("fn locale_startup_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;platform.validate(rt,inputs.init)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,0x40b42a,{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"locale callback code read\")?!=&{bytes:?}{{return Err(\"locale callback code changed\");}}{body}}}",bytes.len(),bytes.len());
    let bytes = crate::crt_ptd::raw(GETTER);
    // The original nonreturning termination call is the final node. Its actual
    // trailing INT3 is an explicit rejected boundary, never structural success.
    let g = crate::crt_startup_table::graph(&bytes, 0x40a2ef)?;
    let body = crate::crt_stream_emit::emit_body_with_exit(
        &g,
        |pc, target| {
            let next = pc + g.nodes[&pc].length;
            Ok(match target{
   Target::Direct(0x414268)=>format!("binding=Some(CrtCxxChainBinding::bind(rt,cpu,epoch)?);binding.as_ref().unwrap().prepare(rt,cpu,epoch)?;frame=Some(CrtPtdFrame::new_mode(rt,cpu,binding.as_ref().unwrap().token,0x414b4a,0x41c000,true)?);ptd_prolog_registered(rt,cpu,epoch,frame.as_mut().unwrap(),binding.as_mut().unwrap(),{next})?;"),
   Target::Direct(0x414254)=>format!("ptd_epilog_registered(rt,cpu,epoch,frame.as_mut().ok_or(\"required PTD missing frame\")?,binding.as_mut().ok_or(\"required PTD missing chain\")?,{next})?;"),
   Target::Direct(0x408061)=>format!("frame.as_ref().ok_or(\"required PTD missing frame\")?.live(rt,cpu)?;let p=rt.process_image_code(inputs.image,0x408061,12)?;if rt.memory.read(p.address(),12).map_err(|_|\"required PTD FLS code read\")?!=&{:?}{{return Err(\"required PTD FLS thunk changed\");}}rt.process_image_import(inputs.image,0x4150a0,\"kernel32.dll\",\"FlsGetValue\")?;cpu.call_activation(rt,{next},4,|rt,c|{{let cpu=&mut *c;let _=(||->Result<CrtValue,&'static str>{{{}}})()?;let v=platform.fls_get_call(rt,cpu,inputs.init)?;locale_required_view(rt,platform,v)?;Ok(v)}})?;",crate::crt_ptd::raw(crate::crt_ptd::FLS_THUNK),crate::crt_stream_emit::emit_linear_fragment(&Graph::decode_linear_fragment(&crate::crt_ptd::raw(crate::crt_ptd::FLS_THUNK)[..6],0x408061)?,&Default::default())?),
   Target::Direct(0x40a1ee)=>format!("cpu.call_activation(rt,{next},0,|rt,c|ucrt_lazy_native(rt,c,inputs,platform,epoch))?;locale_required_view(rt,platform,cpu.r[0])?;"),
   Target::Direct(0x4077ff)=>"return Err(\"required PTD termination effect unbound\");".into(),
   _=>return Err("required PTD unexpected target".into())})
        },
        &std::collections::BTreeMap::from([(0x41c170, "CrtRegionKind::Module".into())]),
        2048,
        |_, _| Err("required PTD direct FS effect unbound".into()),
        |_, _| Ok(String::new()),
        |_, pop| {
            if pop != 0 {
                return Err("required PTD RET cleanup".into());
            }
            Ok(Some("if !frame.as_ref().is_some_and(|f|f.phase==2)||!binding.as_ref().is_some_and(|b|b.done){return Err(\"required PTD incomplete epilog\");}locale_required_view(rt,platform,cpu.r[0])?;return cpu.finish(rt);".into()))
        },
        Some(g.end),
    )?;
    let terminal = format!("if pc=={}{{return Ok(cpu.r[0]);}}", g.end);
    if !body.contains(&terminal) {
        return Err("required PTD terminal guard missing".into());
    }
    let body = body.replace(
        &terminal,
        &format!(
            "if pc=={}{{return Err(\"required PTD terminal trap reached\");}}",
            g.end
        ),
    );
    let prolog = crate::crt_ptd::raw(crate::crt_ptd::PROLOG);
    let epilog = crate::crt_ptd::raw(crate::crt_ptd::EPILOG);
    let handler = crate::crt_ptd::raw(HANDLER);
    out.push_str(&format!("fn locale_required_ptd(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;platform.validate(rt,inputs.init)?;cpu.validate_active(rt)?;epoch.state()?;CrtNormalBinding::validate_cxx_head(rt,epoch)?;for(address,expected)in[(0x40a2efu32,&{bytes:?}[..]),(0x414268,&{prolog:?}[..]),(0x414254,&{epilog:?}[..]),(0x414b4a,&{handler:?}[..])]{{let p=rt.process_image_code(inputs.image,address,expected.len()as u32)?;if rt.memory.read(p.address(),expected.len()as u32).map_err(|_|\"required PTD code read\")?!=expected{{return Err(\"required PTD code changed\");}}}}let mut frame:Option<CrtPtdFrame>=None;let mut binding:Option<CrtCxxChainBinding>=None;{body}}}"));
    out.push_str("fn locale_required_view(rt:&CrtStreamRuntime,_platform:&CrtNativePlatform,value:CrtValue)->Result<(),&'static str>{match value{CrtValue::Pointer(p)=>{let view=rt.heap_ptds.iter().find(|v|v.pointer==p&&v.layout==CrtPtdLayout::Ucrt).ok_or(\"required PTD UCRT allocation view\")?;rt.heap_ptd_layout_view(p,view.slot,CrtPtdLayout::Ucrt)?;if rt.fls.get(&view.slot.index).map(|x|x.1)!=Some(value){return Err(\"required PTD publication changed\");}Ok(())},CrtValue::Scalar{bits:0|u32::MAX,known:u32::MAX}=>Ok(()),_=>Err(\"required PTD value authority\")}}\n");
    Ok(out)
}

#[cfg(test)]
const ALIGN_PREFIX: &str = "8bff538bdc515183e4f883c40455";
#[cfg(test)]
const ALIGN_TAIL: &str = "558b6b04896c24048bec81ec380200005657ff7314ff7310";

#[test]
fn original_stack_alignment_exposes_pointer_and_return_copy_limits() {
    let prefix = crate::crt_ptd::raw(ALIGN_PREFIX);
    let g = Graph::decode_linear_fragment(&prefix, 0x40b235).unwrap();
    let body = crate::crt_stream_emit::emit_linear_fragment(&g, &Default::default()).unwrap();
    let tail = crate::crt_ptd::raw(ALIGN_TAIL);
    let tg = Graph::decode_linear_fragment(&tail, 0x40b242).unwrap();
    let tb = crate::crt_stream_emit::emit_linear_fragment(&tg, &Default::default()).unwrap();
    let add = Graph::decode_linear_fragment(&[0x83, 0xc4, 4], 0x40b23f).unwrap();
    let add_body = crate::crt_stream_emit::emit_linear_fragment(&add, &Default::default()).unwrap();
    let extra=format!("fn align_prefix(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}fn alignment_add(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{add_body}}}fn alignment_tail(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{tb}}}");
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
for offset in [2048,2052]{
 let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0xa000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,offset).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(99)).unwrap();let mut c=CrtCpu::new(sp,99).unwrap();c.clobber(CrtValue::scalar(0));let old=c.entry;
 assert_eq!(align_prefix(&mut rt,&mut c),Err("CRT pointer provenance"));assert!(!c.returned);assert_eq!(c.steps,7);assert!(matches!(c.r[4],CrtValue::Scalar{known:u32::MAX,..}));assert_eq!(CrtCpu::number(c.r[4]).unwrap(),(sp.address()-12)&!7);assert_eq!(rt.load(sp,32).unwrap(),CrtValue::ProtectedReturn(99));assert_eq!(rt.load(rt.offset(sp,-4).unwrap(),32).unwrap(),old[3]);assert_eq!(c.r[3],CrtValue::Pointer(rt.offset(sp,-4).unwrap()));
 // AND loses pointer authority; the following ADD rejects in discard before
 // writing its result. PUSH has not executed. Independent reference state
 // after mathematical alignment and ADD, not a
 // production lowering or admission bypass. Execute the original copy tail.
 let aligned=rt.offset(stack,i64::from(CrtCpu::number(c.r[4]).unwrap()-stack.address())).unwrap();let padding=rt.load(aligned,32);c.r[4]=CrtValue::Pointer(aligned);let added=alignment_add(&mut rt,&mut c);
 assert_eq!(padding,Ok(CrtValue::Scalar{bits:0,known:0}),"unknown padding/pushed data must stay unknown");added.expect("owned ordinary padding need not have known bits in the declared reference state");assert_eq!(c.r[4],CrtValue::Pointer(rt.offset(aligned,4).unwrap()));
 c.r[4]=CrtValue::Pointer(rt.offset(aligned,4).unwrap());for n in 1..=4{rt.store(rt.offset(sp,n*4).unwrap(),32,CrtValue::scalar(n as u32)).unwrap();}
 alignment_tail(&mut rt,&mut c).expect("original mirror/callee frame writes must execute in the reference state");
 assert_eq!(rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(99)).count(),2);assert_eq!(c.validate_active(&rt),Err("CRT active caller lifetime/return authority"));assert_eq!(rt.load(sp,32).unwrap(),CrtValue::ProtectedReturn(99));
}
"#,
        "original-aligned-frame-limits",
    );
}
