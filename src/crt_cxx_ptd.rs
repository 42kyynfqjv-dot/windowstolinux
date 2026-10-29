//! VCRUNTIME dispatcher PTD: distinct from the UCRT FLS/errno object.
use crate::crt_stream_ir::{Graph, Target};
use std::collections::BTreeMap;
pub(crate) const REQUIRED: &str = "e80900000085c00f842f4f0000c3";
pub(crate) const GETTER:&str="833d60c04100ff750333c0c35357ff1544504100ff3560c041008bf8e8c20200008bd85983fbff741785db75596affff3560c04100e8e4020000595985c0750433dbeb42566a286a01e8314f00008bf0595985f6741256ff3560c04100e8bc020000595985c0751233db53ff3560c04100e8a80200005959eb048bde33f656e8fb4d0000595e57ff15485041005f8bc35bc3";
pub(crate) fn source(getter: &[u8], required: &[u8]) -> Result<String, String> {
    if getter != crate::crt_ptd::raw(GETTER) || required != crate::crt_ptd::raw(REQUIRED) {
        return Err("C++ PTD original code binding".into());
    }
    let roles = BTreeMap::from([(0x41c060, "CrtRegionKind::Module".into())]);
    let graph = Graph::decode(getter, 0x4028d1).map_err(|e| format!("getter: {e}"))?;
    let body = crate::crt_stream_emit::emit_body(
        &graph,
        |pc, target| {
            let next = pc + graph.nodes[&pc].length;
            Ok(match target{
 Target::Import(0x415044)=>format!("cpu.call_activation(rt,{next},0,|rt,child|{{child.clobber(rt.last_os_error.map(CrtValue::scalar).unwrap_or(CrtValue::Scalar{{bits:0,known:0}}));child.finish(rt)}})?;"),
 Target::Import(0x415048)=>format!("cpu.call_activation(rt,{next},4,|rt,child|{{let p=CrtCpu::pointer(child.r[4])?;let value=rt.load(rt.offset(p,4)?,32)?;if !matches!(value,CrtValue::Scalar{{..}}){{return Err(\"C++ LastError scalar\");}}rt.last_os_error=value.known_scalar().ok();child.clobber(CrtValue::Scalar{{bits:0,known:0}});child.finish_pop(rt,4)}})?;"),
 Target::Direct(0x402bb4)=>format!("cpu.call_activation(rt,{next},0,|rt,child|cxx_original_lookup(rt,child,lookup))?;"),
 _=>"return Err(\"C++ PTD lazy setter/allocation/free effect unbound\");".into()})
        },
        &roles,
        4096,
    )?;
    let mut out=format!("fn cxx_ptd_get(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lookup:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{{body}}}");
    // This certified 14-byte wrapper has a conditional nonreturning exit.
    // Keep the generic decoder's JMP-only external-edge policy unchanged.
    let nodes = [(0, 5), (5, 7), (7, 13), (13, 14)]
        .into_iter()
        .map(|(a, b)| {
            Ok((
                0x4028c3 + a as u32,
                Graph::decode_instruction(&required[a..b], 0x4028c3 + a as u32)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let graph = Graph {
        origin: 0x4028c3,
        end: 0x4028d1,
        nodes,
    };
    let body = crate::crt_stream_emit::emit_body_with_exit(
        &graph,
        |_, target| {
            if target != Target::Direct(0x4028d1) {
                return Err("C++ required PTD target".into());
            }
            Ok(
                "cpu.call_activation(rt,0x4028c8,0,|rt,child|cxx_ptd_get(rt,child,lookup))?;"
                    .into(),
            )
        },
        &roles,
        4096,
        |_, _| Err("C++ PTD unexpected thread effect".into()),
        |_, _| Ok(String::new()),
        |_, pop| {
            if pop != 0 {
                return Err("C++ PTD RET cleanup".into());
            }
            Ok(Some("let p=CrtCpu::pointer(cpu.r[0])?;if p.kind!=CrtRegionKind::ThreadData||p.address()!=p.base||!rt.regions.iter().any(|r|r.pointer==p){return Err(\"C++ PTD root provenance\");}rt.valid(p,40)?;return cpu.finish(rt);".into()))
        },
        Some(0x4077ff),
    )?;
    out.push_str(&format!("fn cxx_ptd_required(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lookup:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{let value=(||->Result<CrtValue,&'static str>{{{body}}})()?;if cpu.returned{{return Ok(value);}}Err(\"C++ required PTD termination effect unbound\")}}"));
    out.push_str(&crate::crt_cxx_lookup::source(
        &crate::crt_ptd::raw(crate::crt_cxx_lookup::PREFIX),
        &crate::crt_ptd::raw(crate::crt_cxx_lookup::EPILOG),
        &crate::crt_ptd::raw(crate::crt_cxx_lookup::WRAPPER),
    )?);
    Ok(out)
}
#[test]
fn distinct_dispatcher_ptd_extent_and_failure_paths() {
    let extra = source(&crate::crt_ptd::raw(GETTER), &crate::crt_ptd::raw(REQUIRED)).unwrap();
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
for mode in 0..19{
 let mut rt=CrtStreamRuntime::new(7,9,0x8000,65536).unwrap();
 let index=rt.map_region(0x41c060,4,CrtRegionKind::Module,Some(&(if mode==8{u32::MAX}else{3u32}).to_le_bytes())).unwrap();
 let mut cache_bytes=[0u8;12];cache_bytes[8..12].copy_from_slice(&(if mode==14{0}else if mode==15{0x401234}else{u32::MAX}).to_le_bytes());let cache=rt.map_region(0x41cd14,if mode==17{8}else{12},if mode==18{CrtRegionKind::Input}else{CrtRegionKind::Module},Some(if mode==17{&cache_bytes[..8]}else{&cache_bytes})).unwrap();if mode==16{rt.store(rt.offset(cache,8).unwrap(),32,CrtValue::Scalar{bits:0,known:0}).unwrap();}
 let ptd=rt.map_region(0x7000,if mode==1{20}else if mode==2{39}else{40},if mode==12{CrtRegionKind::Context}else{CrtRegionKind::ThreadData},None).unwrap();
 let stack=rt.map_region(0x9000,2048,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,1536).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();let saved=cpu.r;
 let probe=rt.map_region(0x6000,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes())).unwrap();
 rt.last_os_error=if mode==9{None}else{Some(55)};let initial=rt.last_os_error;if mode==11{rt.retire_region(ptd).unwrap();}
 let mut other=CrtStreamRuntime::new(7,9,0x8000,65536).unwrap();let foreign=other.map_region(0x7000,40,CrtRegionKind::ThreadData,None).unwrap();
 let mut calls=0;let result=cxx_ptd_required(&mut rt,&mut cpu,&mut |rt,child|{calls+=1;let sp=CrtCpu::pointer(child.r[4])?;assert_eq!(rt.load(rt.offset(sp,4)?,32)?,CrtValue::scalar(3));rt.last_os_error=None;
 if mode==10{rt.store(probe,32,CrtValue::scalar(77))?;return Err("independent lookup failure");}
 let v=match mode{13=>CrtValue::Pointer(foreign),3=>CrtValue::scalar(ptd.address()),4=>CrtValue::Pointer(rt.offset(ptd,4)?),5=>CrtValue::Scalar{bits:0,known:0},6=>CrtValue::scalar(0),7=>CrtValue::scalar(u32::MAX),_=>CrtValue::Pointer(ptd)};child.clobber(v);child.finish_pop(rt,4)});
 if mode==0||mode==9{assert_eq!(result.unwrap(),CrtValue::Pointer(ptd));assert!(cpu.returned);for r in [3,5,6,7]{assert_eq!(cpu.r[r],saved[r]);}assert!(cxx_ptd_required(&mut rt,&mut cpu,&mut |_,_|panic!("replay")).is_err());}
 else{assert!(result.is_err(),"mode {}",mode);assert!(!cpu.returned);}
 if mode==10{assert_eq!(rt.load(probe,32).unwrap(),CrtValue::scalar(77));assert_eq!(rt.last_os_error,None);}else if mode==5||mode==6{assert_eq!(rt.last_os_error,None);}else{assert_eq!(rt.last_os_error,initial,"mode {}",mode);}
 assert_eq!(calls,if mode==8||mode>=14{0}else{1});assert_eq!(rt.load(index,32).unwrap(),CrtValue::scalar(if mode==8{u32::MAX}else{3}));
}
"#,
        "cxx-ptd-effects",
    );
    for (which, raw) in [
        crate::crt_cxx_lookup::PREFIX,
        crate::crt_cxx_lookup::EPILOG,
        crate::crt_cxx_lookup::WRAPPER,
    ]
    .iter()
    .enumerate()
    {
        for i in 0..raw.len() / 2 {
            let mut code = [
                crate::crt_ptd::raw(crate::crt_cxx_lookup::PREFIX),
                crate::crt_ptd::raw(crate::crt_cxx_lookup::EPILOG),
                crate::crt_ptd::raw(crate::crt_cxx_lookup::WRAPPER),
            ];
            code[which][i] ^= 1;
            assert!(crate::crt_cxx_lookup::source(&code[0], &code[1], &code[2]).is_err());
        }
    }
    for (which, raw) in [GETTER, REQUIRED].iter().enumerate() {
        for i in 0..raw.len() / 2 {
            let mut b = [crate::crt_ptd::raw(GETTER), crate::crt_ptd::raw(REQUIRED)];
            b[which][i] ^= 1;
            assert!(source(&b[0], &b[1]).is_err());
        }
    }
}
