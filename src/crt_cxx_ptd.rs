//! VCRUNTIME dispatcher PTD: distinct from the UCRT FLS/errno object.
use crate::crt_stream_ir::{Graph, Target};
use std::collections::BTreeMap;
pub(crate) const REQUIRED: &str = "e80900000085c00f842f4f0000c3";
pub(crate) const GETTER:&str="833d60c04100ff750333c0c35357ff1544504100ff3560c041008bf8e8c20200008bd85983fbff741785db75596affff3560c04100e8e4020000595985c0750433dbeb42566a286a01e8314f00008bf0595985f6741256ff3560c04100e8bc020000595985c0751233db53ff3560c04100e8a80200005959eb048bde33f656e8fb4d0000595e57ff15485041005f8bc35bc3";
pub(crate) fn source(getter: &[u8], required: &[u8]) -> Result<String, String> {
    emit_source(getter, required, false)
}
pub(crate) fn dynamic_source(getter: &[u8], required: &[u8]) -> Result<String, String> {
    emit_source(getter, required, true)
}
fn emit_source(getter: &[u8], required: &[u8], dynamic: bool) -> Result<String, String> {
    let parameters = if dynamic {
        "access:CrtResolverAccess,fiber:CrtFiber,slot:CrtFlsSlot,api:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,u32)->Result<CrtValue,&'static str>"
    } else {
        "lookup:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>"
    };
    let arguments = if dynamic {
        "access,fiber,slot,api"
    } else {
        "lookup"
    };
    let lookup = if dynamic {
        "cxx_dynamic_lookup"
    } else {
        "cxx_original_lookup"
    };
    let entry = if dynamic { "access.check(rt)?;" } else { "" };
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
 Target::Direct(0x402bb4)=>format!("cpu.call_activation(rt,{next},0,|rt,child|{lookup}(rt,child,{arguments}))?;"),
 _=>"return Err(\"C++ PTD lazy setter/allocation/free effect unbound\");".into()})
        },
        &roles,
        4096,
    )?;
    let mut out=format!("fn cxx_ptd_get(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,{parameters})->Result<CrtValue,&'static str>{{{entry}{body}}}");
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
            Ok(format!(
                "cpu.call_activation(rt,0x4028c8,0,|rt,child|cxx_ptd_get(rt,child,{arguments}))?;"
            ))
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
    out.push_str(&format!("fn cxx_ptd_required(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,{parameters})->Result<CrtValue,&'static str>{{{entry}let value=(||->Result<CrtValue,&'static str>{{{body}}})()?;if cpu.returned{{return Ok(value);}}Err(\"C++ required PTD termination effect unbound\")}}"));
    if dynamic {
        out.push_str(&crate::crt_cxx_lookup::cold_source(
            &crate::crt_ptd::raw(crate::crt_cxx_lookup::COLD_FULL),
            &crate::crt_ptd::raw(crate::crt_cxx_lookup::LOAD_HELPER),
        )?);
        out.push_str(&crate::crt_cxx_lookup::dynamic_source(
            &crate::crt_ptd::raw(crate::crt_cxx_lookup::WRAPPER),
            &crate::crt_ptd::raw(crate::crt_cxx_lookup::INDIRECT_GUARD),
        )?);
    } else {
        out.push_str(&crate::crt_cxx_lookup::source(
            &crate::crt_ptd::raw(crate::crt_cxx_lookup::PREFIX),
            &crate::crt_ptd::raw(crate::crt_cxx_lookup::EPILOG),
            &crate::crt_ptd::raw(crate::crt_cxx_lookup::WRAPPER),
        )?);
    }
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

#[test]
fn dispatcher_getter_connects_dynamic_fls_without_losing_error_or_lifetime_checks() {
    let getter = crate::crt_ptd::raw(GETTER);
    let required = crate::crt_ptd::raw(REQUIRED);
    let extra = dynamic_source(&getter, &required).unwrap();
    if let Some(out) = std::env::var_os("W2L_EH4_EVIDENCE") {
        std::fs::write(
            std::path::Path::new(&out).join("dynamic-dispatcher-ptd.rs"),
            format!(
                "{}\n{}\n{}",
                crate::crt_stream_runtime::EMITTED_TYPES,
                crate::crt_stream_cpu::EMITTED_TYPES,
                extra
            ),
        )
        .unwrap();
    }
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
for mode in 0..29 {
 let(mut rt,init)=CrtStreamRuntime::new_initializing(23,45,0x8000,65536).unwrap();
 let index=rt.map_region(0x41c060,4,CrtRegionKind::Module,Some(&(if mode==14{u32::MAX}else{7u32}).to_le_bytes())).unwrap();if mode==13{rt.store(index,32,CrtValue::Scalar{bits:0,known:0}).unwrap();}
 let (m,reference)=rt.module_acquire_result(init,"unrelated dispatcher dependency",0x710000).unwrap();let f=rt.module_export_result(init,m,if mode==16{"WrongFunction"}else{"FlsGetValue"},0x711000).unwrap();
 let cache_root=rt.map_region(0x41cd14,12,CrtRegionKind::Module,None).unwrap();let cache=rt.offset(cache_root,8).unwrap();rt.store(cache,32,if matches!(mode,17|19|20){CrtValue::scalar(0)}else if mode==26{CrtValue::scalar(u32::MAX)}else{CrtValue::Function(f)}).unwrap();
 let guard=rt.map_region(0x415128,4,CrtRegionKind::Module,Some(&0x401bf9u32.to_le_bytes())).unwrap();
 rt.map_region(0x415d4c,8,CrtRegionKind::Input,Some(&[0,0,0,0,2,0,0,0])).unwrap();rt.map_region(0x415d54,12,CrtRegionKind::Input,Some(b"FlsGetValue\0")).unwrap();
 let ptd=rt.map_region(0x7000,if mode==1{20}else if mode==2{39}else{40},CrtRegionKind::ThreadData,None).unwrap();let fiber=rt.bind_fiber(45).unwrap();let slot=rt.bind_fls(fiber,7,if mode==3{CrtValue::scalar(0)}else if mode==4{CrtValue::scalar(u32::MAX)}else{CrtValue::Pointer(ptd)}).unwrap();
 let(mut other,other_init)=CrtStreamRuntime::new_initializing(23,45,0x8000,65536).unwrap();let foreign=other.bind_fiber(45).unwrap();
 match mode{
  28=>{rt.retire_fls(fiber,slot).unwrap();rt.retire_fiber(fiber).unwrap();},
  5|21=>{rt.retire_fls(fiber,slot).unwrap();},6=>{rt.retire_fls(fiber,slot).unwrap();rt.bind_fls(fiber,7,CrtValue::Pointer(ptd)).unwrap();},
  8|9|22=>{rt.module_release_result(init,reference,true).unwrap();if mode==9{rt.module_acquire_result(init,"unrelated dispatcher dependency",0x710000).unwrap();}},
  10|27=>{rt.retire_region(ptd).unwrap();},11=>{rt.store(guard,32,CrtValue::scalar(0x401bfa)).unwrap();},12=>{rt.fls_set(fiber,slot,7,CrtValue::Pointer(ptd),false,Some(8)).unwrap();},
  17=>{let cells=rt.map_region(0x41cd08,12,CrtRegionKind::Module,Some(&[0;12])).unwrap();rt.bind_loader_cell(init,cells,false).unwrap();rt.bind_loader_cell(init,cache,true).unwrap();let name=rt.map_region(0x6500,4,CrtRegionKind::Input,Some(&[97,0,0,0])).unwrap();let table=rt.map_region(0x415c80,12,CrtRegionKind::Module,None).unwrap();rt.store(table,32,CrtValue::Pointer(name)).unwrap();},_=>{}
 }
 if mode>=18&&mode!=20{rt.end_initialization(init).unwrap();}
 let access=if matches!(mode,18|19|20|21|22|23|26|27|28){CrtResolverAccess::Cached}else{CrtResolverAccess::Initializing(if mode==25{other_init}else{init})};
 if mode==20{rt.bind_loader_cell(init,cache,true).unwrap();}
 let cache_before=rt.memory.read(cache.address(),4).unwrap().to_vec();let tag_before=rt.tags.get(&cache.address()).copied();let refs_before=rt.module_references.len();let fls_before=rt.fls.clone();let phase_before=rt.initialization;
 let probe=rt.map_region(0x6600,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes())).unwrap();rt.last_os_error=if mode==15{None}else{Some(55)};let initial=rt.last_os_error;
 let stack=rt.map_region(0x9000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,3072).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();cpu.r[1]=CrtValue::Scalar{bits:0,known:0};let saved=cpu.r;
 let result=cxx_ptd_required(&mut rt,&mut cpu,access,if mode==7||mode==23{foreign}else{fiber},slot,&mut |rt,_,iat|{assert_eq!(mode,17);assert_eq!(iat,0x415074);rt.store(probe,32,CrtValue::scalar(77))?;rt.last_os_error=Some(99);Err("independent loader failure with earlier effects")});
 if mode==0||mode==15||mode==18{assert_eq!(result.unwrap(),CrtValue::Pointer(ptd));assert!(cpu.returned);for r in [3,5,6,7]{assert_eq!(cpu.r[r],saved[r]);}assert!(rt.load(rt.offset(ptd,16).unwrap(),32).unwrap().known_scalar().is_err());assert!(cxx_ptd_required(&mut rt,&mut cpu,access,fiber,slot,&mut |_,_,_|panic!("replay effect")).is_err());}
 else{assert!(result.is_err(),"mode {mode}");assert!(!cpu.returned);}
 if mode>=18{assert_eq!(rt.memory.read(cache.address(),4).unwrap(),cache_before);assert_eq!(rt.tags.get(&cache.address()).copied(),tag_before);assert_eq!(rt.module_references.len(),refs_before);assert_eq!(rt.fls,fls_before);assert_eq!(rt.initialization,phase_before);if mode==20{assert!(access.initialization(&rt).is_err());}else{assert!(rt.exchange_module_word(cache,CrtValue::scalar(0)).is_err());}}
 assert_eq!(rt.last_os_error,if mode==3{None}else if mode==17{Some(99)}else{initial},"mode {mode}");if mode==17{assert_eq!(rt.load(probe,32).unwrap(),CrtValue::scalar(77));}
}
"#,
        "connected-dispatcher-fls",
    );
    for (which, bytes) in [(0, &getter), (1, &required)] {
        for i in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[i] ^= 1;
            assert!(if which == 0 {
                dynamic_source(&changed, &required)
            } else {
                dynamic_source(&getter, &changed)
            }
            .is_err());
        }
    }
}
