//! VCRUNTIME dispatcher PTD: distinct from the UCRT FLS/errno object.
use crate::crt_stream_ir::{Graph, Target};
use std::collections::BTreeMap;
pub(crate) const REQUIRED: &str = "e80900000085c00f842f4f0000c3";
pub(crate) const GETTER:&str="833d60c04100ff750333c0c35357ff1544504100ff3560c041008bf8e8c20200008bd85983fbff741785db75596affff3560c04100e8e4020000595985c0750433dbeb42566a286a01e8314f00008bf0595985f6741256ff3560c04100e8bc020000595985c0751233db53ff3560c04100e8a80200005959eb048bde33f656e8fb4d0000595e57ff15485041005f8bc35bc3";
pub(crate) fn source(getter: &[u8], required: &[u8]) -> Result<String, String> {
    emit_source(getter, required, false, false, true)
}
pub(crate) fn dynamic_source(getter: &[u8], required: &[u8]) -> Result<String, String> {
    emit_source(getter, required, true, false, true)
}
pub(crate) const CALLOC_THUNK: &str = "8bff558bec5de995040000";
pub(crate) const FREE_THUNK: &str = "e9fb050000";
pub(crate) fn lazy_source(getter: &[u8], required: &[u8], setter: &[u8]) -> Result<String, String> {
    lazy_source_mode(getter, required, setter, true)
}
pub(crate) fn lazy_extension_source() -> Result<String, String> {
    Ok(lazy_source_mode(
        &crate::crt_ptd::raw(GETTER),
        &crate::crt_ptd::raw(REQUIRED),
        &crate::crt_ptd::raw(crate::crt_cxx_lookup::SETTER),
        false,
    )?
    .replace("cxx_ptd_required(", "cxx_lazy_ptd_required(")
    .replace("cxx_ptd_get(", "cxx_lazy_ptd_get("))
}
fn lazy_source_mode(
    getter: &[u8],
    required: &[u8],
    setter: &[u8],
    dependencies: bool,
) -> Result<String, String> {
    let mut out = emit_source(getter, required, true, true, dependencies)?;
    out.push_str(&crate::crt_cxx_lookup::setter_source(
        setter,
        &crate::crt_ptd::raw(crate::crt_cxx_lookup::INDIRECT_GUARD),
    )?);
    for (bytes, origin, end, target, name) in [
        (
            CALLOC_THUNK,
            0x407850,
            0x40785b,
            0x407cf0,
            "cxx_ptd_allocate",
        ),
        (FREE_THUNK, 0x407750, 0x407755, 0x407d50, "cxx_ptd_free"),
    ] {
        let raw = crate::crt_ptd::raw(bytes);
        let mut nodes = BTreeMap::new();
        let mut decoder =
            iced_x86::Decoder::with_ip(32, &raw, u64::from(origin), iced_x86::DecoderOptions::NONE);
        while decoder.can_decode() {
            let i = decoder.decode();
            let at = (i.ip32() - origin) as usize;
            nodes.insert(
                i.ip32(),
                Graph::decode_instruction(&raw[at..at + i.len()], i.ip32())?,
            );
        }
        let graph = Graph { origin, end, nodes };
        let body = crate::crt_stream_emit::emit_body_with_exit(
            &graph,
            |_, _| Err("PTD allocation thunk call".into()),
            &BTreeMap::new(),
            32,
            |_, _| Err("PTD allocation thunk thread effect".into()),
            |_, _| Ok(String::new()),
            |_, _| Err("PTD allocation thunk unexpected RET".into()),
            Some(target),
        )?;
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,allocation:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,u32)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{let _=(||->Result<CrtValue,&'static str>{{{body}}})()?;allocation(rt,cpu,{target})}}"));
    }
    Ok(out)
}
fn emit_source(
    getter: &[u8],
    required: &[u8],
    dynamic: bool,
    lazy: bool,
    dependencies: bool,
) -> Result<String, String> {
    let parameters = if lazy {
        "access:CrtResolverAccess,fiber:CrtFiber,slot:CrtFlsSlot,api:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,u32)->Result<CrtValue,&'static str>,set_result:&mut impl FnMut(&mut CrtStreamRuntime,u32,CrtValue)->Result<(u32,Option<u32>),&'static str>,allocation:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,u32)->Result<CrtValue,&'static str>"
    } else if dynamic {
        "access:CrtResolverAccess,fiber:CrtFiber,slot:CrtFlsSlot,api:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,u32)->Result<CrtValue,&'static str>"
    } else {
        "lookup:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>"
    };
    let arguments = if lazy {
        "access,fiber,slot,api,set_result,allocation"
    } else if dynamic {
        "access,fiber,slot,api"
    } else {
        "lookup"
    };
    let lookup_arguments = if dynamic {
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
 Target::Direct(0x402bb4)=>format!("cpu.call_activation(rt,{next},0,|rt,child|{lookup}(rt,child,{lookup_arguments}))?;"),
 Target::Direct(0x402bef) if lazy=>format!("cpu.call_activation(rt,{next},0,|rt,child|cxx_dynamic_setter(rt,child,access,fiber,slot,api,set_result))?;"),
 Target::Direct(0x407850) if lazy=>format!("let sp=CrtCpu::pointer(cpu.r[4])?;if rt.load(sp,32)?.known_scalar()?!=1||rt.load(rt.offset(sp,4)?,32)?.known_scalar()?!=40{{return Err(\"C++ PTD allocation argument domain\");}}let ticket=rt.begin_heap_ptd_allocation(fiber,slot)?;let value=cpu.call_activation(rt,{next},0,|rt,child|cxx_ptd_allocate(rt,child,allocation))?;match value{{CrtValue::Pointer(p)=>rt.bind_heap_ptd_return(ticket,p)?,CrtValue::Scalar{{bits:0,known:u32::MAX}}=>{{}},_=>return Err(\"C++ PTD allocator result authority\")}}"),
 Target::Direct(0x407750) if lazy=>format!("let sp=CrtCpu::pointer(cpu.r[4])?;let value=rt.load(sp,32)?;match value{{CrtValue::Pointer(p)=>rt.heap_ptd_view(p,slot)?,CrtValue::Scalar{{bits:0,known:u32::MAX}}=>{{}},_=>return Err(\"C++ PTD free argument authority\")}}let before=rt.serial;cpu.call_activation(rt,{next},0,|rt,child|cxx_ptd_free(rt,child,allocation))?;if let CrtValue::Pointer(p)=value{{rt.take_ptd_free_completion(p,before)?;}}"),
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
            Ok(Some(
                "let p=CrtCpu::pointer(cpu.r[0])?;rt.dispatcher_ptd(p)?;return cpu.finish(rt);"
                    .into(),
            ))
        },
        Some(0x4077ff),
    )?;
    out.push_str(&format!("fn cxx_ptd_required(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,{parameters})->Result<CrtValue,&'static str>{{{entry}let value=(||->Result<CrtValue,&'static str>{{{body}}})()?;if cpu.returned{{return Ok(value);}}Err(\"C++ required PTD termination effect unbound\")}}"));
    if dynamic && dependencies {
        out.push_str(&crate::crt_cxx_lookup::cold_source(
            &crate::crt_ptd::raw(crate::crt_cxx_lookup::COLD_FULL),
            &crate::crt_ptd::raw(crate::crt_cxx_lookup::LOAD_HELPER),
        )?);
        out.push_str(&crate::crt_cxx_lookup::dynamic_source(
            &crate::crt_ptd::raw(crate::crt_cxx_lookup::WRAPPER),
            &crate::crt_ptd::raw(crate::crt_cxx_lookup::INDIRECT_GUARD),
        )?);
    } else if !dynamic && dependencies {
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

#[test]
fn allocated_dispatcher_ptd_cannot_gain_fls_role_by_retagging_or_copying() {
    crate::crt_stream_callees_tests::native(
        "",
        r#"
let mut rt=CrtStreamRuntime::new(17,29,0x8000,65536).unwrap();
let fiber=rt.bind_fiber(29).unwrap();let slot=rt.bind_fls(fiber,7,CrtValue::scalar(0)).unwrap();
let allocated=rt.allocate(40,true,true).unwrap().expect("actual zeroed allocation");
assert_eq!(allocated.kind,CrtRegionKind::Buffer);
assert_eq!(rt.load(rt.offset(allocated,32).unwrap(),32).unwrap(),CrtValue::scalar(0));
let old=rt.fls.clone();rt.last_os_error=Some(313);
assert_eq!(rt.fls_set(fiber,slot,7,CrtValue::Pointer(allocated),true,None),Err("CRT FLS PTD root/extent"));
assert_eq!(rt.fls,old);assert_eq!(rt.last_os_error,Some(313));
let retagged=CrtPointer{kind:CrtRegionKind::ThreadData,..allocated};
assert_eq!(rt.fls_set(fiber,slot,7,CrtValue::Pointer(retagged),true,None),Err("CRT pointer complete range/identity"));
assert_eq!(rt.fls,old);assert_eq!(rt.last_os_error,Some(313));
// Copying contents produces a different allocation, not an alias or receipt
// transferring the original heap object's role or lifetime.
let copied=rt.map_region(0x7000,40,CrtRegionKind::ThreadData,Some(&[0;40])).unwrap();
assert_ne!(copied.cap,allocated.cap);
assert_eq!(rt.difference(allocated,copied),Err("CRT unrelated pointer subtraction"));
rt.free_allocation(allocated).unwrap();
assert_eq!(rt.fls_set(fiber,slot,7,CrtValue::Pointer(allocated),true,None),Err("CRT stale/foreign pointer"));
assert_eq!(rt.fls,old);assert_eq!(rt.last_os_error,Some(313));
assert_eq!(rt.load(rt.offset(copied,32).unwrap(),32).unwrap(),CrtValue::scalar(0));
// Existing explicit-input ThreadData and sentinel paths still work; they do
// not establish an allocator-to-PTD conversion for the original guest object.
assert_eq!(rt.fls_set(fiber,slot,7,CrtValue::Pointer(copied),true,None),Ok(true));
assert_eq!(rt.fls_get(fiber,slot,7).unwrap(),CrtValue::Pointer(copied));
assert_eq!(rt.fls_set(fiber,slot,7,CrtValue::scalar(u32::MAX),true,None),Ok(true));
assert_eq!(rt.fls_get(fiber,slot,7).unwrap(),CrtValue::scalar(u32::MAX));
"#,
        "dispatcher-ptd-allocation-role",
    );
}

#[test]
fn heap_ptd_views_preserve_aliases_and_expire_with_allocation_or_slot() {
    crate::crt_stream_callees_tests::native(
        "",
        r#"
for mode in 0..17 {
 let mut rt=CrtStreamRuntime::new(17,29,0x8000,65536).unwrap();
 let fiber=rt.bind_fiber(29).unwrap();let slot=rt.bind_fls(fiber,7,CrtValue::scalar(u32::MAX)).unwrap();
 let ticket=rt.begin_heap_ptd_allocation(fiber,slot).unwrap();
 let p=rt.allocate(if mode==1{39}else{40},mode!=2,true).unwrap().unwrap();let alias=rt.offset(p,32).unwrap();
 let ticket=if mode==3{rt.begin_heap_ptd_allocation(fiber,slot).unwrap()}else{ticket};
 if mode==4{rt.fls_set(fiber,slot,7,CrtValue::scalar(0),true,None).unwrap();}
 if mode==5{rt.store(alias,32,CrtValue::scalar(1)).unwrap();}
 if mode==13{rt.retire_fls(fiber,slot).unwrap();rt.bind_fls(fiber,7,CrtValue::scalar(u32::MAX)).unwrap();assert_eq!(rt.bind_heap_ptd_return(ticket,p),Err("CRT PTD allocation slot lifetime"));assert!(rt.heap_ptds.is_empty());continue;}
 if mode==14{let mut other=CrtStreamRuntime::new(17,29,0x8000,65536).unwrap();let f=other.bind_fiber(29).unwrap();let s=other.bind_fls(f,7,CrtValue::scalar(u32::MAX)).unwrap();let foreign=other.begin_heap_ptd_allocation(f,s).unwrap();assert_eq!(rt.bind_heap_ptd_return(foreign,p),Err("CRT PTD allocation foreign ticket"));assert!(rt.heap_ptds.is_empty());continue;}
 if mode==15{rt.free_allocation(p).unwrap();assert_eq!(rt.bind_heap_ptd_return(ticket,p),Err("CRT stale/foreign pointer"));assert!(rt.heap_ptds.is_empty());continue;}
 if mode==16{rt.retire_fls(fiber,slot).unwrap();rt.retire_fiber(fiber).unwrap();let next=rt.bind_fiber(29).unwrap();rt.bind_fls(next,7,CrtValue::scalar(u32::MAX)).unwrap();assert_eq!(rt.bind_heap_ptd_return(ticket,p),Err("CRT fiber identity/lifetime"));assert!(rt.heap_ptds.is_empty());continue;}
 let result=rt.bind_heap_ptd_return(ticket,p);
 if (1..=5).contains(&mode){assert_eq!(result,Err(match mode{1=>"CRT pointer complete range/identity",2|5=>"CRT PTD allocation zero initialization",3=>"CRT PTD allocation fresh root/role",4=>"CRT PTD allocation missing sentinel",_=>unreachable!()}),"mode {mode}");assert!(rt.heap_ptds.is_empty());continue;}
 result.unwrap();assert_eq!(p.kind,CrtRegionKind::Buffer);assert_eq!(rt.regions.iter().find(|r|r.pointer.cap==p.cap).unwrap().pointer,p);
 assert_eq!(rt.load(alias,32).unwrap(),CrtValue::scalar(0));assert!(rt.dispatcher_ptd(p).is_err());
 let duplicate=rt.begin_heap_ptd_allocation(fiber,slot).unwrap();assert_eq!(rt.bind_heap_ptd_return(duplicate,p),Err("CRT PTD allocation fresh root/role"));
 assert_eq!(rt.claim_file_buffer(p,0x8000),Err("CRT cross-FILE buffer ownership"));
 let other=rt.bind_fls(fiber,8,CrtValue::scalar(0)).unwrap();
 assert_eq!(rt.fls_set(fiber,other,8,CrtValue::Pointer(p),true,None),Err("CRT PTD view owner/slot/lifetime"));
 rt.fls_set(fiber,slot,7,CrtValue::Pointer(p),true,None).unwrap();rt.dispatcher_ptd(p).unwrap();
 rt.store(alias,32,CrtValue::scalar(123)).unwrap();assert_eq!(rt.load(rt.offset(p,32).unwrap(),32).unwrap(),CrtValue::scalar(123));
 match mode {
  6=>{rt.free_allocation(p).unwrap();assert_eq!(rt.fls_get(fiber,slot,7),Err("CRT stale/foreign pointer"));assert!(rt.heap_ptds.is_empty());},
  7=>{rt.retire_fls(fiber,slot).unwrap();assert!(rt.dispatcher_ptd(p).is_err());assert_eq!(rt.load(alias,32).unwrap(),CrtValue::scalar(123));let new=rt.bind_fls(fiber,7,CrtValue::scalar(0)).unwrap();assert_ne!(slot,new);assert!(rt.fls_set(fiber,new,7,CrtValue::Pointer(p),true,None).is_err());},
  8=>{rt.fls_set(fiber,slot,7,CrtValue::Pointer(p),false,Some(8)).unwrap();assert!(rt.fls_get(fiber,slot,7).is_err());assert!(rt.dispatcher_ptd(p).is_err());assert_eq!(rt.load(alias,32).unwrap(),CrtValue::scalar(123));},
  9=>{let mut foreign=CrtStreamRuntime::new(17,29,0x8000,65536).unwrap();let f=foreign.bind_fiber(29).unwrap();let s=foreign.bind_fls(f,7,CrtValue::scalar(u32::MAX)).unwrap();let ticket=foreign.begin_heap_ptd_allocation(f,s).unwrap();assert!(foreign.bind_heap_ptd_return(ticket,p).is_err());},
  10=>{rt.retire_fls(fiber,slot).unwrap();rt.retire_fls(fiber,other).unwrap();rt.retire_fiber(fiber).unwrap();let new=rt.bind_fiber(29).unwrap();assert_ne!(new,fiber);assert!(rt.heap_ptd_view(p,slot).is_err());},
  11=>{let q=CrtPointer{kind:CrtRegionKind::ThreadData,..p};assert_eq!(rt.dispatcher_ptd(q),Err("CRT pointer complete range/identity"));},
  12=>{rt.store(alias,32,CrtValue::Scalar{bits:0,known:0}).unwrap();rt.dispatcher_ptd(p).unwrap();assert!(rt.load(alias,32).unwrap().known_scalar().is_err());},
  _=>{assert_eq!(rt.fls_get(fiber,slot,7).unwrap(),CrtValue::Pointer(p));}
 }
}
"#,
        "heap-ptd-view",
    );
}

#[test]
fn original_lazy_ptd_setter_publication_and_cleanup_preserve_heap_identity() {
    let mut extra = lazy_source(
        &crate::crt_ptd::raw(GETTER),
        &crate::crt_ptd::raw(REQUIRED),
        &crate::crt_ptd::raw(crate::crt_cxx_lookup::SETTER),
    )
    .unwrap();
    extra.push_str(&crate::crt_standard_handles_tests::allocator_source_with_errno(None));
    extra.push_str(&crate::crt_heap_free::fixture_source());
    if let Some(out) = std::env::var_os("W2L_EH4_EVIDENCE") {
        std::fs::write(
            std::path::Path::new(&out).join("lazy-ptd-component.rs"),
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
for mode in 0..20 {
 let(mut rt,init)=CrtStreamRuntime::new_initializing(17,29,0x8000,65536).unwrap();
 rt.map_region(0x41c060,4,CrtRegionKind::Module,Some(&7u32.to_le_bytes())).unwrap();
 let(module,reference)=rt.module_acquire_result(init,"independent runtime backend",0x710000).unwrap();
 let get=rt.module_export_result(init,module,"FlsGetValue",0x711000).unwrap();let set=rt.module_export_result(init,module,if mode==12{"WrongSetter"}else{"FlsSetValue"},0x712000).unwrap();
 let cache=rt.map_region(0x41cd14,16,CrtRegionKind::Module,Some(&[0;16])).unwrap();rt.store(rt.offset(cache,8).unwrap(),32,CrtValue::Function(get)).unwrap();rt.store(rt.offset(cache,12).unwrap(),32,CrtValue::Function(set)).unwrap();
 let guard=rt.map_region(0x415128,4,CrtRegionKind::Module,Some(&0x401bf9u32.to_le_bytes())).unwrap();
 rt.map_region(0x415d4c,8,CrtRegionKind::Input,Some(&[0,0,0,0,2,0,0,0])).unwrap();rt.map_region(0x415d54,12,CrtRegionKind::Input,Some(b"FlsGetValue\0")).unwrap();
 rt.map_region(0x415d60,8,CrtRegionKind::Input,Some(&[0,0,0,0,2,0,0,0])).unwrap();rt.map_region(0x415d68,12,CrtRegionKind::Input,Some(b"FlsSetValue\0")).unwrap();
 let fiber=rt.bind_fiber(29).unwrap();let slot=rt.bind_fls(fiber,7,CrtValue::scalar(0)).unwrap();
 let preexisting=rt.allocate(40,true,true).unwrap().unwrap();
 let heapcell=rt.map_region(0x41d2c8,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes())).unwrap();
 rt.map_region(0x41ce80,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes())).unwrap();
 let errno=rt.map_region(0x7000,4,CrtRegionKind::Context,Some(&0u32.to_le_bytes())).unwrap();
 let error_ptd=rt.map_region(0x7100,32,CrtRegionKind::ThreadData,None).unwrap();let error_cell=rt.offset(error_ptd,16).unwrap();rt.store(error_cell,32,CrtValue::scalar(73)).unwrap();
 let stack=rt.map_region(0x9000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,3072).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();
 cpu.call_activation(&mut rt,0x1110,0,|rt,c|heap_producer(rt,c,init,true,Some(false),(1,1),false,errno,&mut vec![],&mut|_,_|panic!("heap producer new handler"))).unwrap();
 assert!(matches!(rt.load(heapcell,32).unwrap(),CrtValue::Heap(_)));let saved=cpu.r;
 rt.last_os_error=Some(55);let setters=std::cell::RefCell::new(vec![]);let effects=std::cell::RefCell::new(vec![]);let issued=std::cell::Cell::new(None);
 let result=cxx_ptd_get(&mut rt,&mut cpu,CrtResolverAccess::Cached,fiber,slot,&mut |_,_,_|panic!("cached path called loader"),&mut |rt,index,value|{
  assert_eq!(index,7);let n=setters.borrow().len();setters.borrow_mut().push(value);effects.borrow_mut().push("setter");
  if mode==10&&n==1{rt.retire_fls(fiber,slot)?;return Ok((1,None));}
  if mode==11&&n==1{rt.module_release_result(init,reference,true)?;return Ok((1,None));}
  if mode==14&&n==1{rt.store(rt.offset(issued.get().unwrap(),32)?,32,CrtValue::scalar(9))?;return Err("independent setter failure after write");}
  Ok((if mode==1&&n==0||(matches!(mode,2|3|7|13)||mode>=15)&&n==1||mode==3&&n==2{0}else{7},Some(101+n as u32)))
 },&mut |rt,c,target|{
  let sp=CrtCpu::pointer(c.r[4])?;let a=rt.load(rt.offset(sp,4)?,32)?;
  if target==0x407cf0{
   effects.borrow_mut().push("allocate");assert_eq!(a,CrtValue::scalar(1));assert_eq!(rt.load(rt.offset(sp,8)?,32)?,CrtValue::scalar(40));
   let p=if mode==5{Some(preexisting)}else if mode==6||mode==8{rt.allocate(if mode==6{39}else{40},mode!=8,true)?}else{
    let value=calloc_original(rt,c,init,true,Some(false),if mode==4{(0,usize::MAX)}else{(1,1)},false,errno,&mut vec![],&mut|_,_|Err("unexpected new handler"))?;
    let p=match value{CrtValue::Pointer(p)=>Some(p),CrtValue::Scalar{bits:0,known:u32::MAX}=>None,_=>panic!("calloc value")};issued.set(p);
    if mode==9{rt.store(guard,32,CrtValue::scalar(0x401bfa))?;}return Ok(value);
   };issued.set(p);
   if mode==9{rt.store(guard,32,CrtValue::scalar(0x401bfa))?;}
   c.clobber(p.map(CrtValue::Pointer).unwrap_or(CrtValue::scalar(0)));c.finish(rt)
  }else{assert_eq!(target,0x407d50);effects.borrow_mut().push("free");
   if mode==7{return Err("independent free failure");}
   if mode>=15{return original_free(rt,c,&mut|_,_,_,_|Ok((0,if mode==17{None}else{Some(if mode==16{87}else{5})})),&mut|rt,child|{
    if mode==18{rt.store(error_cell,32,CrtValue::scalar(74))?;return Err("independent cleanup errno failure");}
    if mode==19{rt.retire_region(error_ptd)?;}
    child.clobber(CrtValue::Pointer(error_ptd));child.finish(rt)
   });}

   if let CrtValue::Pointer(p)=a{if mode!=13{rt.free_allocation(p)?;}}else{assert_eq!(a,CrtValue::scalar(0));}
   c.clobber(CrtValue::Scalar{bits:0,known:0});c.finish(rt)
  }
 });
 if matches!(mode,0..=4|15|16){assert_eq!(rt.last_os_error,Some(55),"mode {mode}");}
 match mode {
  0=>{let p=issued.get().unwrap();assert_eq!(result.unwrap(),CrtValue::Pointer(p));rt.dispatcher_ptd(p).unwrap();assert_eq!(p.kind,CrtRegionKind::Buffer);assert_eq!(rt.load(rt.offset(p,32).unwrap(),32).unwrap(),CrtValue::scalar(0));assert_eq!(&*effects.borrow(),&["setter","allocate","setter","free"]);},
  1=>{assert_eq!(result.unwrap(),CrtValue::scalar(0));assert_eq!(&*effects.borrow(),&["setter"]);assert!(rt.fls_get(fiber,slot,7).is_err());},
  2|3=>{assert_eq!(result.unwrap(),CrtValue::scalar(0));assert!(rt.valid(issued.get().unwrap(),0).is_err());assert!(rt.heap_ptds.is_empty());assert_eq!(&*effects.borrow(),&["setter","allocate","setter","setter","free"]);if mode==2{assert_eq!(rt.fls_get(fiber,slot,7).unwrap(),CrtValue::scalar(0));}else{assert!(rt.fls_get(fiber,slot,7).is_err());}},
  4=>{assert_eq!(result.unwrap(),CrtValue::scalar(0));assert_eq!(&*effects.borrow(),&["setter","allocate","setter","free"]);},
  5|6|8=>{assert_eq!(result,Err(match mode{5=>"CRT PTD allocation fresh root/role",6=>"CRT pointer complete range/identity",8=>"CRT PTD allocation zero initialization",_=>unreachable!()}),"mode {mode}");assert_eq!(setters.borrow().len(),1);assert!(rt.heap_ptds.is_empty());},
  7=>{assert_eq!(result,Err("independent free failure"));assert!(rt.valid(issued.get().unwrap(),40).is_ok());assert_eq!(rt.fls_get(fiber,slot,7).unwrap(),CrtValue::scalar(0));},
  9=>{assert_eq!(result,Err("C++ live guard target unbound"));assert_eq!(setters.borrow().len(),1);},
  10|11=>{assert_eq!(result,Err(if mode==10{"CRT FLS setter owner/index/lifetime"}else{"CRT unloaded module"}));assert!(rt.valid(issued.get().unwrap(),40).is_ok());},
  12=>{assert_eq!(result,Err("CRT export owner/symbol"));assert!(setters.borrow().is_empty());},
  13=>{assert_eq!(result,Err("C++ PTD free effect missing"));assert!(rt.valid(issued.get().unwrap(),40).is_ok());},
  14=>{assert_eq!(result,Err("independent setter failure after write"));assert_eq!(rt.load(rt.offset(issued.get().unwrap(),32).unwrap(),32).unwrap(),CrtValue::scalar(9));},
  15|16=>{assert_eq!(result.unwrap(),CrtValue::scalar(0));let p=issued.get().unwrap();assert_eq!(rt.uncertain_allocations,[p]);assert!(rt.memory.validate(p.cap,p.owner).is_ok());assert!(rt.valid(p,0).is_err());assert!(rt.heap_ptds.is_empty());assert!(rt.completed_failed_frees.is_empty());assert_eq!(rt.errno,Some(if mode==16{22}else{13}));assert_eq!(rt.load(error_cell,32).unwrap(),CrtValue::scalar(if mode==16{22}else{13}));assert_eq!(&*effects.borrow(),&["setter","allocate","setter","setter","free"]);assert_eq!(rt.fls_get(fiber,slot,7).unwrap(),CrtValue::scalar(0));},
  17|18|19=>{assert_eq!(result,Err(match mode{17=>"CRT scalar knowledge/type",18=>"independent cleanup errno failure",19=>"CRT stale/foreign pointer",_=>unreachable!()}));assert_eq!(rt.uncertain_allocations,[issued.get().unwrap()]);assert!(rt.completed_failed_frees.is_empty());assert_eq!(rt.last_os_error,if mode==17{None}else{Some(5)});if mode==18{assert_eq!(rt.load(error_cell,32).unwrap(),CrtValue::scalar(74));}},
  _=>unreachable!()
 }
 if matches!(mode,0..=4|15|16){assert!(cpu.returned);for r in [3,5,6,7]{assert_eq!(cpu.r[r],saved[r]);}assert!(cxx_ptd_get(&mut rt,&mut cpu,CrtResolverAccess::Cached,fiber,slot,&mut|_,_,_|panic!(),&mut|_,_,_|panic!(),&mut|_,_,_|panic!()).is_err());}else{assert!(!cpu.returned);}
 assert!(rt.valid(preexisting,40).is_ok());
}
"#,
        "lazy-ptd-publication",
    );
    let original = crate::crt_ptd::raw(crate::crt_cxx_lookup::SETTER);
    for i in 0..original.len() {
        let mut changed = original.clone();
        changed[i] ^= 1;
        assert!(lazy_source(
            &crate::crt_ptd::raw(GETTER),
            &crate::crt_ptd::raw(REQUIRED),
            &changed
        )
        .is_err());
    }
}
