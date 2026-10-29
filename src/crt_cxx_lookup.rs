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

pub(crate) const COLD_FULL:&str="558bec51518b4508578d048514cd41008945f88b009083cfff3bc7750433c0eb5685c07552538b5d1056eb3d8b0b894dfc8d048d08cd41008b309085f674063bf77546eb21ff348d805c4100e84f0000008b55fc8bf0598d0c9508cd410085f675188bc7870183c3043b5d1475be8b55f8873a33c05e5b5fc9c38bc6870185c0740756ff156c504100ff750c56ff157050410085c074d78b55f88bc8870aebd5";
pub(crate) const LOAD_HELPER:&str="558bec68000800006a00ff7508ff157450410085c07532ff154450410083f85775256a0768185d4100ff7508e8bc4d000083c40c85c0740f6a006a00ff7508ff15745041005dc333c05dc3";

#[test]
fn cold_resolution_has_atomic_publication_and_owned_loader_dependencies() {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
    let bytes = crate::crt_ptd::raw(COLD_FULL);
    let mut d = Decoder::with_ip(32, &bytes, 0x402a53, DecoderOptions::NONE);
    let mut exchanges = Vec::new();
    let mut imports = Vec::new();
    while d.can_decode() {
        let i = d.decode();
        assert!(!i.is_invalid());
        if i.mnemonic() == Mnemonic::Xchg {
            assert_eq!(i.op0_kind(), OpKind::Memory);
            assert_eq!(i.op1_kind(), OpKind::Register);
            exchanges.push(i.ip32());
            let a = (i.ip32() - 0x402a53) as usize;
            assert!(matches!(
                Graph::decode_instruction(&bytes[a..a + i.len()], i.ip32())
                    .unwrap()
                    .op,
                crate::crt_stream_ir::Op::Exchange { .. }
            ));
        }
        if i.mnemonic() == Mnemonic::Call && i.op0_kind() == OpKind::Memory {
            imports.push(i.memory_displacement32());
        }
    }
    assert_eq!(exchanges, [0x402ab7, 0x402ac4, 0x402acf, 0x402aef]);
    assert_eq!(imports, [0x41506c, 0x415070]);
    let load = crate::crt_ptd::raw(LOAD_HELPER);
    let graph = Graph::decode(&load, 0x402af3).unwrap();
    let calls: Vec<_> = graph
        .nodes
        .values()
        .filter_map(|n| {
            if let crate::crt_stream_ir::Op::Call(t) = n.op {
                Some(t)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        calls,
        [
            Target::Import(0x415074),
            Target::Import(0x415044),
            Target::Direct(0x4078e0),
            Target::Import(0x415074)
        ]
    );
}

/// Mechanically execute the complete resolver and load helper under an explicit
/// startup-exclusive component domain. Loader API effects remain a checked cut;
/// the error-87 comparison/retry path is rejected until its helper is lifted.
pub(crate) fn cold_source(resolver: &[u8], load: &[u8]) -> Result<String, String> {
    if resolver != crate::crt_ptd::raw(COLD_FULL) || load != crate::crt_ptd::raw(LOAD_HELPER) {
        return Err("C++ cold original code binding".into());
    }
    let mut out = String::new();
    for (bytes, origin, name) in [
        (resolver, 0x402a53, "cxx_cold_resolver"),
        (load, 0x402af3, "cxx_load_helper"),
    ] {
        let graph = Graph::decode(bytes, origin)?;
        let roles = BTreeMap::from([
            (0x41cd14, "CrtRegionKind::Module".into()),
            (0x41cd08, "CrtRegionKind::Module".into()),
            (0x415c80, "CrtRegionKind::Module".into()),
        ]);
        let body = crate::crt_stream_emit::emit_body_with_exit(
            &graph,
            |pc, target| {
                let next = pc + graph.nodes[&pc].length;
                Ok(match target {
                Target::Direct(0x402af3)=>format!("cpu.call_activation(rt,{next},0,|rt,child|cxx_load_helper(rt,child,init,api))?;"),
                Target::Import(0x415044)=>format!("cpu.call_activation(rt,{next},0,|rt,child|{{child.clobber(rt.last_os_error.map(CrtValue::scalar).unwrap_or(CrtValue::Scalar{{bits:0,known:0}}));child.finish(rt)}})?;"),
                Target::Import(iat @ (0x415074|0x415070|0x41506c))=>{
                    let pop=match iat{0x415074=>12,0x415070=>8,_=>4};
                    format!("cpu.call_activation(rt,{next},{pop},|rt,child|cxx_loader_effect(rt,child,init,{iat},api))?;")
                },
                _=>"return Err(\"C++ cold prefix comparator/loader effect unbound\");".into()
            })
            },
            &roles,
            4096,
            |_, _| Err("C++ cold thread effect".into()),
            |pc, _| {
                Ok(match pc{
            0x402a68=>"match cpu.r[0]{CrtValue::Function(f)=>rt.function_identity(f,None)?,CrtValue::Scalar{bits:0|u32::MAX,known:u32::MAX}=>{},_=>return Err(\"C++ function cache authority\")}".into(),
            0x402a8d=>"match cpu.r[6]{CrtValue::Module(m)=>rt.module_identity(m)?,CrtValue::Scalar{bits:0|u32::MAX,known:u32::MAX}=>{},_=>return Err(\"C++ module cache authority\")}".into(),
            _=>String::new()
        })
            },
            |_, pop| {
                if pop != 0 {
                    return Err("C++ cold RET convention".into());
                }
                Ok(None)
            },
            None,
        )?;
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,api:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,u32)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{rt.initialization(init)?;{body}}}"));
    }
    out.push_str(r#"
fn cxx_loader_effect(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,iat:u32,api:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,u32)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{
 rt.initialization(init)?;let sp=CrtCpu::pointer(cpu.r[4])?;
 let arg=rt.load(rt.offset(sp,4)?,32)?;
 let symbol=if iat==0x415070{
  let CrtValue::Module(module)=arg else{return Err("C++ GetProcAddress module authority");};rt.module_identity(module)?;
  let p=CrtCpu::pointer(rt.load(rt.offset(sp,8)?,32)?)?;let mut bytes=Vec::new();let mut ended=false;
  for i in 0..256{let b=rt.load(rt.offset(p,i)?,8)?.known_scalar()? as u8;if b==0{ended=true;break;}bytes.push(b);}
  if !ended||bytes.is_empty()||!bytes.is_ascii(){return Err("C++ named export bounds/encoding");}Some((module,String::from_utf8(bytes).map_err(|_|"C++ export encoding")?))
 }else{None};
 if iat==0x415074{
  let p=CrtCpu::pointer(arg)?;let mut units=Vec::new();let mut ended=false;
  for i in 0..260{let u=rt.load(rt.offset(p,i*2)?,16)?.known_scalar()? as u16;if u==0{ended=true;break;}units.push(u);}
  if !ended||units.is_empty()||String::from_utf16(&units).is_err(){return Err("C++ module name bounds/encoding");}
  if rt.load(rt.offset(sp,8)?,32)?.known_scalar()?!=0||!matches!(rt.load(rt.offset(sp,12)?,32)?.known_scalar()?,0|0x800){return Err("C++ executable loader flags/reserved argument");}
 }
 if iat==0x41506c{let CrtValue::Module(m)=arg else{return Err("C++ FreeLibrary module authority");};rt.module_identity(m)?;}
 let references=rt.module_references.clone();
 let result=api(rt,cpu,iat)?;rt.initialization(init)?;
 let added:Vec<_>=rt.module_references.iter().filter(|(id,_)|!references.contains_key(id)).map(|(_,r)|*r).collect();
 let removed:Vec<_>=references.iter().filter(|(id,_)|!rt.module_references.contains_key(id)).map(|(_,r)|*r).collect();
 if iat==0x415074 {match result{
  CrtValue::Module(m) if added.len()==1&&added[0].module==m&&removed.is_empty()=>{},
  CrtValue::Scalar{bits:0,known:u32::MAX} if added.is_empty()&&removed.is_empty()=>{},
  _=>return Err("C++ load acquisition receipt mismatch")
 }}else if iat==0x41506c{
  let CrtValue::Module(m)=arg else{unreachable!()};
  if result.known_scalar()?==0{return Err("C++ release failure effects unclosed");}
  if !added.is_empty()||removed.len()!=1||removed[0].module!=m{return Err("C++ release receipt mismatch");}
 }else if !added.is_empty()||!removed.is_empty(){return Err("C++ export lookup changed references");}
 match iat{
  0x415074=>match result{CrtValue::Module(m)=>rt.module_identity(m)?,CrtValue::Scalar{bits:0,known:u32::MAX}=>{},_=>return Err("C++ loader result authority")},
  0x415070=>{let(module,name)=symbol.unwrap();rt.module_identity(module)?;match result{CrtValue::Function(f) if f.module==module=>rt.function_identity(f,Some(&name))?,CrtValue::Scalar{bits:0,known:u32::MAX}=>{},_=>return Err("C++ export result authority")}},
  0x41506c=>{result.known_scalar()?;},_=>return Err("C++ unknown loader import")
 }Ok(result)
}
"#);
    Ok(out)
}

#[test]
fn cold_original_execution_preserves_module_export_and_publication_authority() {
    let resolver = crate::crt_ptd::raw(COLD_FULL);
    let helper = crate::crt_ptd::raw(LOAD_HELPER);
    let extra = cold_source(&resolver, &helper).unwrap();
    if let Some(out) = std::env::var_os("W2L_EH4_EVIDENCE") {
        let source = format!(
            "{}\n{}\n{}",
            crate::crt_stream_runtime::EMITTED_TYPES,
            crate::crt_stream_cpu::EMITTED_TYPES,
            extra
        );
        std::fs::write(
            std::path::Path::new(&out).join("cold-resolver-component.rs"),
            source,
        )
        .unwrap();
    }
    let body = r#"
for scenario in 0..13 {
 let(mut rt,init)=CrtStreamRuntime::new_initializing(11,29,0x8000,65536).unwrap();
 let cache=rt.map_region(0x41cd08,20,CrtRegionKind::Module,Some(&[0;20])).unwrap();
 let module_cell=cache;let function_cell=rt.offset(cache,12).unwrap();
 rt.bind_loader_cell(init,module_cell,false).unwrap();rt.bind_loader_cell(init,function_cell,true).unwrap();
 let list=rt.map_region(0x6000,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes())).unwrap();
 let name=rt.map_region(0x6100,14,CrtRegionKind::Input,Some(&[b'a',0,b'l',0,b'p',0,b'h',0,b'a',0,0,0,0,0])).unwrap();
 let symbol=rt.map_region(0x6200,12,CrtRegionKind::Input,Some(b"FlsGetValue\0")).unwrap();
 let names=rt.map_region(0x415c80,4,CrtRegionKind::Module,None).unwrap();rt.store(names,32,CrtValue::Pointer(name)).unwrap();
 let stack=rt.map_region(0x9000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,3072).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();
 let mut cpu=CrtCpu::new(sp,1).unwrap();cpu.r[1]=CrtValue::Scalar{bits:0,known:0};let end=rt.offset(list,4).unwrap();cpu.push(&mut rt,CrtValue::Pointer(end)).unwrap();cpu.push(&mut rt,CrtValue::Pointer(list)).unwrap();cpu.push(&mut rt,CrtValue::Pointer(symbol)).unwrap();cpu.push(&mut rt,CrtValue::scalar(0)).unwrap();
 let retained=if matches!(scenario,3|10|11){Some(rt.module_acquire_result(init,"independent alpha identity",0x700000).unwrap())}else{None};let mut acquisitions=Vec::new();let mut calls=Vec::new();
 let result=cpu.call_activation(&mut rt,0x1234,0,|rt,child|cxx_cold_resolver(rt,child,init,&mut |rt,cpu,iat|{
  calls.push(iat);let sp=CrtCpu::pointer(cpu.r[4])?;
  let value=match iat{
   0x415074=>{
    assert_eq!(rt.load(rt.offset(sp,4)?,32)?,CrtValue::Pointer(name));assert_eq!(rt.load(rt.offset(sp,8)?,32)?,CrtValue::scalar(0));assert_eq!(rt.load(rt.offset(sp,12)?,32)?,CrtValue::scalar(0x800));
    if scenario==10{CrtValue::Module(retained.unwrap().0)}else if scenario==1||scenario==2||scenario==9{rt.last_os_error=if scenario==9{None}else{Some(if scenario==2{87}else{126})};CrtValue::scalar(0)}else{
     let(m,r)=rt.module_acquire_result(init,"independent alpha identity",0x700000)?;acquisitions.push(r);
     if matches!(scenario,3|11){let (winner,_)=retained.unwrap();rt.store(module_cell,32,CrtValue::Module(winner))?;}
     if scenario==4{return Err("independent loader failure after acquisition");}
     if scenario==12{CrtValue::scalar(0)}else{CrtValue::Module(m)}
    }
   },
   0x41506c=>{assert!(matches!(scenario,3|11));if scenario==3{rt.module_release_result(init,acquisitions[0],true)?;}CrtValue::scalar(1)},
   0x415070=>{let CrtValue::Module(m)=rt.load(rt.offset(sp,4)?,32)? else {panic!()};assert_eq!(rt.load(rt.offset(sp,8)?,32)?,CrtValue::Pointer(symbol));
    match scenario{
     5=>CrtValue::scalar(0),
     6=>CrtValue::scalar(0x710000),
     7=>{let f=rt.module_export_result(init,m,"FlsGetValue",0x710000)?;for r in &acquisitions{rt.module_release_result(init,*r,true)?;}CrtValue::Function(f)},
     8=>CrtValue::Function(rt.module_export_result(init,m,"TlsGetValue",0x710000)?),
     _=>CrtValue::Function(rt.module_export_result(init,m,"FlsGetValue",0x710000)?)
    }
   },_=>panic!()
  };cpu.clobber(value);cpu.finish_pop(rt,match iat{0x415074=>12,0x415070=>8,_=>4})
 }));
 match scenario{
  0|3=>{let CrtValue::Function(f)=result.unwrap()else{panic!()};rt.function_identity(f,Some("FlsGetValue")).unwrap();assert_eq!(rt.load(function_cell,32).unwrap(),CrtValue::Function(f));assert_eq!(rt.module_references.len(),1);cpu.discard(&mut rt,16).unwrap();cpu.finish(&mut rt).unwrap();
   assert_eq!(calls,if scenario==3{vec![0x415074,0x41506c,0x415070]}else{vec![0x415074,0x415070]});
   rt.store(sp,32,CrtValue::ProtectedReturn(2)).unwrap();let mut cached=CrtCpu::new(sp,2).unwrap();cached.r[1]=CrtValue::Scalar{bits:0,known:0};let end=rt.offset(list,4).unwrap();cached.push(&mut rt,CrtValue::Pointer(end)).unwrap();cached.push(&mut rt,CrtValue::Pointer(list)).unwrap();cached.push(&mut rt,CrtValue::Pointer(symbol)).unwrap();cached.push(&mut rt,CrtValue::scalar(0)).unwrap();
   let hit=cached.call_activation(&mut rt,0x1234,0,|rt,child|cxx_cold_resolver(rt,child,init,&mut |_,_,_|panic!("cached hit invoked loader"))).unwrap();assert_eq!(hit,CrtValue::Function(f));cached.discard(&mut rt,16).unwrap();cached.finish(&mut rt).unwrap();
  },
  1=>{assert_eq!(result.unwrap(),CrtValue::scalar(0));assert_eq!(rt.load(module_cell,32).unwrap(),CrtValue::scalar(u32::MAX));assert_eq!(rt.load(function_cell,32).unwrap(),CrtValue::scalar(u32::MAX));},
  5=>{assert_eq!(result.unwrap(),CrtValue::scalar(0));assert_eq!(rt.load(function_cell,32).unwrap(),CrtValue::scalar(u32::MAX));assert_eq!(rt.module_references.len(),1);},
  _=>{assert!(result.is_err(),"scenario {scenario}");if scenario==4{assert_eq!(rt.module_references.len(),1);assert_eq!(rt.load(module_cell,32).unwrap(),CrtValue::scalar(0));}}
 }
}
"#;
    crate::crt_stream_callees_tests::native(&extra, body, "cold-owned-resolver");
    for (which, original) in [(0, resolver.clone()), (1, helper.clone())] {
        for index in 0..original.len() {
            let mut changed = original.clone();
            changed[index] ^= 1;
            let result = if which == 0 {
                cold_source(&changed, &helper)
            } else {
                cold_source(&resolver, &changed)
            };
            assert!(result.is_err(), "changed body {which} byte {index}");
        }
    }
}

#[test]
fn loader_authority_and_exchange_reject_stale_foreign_partial_and_unowned_state() {
    let graph = Graph::decode(&[0x87, 0x01, 0xc3], 0x1000).unwrap();
    let body = crate::crt_stream_emit::emit_body(
        &graph,
        |_, _| Err("no calls".into()),
        &BTreeMap::new(),
        3,
    )
    .unwrap();
    let extra=format!("fn exchange(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}");
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
let(mut rt,init)=CrtStreamRuntime::new_initializing(1,2,0x8000,65536).unwrap();
let cell=rt.map_region(0x5000,8,CrtRegionKind::Module,Some(&[0;8])).unwrap();let second=rt.offset(cell,4).unwrap();
assert!(rt.exchange_module_word(cell,CrtValue::scalar(u32::MAX)).is_err());
rt.bind_loader_cell(init,cell,false).unwrap();rt.bind_loader_cell(init,second,true).unwrap();assert!(rt.bind_loader_cell(init,cell,false).is_err());
let (module,first)=rt.module_acquire_result(init,"unrelated fixture one",0x550000).unwrap();let(same,second_ref)=rt.module_acquire_result(init,"unrelated fixture one",0x550000).unwrap();assert_eq!(module,same);assert_ne!(first,second_ref);
assert!(rt.module_acquire_result(init,"different identity",0x550000).is_err());
let function=rt.module_export_result(init,module,"OtherFunction",0x551000).unwrap();
assert!(rt.function_identity(function,Some("otherfunction")).is_err());
assert!(rt.exchange_module_word(cell,CrtValue::Function(function)).is_err());assert!(rt.exchange_module_word(second,CrtValue::Module(module)).is_err());
assert!(rt.exchange_module_word(cell,CrtValue::scalar(0x550000)).is_err());assert!(rt.exchange_module_word(cell,CrtValue::Scalar{bits:0,known:0}).is_err());assert!(rt.exchange_module_word(rt.offset(cell,1).unwrap(),CrtValue::Module(module)).is_err());
let short=rt.map_region(0x4000,3,CrtRegionKind::Module,Some(&[0;3])).unwrap();assert!(rt.bind_loader_cell(init,short,false).is_err());
let unknown=rt.map_region(0x4100,4,CrtRegionKind::Module,None).unwrap();assert!(rt.bind_loader_cell(init,unknown,false).is_err());
let stack=rt.map_region(0x9000,128,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,64).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(10)).unwrap();
let mut cpu=CrtCpu::new(sp,10).unwrap();cpu.r[0]=CrtValue::Module(module);cpu.r[1]=CrtValue::Pointer(cell);cpu.flags=CrtFlags{cf:Some(true),zf:Some(false),sf:Some(true),of:None};
assert_eq!(exchange(&mut rt,&mut cpu).unwrap(),CrtValue::scalar(0));assert_eq!(rt.load(cell,32).unwrap(),CrtValue::Module(module));assert_eq!((cpu.flags.cf,cpu.flags.zf,cpu.flags.sf,cpu.flags.of),(Some(true),Some(false),Some(true),None));
assert!(rt.load(cell,8).is_err());assert!(rt.store(cell,16,CrtValue::scalar(0)).is_err());
rt.store(second,32,CrtValue::Function(function)).unwrap();rt.module_release_result(init,first,true).unwrap();assert!(rt.module_release_result(init,first,true).is_err());rt.function_identity(function,None).unwrap();rt.module_identity(module).unwrap();
rt.module_release_result(init,second_ref,true).unwrap();assert!(rt.load(cell,32).is_err());assert!(rt.load(second,32).is_err());assert!(rt.function_identity(function,None).is_err());
let(reloaded,third)=rt.module_acquire_result(init,"unrelated fixture one",0x550000).unwrap();assert_ne!(reloaded,module);assert!(rt.module_identity(module).is_err());assert!(rt.function_identity(function,None).is_err());assert!(rt.module_release_result(init,first,true).is_err());
// Reusing a guest address or the same numeric handle never revives authority.
let(mut foreign,foreign_init)=CrtStreamRuntime::new_initializing(1,2,0x8000,65536).unwrap();let(foreign_module,foreign_ref)=foreign.module_acquire_result(foreign_init,"unrelated fixture one",0x550000).unwrap();assert!(rt.module_identity(foreign_module).is_err());assert!(rt.module_release_result(init,foreign_ref,true).is_err());
let other=rt.map_region(0x6000,4,CrtRegionKind::Module,Some(&[0;4])).unwrap();rt.bind_loader_cell(init,other,false).unwrap();let replacement=CrtPointer{cap:foreign.file().cap,..other};assert!(rt.exchange_module_word(replacement,CrtValue::Module(reloaded)).is_err());rt.memory.release(other.cap,other.owner).unwrap();assert!(rt.exchange_module_word(other,CrtValue::Module(reloaded)).is_err());
assert!(rt.module_release_result(init,third,false).is_err());assert!(rt.module_identity(reloaded).is_err());assert!(rt.module_acquire_result(init,"unrelated fixture one",0x550000).is_err());
let fresh=rt.map_region(0x7000,4,CrtRegionKind::Module,Some(&[0;4])).unwrap();rt.bind_loader_cell(init,fresh,false).unwrap();rt.end_initialization(init).unwrap();assert!(rt.exchange_module_word(fresh,CrtValue::scalar(u32::MAX)).is_err());assert_eq!(rt.load(fresh,32).unwrap(),CrtValue::scalar(0));
"#,
        "loader-authority",
    );
    // Unsupported widths, stack destination and prefix/address-space variations.
    for bytes in [
        &[0x86, 0x01][..],
        &[0x66, 0x87, 0x01],
        &[0x87, 0x21],
        &[0x64, 0x87, 0x01],
        &[0x67, 0x87, 0x01],
    ] {
        assert!(Graph::decode_instruction(bytes, 0x1000).is_err());
    }
}
