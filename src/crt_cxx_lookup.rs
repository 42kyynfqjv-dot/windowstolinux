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

pub(crate) const WIDE_COMPARE:&str="8bff558bec8b551085d2750433c05dc38b4d0c8b45085683ea01741c0f1f40000fb7306685f67410663b31750b83c00283c10283ea0175e80fb7000fb7092bc15e5dc3";

/// Mechanically execute the complete resolver and load helper under an explicit
/// component domain. Cached access grants no initialization authority; cold
/// effects require a live initialization lease. Loader API effects remain a cut.
pub(crate) fn cold_source(resolver: &[u8], load: &[u8]) -> Result<String, String> {
    cold_source_with_compare(resolver, load, &crate::crt_ptd::raw(WIDE_COMPARE))
}
fn cold_source_with_compare(
    resolver: &[u8],
    load: &[u8],
    compare: &[u8],
) -> Result<String, String> {
    cold_source_domain(resolver, load, compare, false)
}
pub(crate) fn mapped_source() -> Result<String, String> {
    cold_source_domain(
        &crate::crt_ptd::raw(COLD_FULL),
        &crate::crt_ptd::raw(LOAD_HELPER),
        &crate::crt_ptd::raw(WIDE_COMPARE),
        true,
    )
}
fn cold_source_domain(
    resolver: &[u8],
    load: &[u8],
    compare: &[u8],
    mapped: bool,
) -> Result<String, String> {
    if compare != crate::crt_ptd::raw(WIDE_COMPARE) {
        return Err("C++ original prefix comparator binding".into());
    }
    if resolver != crate::crt_ptd::raw(COLD_FULL) || load != crate::crt_ptd::raw(LOAD_HELPER) {
        return Err("C++ cold original code binding".into());
    }
    let mut out = String::from(
        r#"
#[derive(Clone,Copy)]
enum CrtResolverAccess {Cached,Initializing(CrtInitialization)}
impl CrtResolverAccess {
 fn check(self,rt:&CrtStreamRuntime)->Result<(),&'static str>{if rt.closed{return Err("CRT resolver closed runtime");}match self{Self::Cached=>Ok(()),Self::Initializing(token)=>rt.initialization(token)}}
 fn initialization(self,rt:&CrtStreamRuntime)->Result<CrtInitialization,&'static str>{match self{Self::Cached=>Err("CRT cached access cannot initialize"),Self::Initializing(token)=>{rt.initialization(token)?;Ok(token)}}}
}
"#,
    );
    if mapped {
        out.clear();
    }
    for (bytes, origin, name) in [
        (resolver, 0x402a53, "cxx_cold_resolver"),
        (load, 0x402af3, "cxx_load_helper"),
        (compare, 0x4078e0, "cxx_compare_prefix"),
    ] {
        let graph = Graph::decode(bytes, origin)?;
        let roles = BTreeMap::from([
            (0x41cd14, "CrtRegionKind::Module".into()),
            (0x41cd08, "CrtRegionKind::Module".into()),
            (0x415c80, "CrtRegionKind::Module".into()),
        ]);
        let helper = if mapped {
            "cxx_load_helper_mapped"
        } else {
            "cxx_load_helper"
        };
        let compare_helper = if mapped {
            "cxx_compare_prefix_mapped"
        } else {
            "cxx_compare_prefix"
        };
        let extra_arg = if mapped { ",inputs" } else { "" };
        let after_effect = if mapped { "inputs.validate(rt)?;" } else { "" };
        let prefix_pointer = if mapped {
            "rt.process_image_pointer(inputs.image,0x415d18,14)?"
        } else {
            "rt.resolve_absolute(0x415d18,CrtRegionKind::Input)?"
        };
        let body = crate::crt_stream_emit::emit_body_with_exit(
            &graph,
            |pc, target| {
                let next = pc + graph.nodes[&pc].length;
                Ok(match target {
                Target::Direct(0x402af3)=>format!("cpu.call_activation(rt,{next},0,|rt,child|{helper}(rt,child,access{extra_arg},api))?;"),
                Target::Direct(0x4078e0)=>format!("let sp=CrtCpu::pointer(cpu.r[4])?;let slot=rt.offset(sp,4)?;if rt.load(slot,32)?.known_scalar()?!=0x415d18{{return Err(\"C++ retry prefix address\");}}let prefix={prefix_pointer};for (i,b) in [97u8,0,112,0,105,0,45,0,109,0,115,0,45,0].iter().enumerate(){{if rt.load(rt.offset(prefix,i as i64)?,8)?.known_scalar()?!=u32::from(*b){{return Err(\"C++ retry prefix bytes\");}}}}rt.store(slot,32,CrtValue::Pointer(prefix))?;cpu.call_activation(rt,{next},0,|rt,child|{compare_helper}(rt,child,access{extra_arg},api))?;"),
                Target::Import(0x415044)=>format!("cpu.call_activation(rt,{next},0,|rt,child|{{child.clobber(rt.last_os_error.map(CrtValue::scalar).unwrap_or(CrtValue::Scalar{{bits:0,known:0}}));child.finish(rt)}})?;"),
                Target::Import(iat @ (0x415074|0x415070|0x41506c))=>{
                    let pop=match iat{0x415074=>12,0x415070=>8,_=>4};
                    format!("cpu.call_activation(rt,{next},{pop},|rt,child|cxx_loader_effect(rt,child,access,{iat},api))?;{after_effect}")
                },
                _=>"return Err(\"C++ cold prefix comparator/loader effect unbound\");".into()
            })
            },
            &roles,
            4096,
            |_, _| Err("C++ cold thread effect".into()),
            |pc, _| {
                if mapped && pc == 0x402a9f {
                    return Ok("let sp=CrtCpu::pointer(cpu.r[4])?;let address=rt.load(sp,32)?.known_scalar()?;let name=rt.process_image_pointer(inputs.image,address,2)?;rt.store(sp,32,CrtValue::Pointer(name))?;".into());
                }
                Ok(match pc{
            0x402a78=>"access.initialization(rt)?;".into(),
            0x4078e0=>"let sp=CrtCpu::pointer(cpu.r[4])?;if rt.load(rt.offset(sp,12)?,32)?.known_scalar()?>260{return Err(\"C++ prefix comparison count bound\");}".into(),
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
        let name = if mapped {
            format!("{name}_mapped")
        } else {
            name.to_string()
        };
        let parameter = if mapped {
            ",inputs:&CrtEntropyInputs"
        } else {
            ""
        };
        let check = if mapped {
            format!("inputs.validate(rt)?;cpu.validate_active(rt)?;let code=rt.process_image_code(inputs.image,{origin},{})?;if rt.memory.read(code.address(),{}).map_err(|_|\"startup resolver code read\")?!=&{bytes:?}{{return Err(\"startup resolver live code changed\");}}",bytes.len(),bytes.len())
        } else {
            String::new()
        };
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,access:CrtResolverAccess{parameter},api:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,u32)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{access.check(rt)?;{check}{body}}}"));
    }
    if mapped {
        return Ok(out);
    }
    out.push_str(r#"
fn cxx_loader_effect(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,access:CrtResolverAccess,iat:u32,api:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,u32)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{
 let init=access.initialization(rt)?;let sp=CrtCpu::pointer(cpu.r[4])?;
 let arg=rt.load(rt.offset(sp,4)?,32)?;
 let symbol=if iat==0x415070{
  let CrtValue::Module(module)=arg else{return Err("C++ GetProcAddress module authority");};rt.module_identity(module)?;
  let p=CrtCpu::pointer(rt.load(rt.offset(sp,8)?,32)?)?;let mut bytes=[0u8;256];let mut len=None;
  for(i,byte)in bytes.iter_mut().enumerate(){let b=rt.load(rt.offset(p,i as i64)?,8)?.known_scalar()? as u8;if b==0{len=Some(i);break;}*byte=b;}
  let len=len.filter(|n|*n>0).ok_or("C++ named export bounds/encoding")?;if !bytes[..len].is_ascii(){return Err("C++ named export bounds/encoding");}Some((module,bytes,len))
 }else{None};
 if iat==0x415074{
  let p=CrtCpu::pointer(arg)?;let mut units=[0u16;260];let mut len=None;
  for(i,unit)in units.iter_mut().enumerate(){let u=rt.load(rt.offset(p,(i*2)as i64)?,16)?.known_scalar()? as u16;if u==0{len=Some(i);break;}*unit=u;}
  let len=len.filter(|n|*n>0).ok_or("C++ module name bounds/encoding")?;if char::decode_utf16(units[..len].iter().copied()).any(|c|c.is_err()){return Err("C++ module name bounds/encoding");}
  if rt.load(rt.offset(sp,8)?,32)?.known_scalar()?!=0||!matches!(rt.load(rt.offset(sp,12)?,32)?.known_scalar()?,0|0x800){return Err("C++ executable loader flags/reserved argument");}
 }
 if iat==0x41506c{let CrtValue::Module(m)=arg else{return Err("C++ FreeLibrary module authority");};rt.module_identity(m)?;}
 let references=rt.module_references.clone();
 let result=api(rt,cpu,iat)?;rt.initialization(init)?;
 let mut added=rt.module_references.iter().filter(|(id,_)|!references.contains_key(id)).map(|(_,r)|*r);
 let first_added=added.next();let more_added=added.next().is_some();
 let mut removed=references.iter().filter(|(id,_)|!rt.module_references.contains_key(id)).map(|(_,r)|*r);
 let first_removed=removed.next();let more_removed=removed.next().is_some();
 if iat==0x415074 {match result{
  CrtValue::Module(m) if first_added.is_some_and(|r|r.module==m)&&!more_added&&first_removed.is_none()=>{},
  CrtValue::Scalar{bits:0,known:u32::MAX} if first_added.is_none()&&first_removed.is_none()=>{},
  _=>return Err("C++ load acquisition receipt mismatch")
 }}else if iat==0x41506c{
  let CrtValue::Module(m)=arg else{unreachable!()};
  if result.known_scalar()?==0{return Err("C++ release failure effects unclosed");}
  if first_added.is_some()||!first_removed.is_some_and(|r|r.module==m)||more_removed{return Err("C++ release receipt mismatch");}
 }else if first_added.is_some()||first_removed.is_some(){return Err("C++ export lookup changed references");}
 match iat{
  0x415074=>match result{CrtValue::Module(m)=>rt.module_identity(m)?,CrtValue::Scalar{bits:0,known:u32::MAX}=>{},_=>return Err("C++ loader result authority")},
  0x415070=>{let(module,name,len)=symbol.unwrap();rt.module_identity(module)?;let name=std::str::from_utf8(&name[..len]).map_err(|_|"C++ export encoding")?;match result{CrtValue::Function(f) if f.module==module=>rt.function_identity(f,Some(name))?,CrtValue::Scalar{bits:0,known:u32::MAX}=>{},_=>return Err("C++ export result authority")}},
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
for scenario in 0..17 {
 let(mut rt,init)=CrtStreamRuntime::new_initializing(11,29,0x8000,65536).unwrap();
 let cache=rt.map_region(0x41cd08,20,CrtRegionKind::Module,Some(&[0;20])).unwrap();
 let module_cell=cache;let function_cell=rt.offset(cache,12).unwrap();
 rt.bind_loader_cell(init,module_cell,false).unwrap();rt.bind_loader_cell(init,function_cell,true).unwrap();
 let list=rt.map_region(0x6000,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes())).unwrap();
 rt.map_region(0x415d18,16,CrtRegionKind::Input,Some(&[97,0,112,0,105,0,45,0,109,0,115,0,45,0,0,0])).unwrap();
 let text=if scenario==16{vec![97,0,112,0,105,0,45,0,109,0,115,0,45,0,120,0,0,0]}else{vec![b'a',0,b'l',0,b'p',0,b'h',0,b'a',0,0,0,0,0]};let name=rt.map_region(0x6100,text.len() as u32,CrtRegionKind::Input,Some(&text)).unwrap();
 let symbol=rt.map_region(0x6200,12,CrtRegionKind::Input,Some(b"FlsGetValue\0")).unwrap();
 let names=rt.map_region(0x415c80,4,CrtRegionKind::Module,None).unwrap();rt.store(names,32,CrtValue::Pointer(name)).unwrap();
 let stack=rt.map_region(0x9000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,3072).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();
 let mut cpu=CrtCpu::new(sp,1).unwrap();cpu.r[1]=CrtValue::Scalar{bits:0,known:0};let end=rt.offset(list,4).unwrap();cpu.push(&mut rt,CrtValue::Pointer(end)).unwrap();cpu.push(&mut rt,CrtValue::Pointer(list)).unwrap();cpu.push(&mut rt,CrtValue::Pointer(symbol)).unwrap();cpu.push(&mut rt,CrtValue::scalar(0)).unwrap();
 let retained=if matches!(scenario,3|10|11){Some(rt.module_acquire_result(init,"independent alpha identity",0x700000).unwrap())}else{None};let mut acquisitions=Vec::new();let mut calls=Vec::new();
 let result=cpu.call_activation(&mut rt,0x1234,0,|rt,child|cxx_cold_resolver(rt,child,CrtResolverAccess::Initializing(init),&mut |rt,cpu,iat|{
  calls.push(iat);let sp=CrtCpu::pointer(cpu.r[4])?;
  let value=match iat{
   0x415074=>{
    let retry=rt.load(rt.offset(sp,12)?,32)?.known_scalar()?==0;
    if retry{assert!(scenario==2||scenario>=13);}
    assert_eq!(rt.load(rt.offset(sp,4)?,32)?,CrtValue::Pointer(name));assert_eq!(rt.load(rt.offset(sp,8)?,32)?,CrtValue::scalar(0));assert_eq!(rt.load(rt.offset(sp,12)?,32)?,CrtValue::scalar(if retry{0}else{0x800}));
    if !retry && scenario>=13{rt.last_os_error=Some(87);CrtValue::scalar(0)}else if retry&&scenario==14{rt.last_os_error=Some(126);CrtValue::scalar(0)}else if retry&&scenario==15{return Err("retry failure after first call effects");}else if scenario==10{CrtValue::Module(retained.unwrap().0)}else if scenario==1||scenario==2||scenario==9{rt.last_os_error=if scenario==9{None}else{Some(if scenario==2{87}else{126})};CrtValue::scalar(0)}else{
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
  0|3|13=>{let CrtValue::Function(f)=result.unwrap()else{panic!()};rt.function_identity(f,Some("FlsGetValue")).unwrap();assert_eq!(rt.load(function_cell,32).unwrap(),CrtValue::Function(f));assert_eq!(rt.module_references.len(),1);cpu.discard(&mut rt,16).unwrap();cpu.finish(&mut rt).unwrap();
   assert_eq!(calls,if scenario==3{vec![0x415074,0x41506c,0x415070]}else if scenario==13{vec![0x415074,0x415074,0x415070]}else{vec![0x415074,0x415070]});
   rt.store(sp,32,CrtValue::ProtectedReturn(2)).unwrap();let mut cached=CrtCpu::new(sp,2).unwrap();cached.r[1]=CrtValue::Scalar{bits:0,known:0};let end=rt.offset(list,4).unwrap();cached.push(&mut rt,CrtValue::Pointer(end)).unwrap();cached.push(&mut rt,CrtValue::Pointer(list)).unwrap();cached.push(&mut rt,CrtValue::Pointer(symbol)).unwrap();cached.push(&mut rt,CrtValue::scalar(0)).unwrap();
   let hit=cached.call_activation(&mut rt,0x1234,0,|rt,child|cxx_cold_resolver(rt,child,CrtResolverAccess::Initializing(init),&mut |_,_,_|panic!("cached hit invoked loader"))).unwrap();assert_eq!(hit,CrtValue::Function(f));cached.discard(&mut rt,16).unwrap();cached.finish(&mut rt).unwrap();
  },
  1|2|14|16=>{assert_eq!(result.unwrap(),CrtValue::scalar(0));assert_eq!(rt.load(module_cell,32).unwrap(),CrtValue::scalar(u32::MAX));assert_eq!(rt.load(function_cell,32).unwrap(),CrtValue::scalar(u32::MAX));assert_eq!(calls.len(),if scenario==2||scenario==14{2}else{1});},
  5=>{assert_eq!(result.unwrap(),CrtValue::scalar(0));assert_eq!(rt.load(function_cell,32).unwrap(),CrtValue::scalar(u32::MAX));assert_eq!(rt.module_references.len(),1);},
  _=>{assert!(result.is_err(),"scenario {scenario}");if scenario==15{assert_eq!(rt.last_os_error,Some(87));assert_eq!(calls.len(),2);}if scenario==4{assert_eq!(rt.module_references.len(),1);assert_eq!(rt.load(module_cell,32).unwrap(),CrtValue::scalar(0));}}
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

#[test]
fn original_prefix_compare_has_independent_word_bounds_and_short_circuit_cases() {
    let extra = cold_source(
        &crate::crt_ptd::raw(COLD_FULL),
        &crate::crt_ptd::raw(LOAD_HELPER),
    )
    .unwrap();
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
let cases:Vec<(Vec<u16>,Vec<u16>,u32,Option<u32>)>=vec![
 (vec![],vec![],0,Some(0)),(vec![1],vec![1],1,Some(0)),
 (vec![0x100],vec![0xff],1,Some(1)),(vec![1],vec![2],7,Some(u32::MAX)),
 (vec![0],vec![9],200,Some(0u32.wrapping_sub(9))),
 (vec![4,5,6],vec![4,5,8],2,Some(0)),(vec![4,5,6],vec![4,5,8],3,Some(u32::MAX-1)),
 (vec![0xd800],vec![0xd801],1,Some(u32::MAX)),
 (vec![1],vec![1],2,None),(vec![1],vec![],1,None),(vec![1],vec![1],261,None)
];
for (left,right,count,expected) in cases {
 let(mut rt,init)=CrtStreamRuntime::new_initializing(41,63,0x8000,16384).unwrap();
 let bytes=|v:&[u16]|v.iter().flat_map(|n|n.to_le_bytes()).collect::<Vec<_>>();
 let left_bytes=bytes(&left);let right_bytes=bytes(&right);
 let a=rt.map_region(0x5000,((left.len()*2).max(1))as u32,CrtRegionKind::Input,if left.is_empty(){None}else{Some(&left_bytes)}).unwrap();
 let b=rt.map_region(0x6000,((right.len()*2).max(1))as u32,CrtRegionKind::Input,if right.is_empty(){None}else{Some(&right_bytes)}).unwrap();
 let stack=rt.map_region(0x9000,256,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,192).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();
 cpu.push(&mut rt,CrtValue::scalar(count)).unwrap();cpu.push(&mut rt,CrtValue::Pointer(b)).unwrap();cpu.push(&mut rt,CrtValue::Pointer(a)).unwrap();
 let result=cpu.call_activation(&mut rt,0x1111,0,|rt,c|cxx_compare_prefix(rt,c,CrtResolverAccess::Initializing(init),&mut |_,_,_|panic!("comparator called API")));
 match expected{Some(n)=>{assert_eq!(result.unwrap(),CrtValue::scalar(n));cpu.discard(&mut rt,12).unwrap();cpu.finish(&mut rt).unwrap();},None=>assert!(result.is_err())}
}
"#,
        "prefix-word-comparison",
    );
    let original = crate::crt_ptd::raw(WIDE_COMPARE);
    for index in 0..original.len() {
        let mut changed = original.clone();
        changed[index] ^= 1;
        assert!(cold_source_with_compare(
            &crate::crt_ptd::raw(COLD_FULL),
            &crate::crt_ptd::raw(LOAD_HELPER),
            &changed
        )
        .is_err());
    }
}

pub(crate) const INDIRECT_GUARD: &str = "c20000";
/// Original wrapper with explicit loader and stationary-fiber input contracts.
/// Only the byte-bound return-only guard domain is supported; a patched guard
/// or a missing TLS fallback contract rejects at its original call site.
pub(crate) fn dynamic_source(wrapper: &[u8], guard: &[u8]) -> Result<String, String> {
    dynamic_wrapper_source(wrapper, guard, false)
}
pub(crate) const SETTER: &str = "558bec5668685d410068605d410068685d41006a03e84afeffff83c4108bf0ff750cff750885f6740c8bceff1528514100ffd6eb06ff15645041005e5dc3";
pub(crate) fn setter_source(wrapper: &[u8], guard: &[u8]) -> Result<String, String> {
    dynamic_wrapper_source(wrapper, guard, true)
}
fn dynamic_wrapper_source(wrapper: &[u8], guard: &[u8], setter: bool) -> Result<String, String> {
    let (origin, end, names_at, symbol_at, cache_at, symbol, name, pop) = if setter {
        (
            0x402befu32,
            0x402c2d,
            0x415d60,
            0x415d68,
            0x41cd20,
            "FlsSetValue",
            "cxx_dynamic_setter",
            8,
        )
    } else {
        (
            0x402bb4,
            0x402bef,
            0x415d4c,
            0x415d54,
            0x41cd1c,
            "FlsGetValue",
            "cxx_dynamic_lookup",
            4,
        )
    };
    let guard_name = format!("{name}_guard");
    let outcome_parameter = if setter {
        ",set_result:&mut impl FnMut(&mut CrtStreamRuntime,u32,CrtValue)->Result<(u32,Option<u32>),&'static str>"
    } else {
        ""
    };
    let effect = if setter {
        "let value=rt.load(rt.offset(sp,8)?,32)?;rt.fls_value_for(slot,value)?;rt.check_fiber(fiber)?;if slot.fiber!=fiber||slot.index!=index||rt.fls.get(&index).map(|x|x.0)!=Some(slot){return Err(\"CRT FLS setter owner/index/lifetime\");}let (result,last_error)=set_result(rt,index,value)?;rt.function_identity(f,Some(\"FlsSetValue\"))?;rt.fls_set(fiber,slot,index,value,result!=0,last_error)?;CrtValue::scalar(result)"
    } else {
        "rt.fls_get(fiber,slot,index)?"
    };
    if wrapper != crate::crt_ptd::raw(if setter { SETTER } else { WRAPPER })
        || guard != crate::crt_ptd::raw(INDIRECT_GUARD)
    {
        return Err("C++ dynamic lookup/guard binding".into());
    }
    let guard_graph = Graph::decode(guard, 0x401bf9)?;
    let guard_body = crate::crt_stream_emit::emit_body(
        &guard_graph,
        |_, _| Err("guard call".into()),
        &BTreeMap::new(),
        2,
    )?;
    let mut nodes = BTreeMap::new();
    let mut decoder = iced_x86::Decoder::with_ip(
        32,
        wrapper,
        u64::from(origin),
        iced_x86::DecoderOptions::NONE,
    );
    while decoder.can_decode() {
        let i = decoder.decode();
        let offset = (i.ip32() - origin) as usize;
        nodes.insert(
            i.ip32(),
            Graph::decode_instruction(&wrapper[offset..offset + i.len()], i.ip32())?,
        );
    }
    let graph = Graph { origin, end, nodes };

    let body = crate::crt_stream_emit::emit_body_with_indirect(
        &graph,
        |pc, t| {
            let next = pc + graph.nodes[&pc].length;
            Ok(match t {
                Target::Direct(0x402a53) => format!(
                    r#"let sp=CrtCpu::pointer(cpu.r[4])?;let names=rt.resolve_absolute({names_at},CrtRegionKind::Input)?;if rt.load(names,32)?.known_scalar()?!=0||rt.load(rt.offset(names,4)?,32)?.known_scalar()?!=2{{return Err("C++ module index list");}}let symbol=rt.resolve_absolute({symbol_at},CrtRegionKind::Input)?;for(i,b)in b"{symbol}\0".iter().enumerate(){{if rt.load(rt.offset(symbol,i as i64)?,8)?.known_scalar()?!=u32::from(*b){{return Err("C++ dynamic symbol bytes");}}}}for(offset,address,value)in [(4,{symbol_at},symbol),(8,{names_at},names),(12,{symbol_at},rt.offset(names,8)?)]{{let p=rt.offset(sp,offset)?;if rt.load(p,32)?.known_scalar()?!=address{{return Err("C++ lookup pointer immediate");}}rt.store(p,32,CrtValue::Pointer(value))?;}}cpu.call_activation(rt,{next},0,|rt,c|cxx_cold_resolver(rt,c,access,api))?;"#
                ),
                Target::Import(0x415128) => format!(
                    r#"let cell=rt.resolve_absolute(0x415128,CrtRegionKind::Module)?;if rt.load(cell,32)?.known_scalar()?!=0x401bf9{{return Err("C++ live guard target unbound");}}let CrtValue::Function(f)=cpu.r[1] else{{return Err("C++ guard function authority");}};rt.function_identity(f,Some("{symbol}"))?;if cpu.r[6]!=CrtValue::Function(f){{return Err("C++ guard target mismatch");}}cpu.call_activation(rt,{next},0,|rt,c|{guard_name}(rt,c))?;guarded=Some(f);"#
                ),
                _ => "return Err(\"C++ TLS fallback effect remains unbound\");".into(),
            })
        },
        &BTreeMap::new(),
        4096,
        |_, _| Err("dynamic FS effect".into()),
        |_, _| Ok(String::new()),
        |_, _| Ok(None),
        None,
        |_, _, _| Ok(None),
        |pc, _| {
            let next = pc + graph.nodes[&pc].length;
            Ok(format!(
                r#"let CrtValue::Function(f)=target else{{return Err("C++ indirect function provenance");}};if guarded.take()!=Some(f){{return Err("C++ missing/replayed guard receipt");}}rt.function_identity(f,Some("{symbol}"))?;let cache=rt.resolve_absolute({cache_at},CrtRegionKind::Module)?;if rt.load(cache,32)?!=target{{return Err("C++ indirect cache target changed");}}cpu.call_activation(rt,{next},{pop},|rt,c|{{rt.function_identity(f,Some("{symbol}"))?;let sp=CrtCpu::pointer(c.r[4])?;let index=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;let value={{{effect}}};c.clobber(value);c.finish_pop(rt,{pop})}})?;"#
            ))
        },
    )?;
    Ok(format!("fn {guard_name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{guard_body}}}fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,access:CrtResolverAccess,fiber:CrtFiber,slot:CrtFlsSlot,api:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,u32)->Result<CrtValue,&'static str>{outcome_parameter})->Result<CrtValue,&'static str>{{access.check(rt)?;let mut guarded:Option<CrtFunction>=None;{body}}}"))
}

#[test]
fn original_dynamic_lookup_checks_guard_module_fiber_slot_and_protected_return() {
    let wrapper = crate::crt_ptd::raw(WRAPPER);
    let guard = crate::crt_ptd::raw(INDIRECT_GUARD);
    let extra = format!(
        "{} {}",
        cold_source(
            &crate::crt_ptd::raw(COLD_FULL),
            &crate::crt_ptd::raw(LOAD_HELPER)
        )
        .unwrap(),
        dynamic_source(&wrapper, &guard).unwrap()
    );
    if let Some(out) = std::env::var_os("W2L_EH4_EVIDENCE") {
        std::fs::write(
            std::path::Path::new(&out).join("dynamic-fls-component.rs"),
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
for scenario in 0..19{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(12,34,0x8000,65536).unwrap();
 let(m,reference)=rt.module_acquire_result(init,"independent executable module",0x700000).unwrap();let f=rt.module_export_result(init,m,if scenario==8{"OtherExport"}else{"FlsGetValue"},0x701000).unwrap();
 let cache_root=rt.map_region(0x41cd14,12,CrtRegionKind::Module,None).unwrap();let cache=rt.offset(cache_root,8).unwrap();rt.store(cache,32,if scenario==9{CrtValue::scalar(0x701000)}else if scenario>=16{CrtValue::scalar(0)}else{CrtValue::Function(f)}).unwrap();
 if scenario>=16{let cells=rt.map_region(0x41cd08,12,CrtRegionKind::Module,Some(&[0;12])).unwrap();rt.bind_loader_cell(init,cells,false).unwrap();rt.bind_loader_cell(init,rt.offset(cells,8).unwrap(),false).unwrap();rt.bind_loader_cell(init,cache,true).unwrap();let name=rt.map_region(0x6500,4,CrtRegionKind::Input,Some(&[97,0,0,0])).unwrap();let table=rt.map_region(0x415c80,12,CrtRegionKind::Module,None).unwrap();rt.store(table,32,CrtValue::Pointer(name)).unwrap();}
 let guard=rt.map_region(0x415128,4,CrtRegionKind::Module,Some(&0x401bf9u32.to_le_bytes())).unwrap();
 let names=rt.map_region(0x415d4c,8,CrtRegionKind::Input,Some(&[0,0,0,0,2,0,0,0])).unwrap();
 rt.map_region(0x415d54,12,CrtRegionKind::Input,Some(b"FlsGetValue\0")).unwrap();
 let ptd=rt.map_region(0x6000,40,CrtRegionKind::ThreadData,None).unwrap();let fiber=rt.bind_fiber(34).unwrap();let slot=rt.bind_fls(fiber,3,if scenario==1{CrtValue::scalar(0)}else if scenario==2{CrtValue::scalar(u32::MAX)}else{CrtValue::Pointer(ptd)}).unwrap();
 let(mut other,other_init)=CrtStreamRuntime::new_initializing(12,34,0x8000,65536).unwrap();let foreign=other.bind_fiber(34).unwrap();
 match scenario{
  3=>{rt.retire_fls(fiber,slot).unwrap();},4=>{rt.retire_fls(fiber,slot).unwrap();rt.bind_fls(fiber,3,CrtValue::Pointer(ptd)).unwrap();},
  6|7=>{rt.module_release_result(init,reference,true).unwrap();if scenario==7{rt.module_acquire_result(init,"independent executable module",0x700000).unwrap();}},
  10=>{rt.store(guard,32,CrtValue::scalar(0x401bfa)).unwrap();},11=>{rt.store(guard,32,CrtValue::Scalar{bits:0,known:0}).unwrap();},
  12=>{rt.retire_region(ptd).unwrap();},13=>{rt.fls_set(fiber,slot,3,CrtValue::Pointer(ptd),false,Some(8)).unwrap();},
  14=>{rt.memory.release(names.cap,names.owner).unwrap();},_=>{}
 }
 rt.last_os_error=Some(123);
 let stack=rt.map_region(0x9000,2048,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,1536).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();cpu.r[1]=CrtValue::Scalar{bits:0,known:0};cpu.push(&mut rt,CrtValue::scalar(if scenario==15{4}else{3})).unwrap();
 let mut api_calls=0;
 let result=cpu.call_activation(&mut rt,0x1111,0,|rt,c|cxx_dynamic_lookup(rt,c,CrtResolverAccess::Initializing(init),if scenario==5{foreign}else{fiber},slot,&mut |rt,c,iat|{assert!(scenario>=16);api_calls+=1;let result=match iat{0x415074=>{let(module,_)=rt.module_acquire_result(init,"independent executable module",0x700000)?;if scenario==17{rt.store(guard,32,CrtValue::scalar(0x401bfa))?;}if scenario==18{rt.retire_fls(fiber,slot)?;}CrtValue::Module(module)},0x415070=>CrtValue::Function(rt.module_export_result(init,m,"FlsGetValue",0x701000)?),_=>panic!()};c.clobber(result);c.finish_pop(rt,if iat==0x415074{12}else{8})}));
 if scenario<=2||scenario==16{
  assert_eq!(api_calls,if scenario==16{2}else{0});assert_eq!(result.unwrap(),if scenario==1{CrtValue::scalar(0)}else if scenario==2{CrtValue::scalar(u32::MAX)}else{CrtValue::Pointer(ptd)});assert_eq!(rt.last_os_error,None);assert!(rt.load(rt.offset(ptd,32).unwrap(),32).unwrap().known_scalar().is_err());cpu.discard(&mut rt,4).unwrap();cpu.finish(&mut rt).unwrap();
 }else{assert!(result.is_err(),"scenario {scenario}");assert_eq!(rt.last_os_error,Some(123));if scenario>=17{assert_eq!(api_calls,2);assert_eq!(rt.module_references.len(),2);}}
 // Release receipts stay single-use, and a foreign runtime cannot revive them.
 assert!(other.module_release_result(other_init,reference,true).is_err());
}
"#,
        "owned-dynamic-fls",
    );
    for (which, bytes) in [(0, &wrapper), (1, &guard)] {
        for i in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[i] ^= 1;
            assert!(if which == 0 {
                dynamic_source(&changed, &guard)
            } else {
                dynamic_source(&wrapper, &changed)
            }
            .is_err());
        }
    }
}

#[test]
fn native_loader_checked_transport_survives_allocator_denial() {
    let mut extra = cold_source(
        &crate::crt_ptd::raw(COLD_FULL),
        &crate::crt_ptd::raw(LOAD_HELPER),
    )
    .unwrap();
    extra.push_str(crate::crt_resident_loader::TYPES);
    extra.push_str(r#"struct Guard;static DENY:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
unsafe impl std::alloc::GlobalAlloc for Guard{
 unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{if DENY.load(std::sync::atomic::Ordering::SeqCst){std::ptr::null_mut()}else{std::alloc::System.alloc(l)}}
 unsafe fn realloc(&self,p:*mut u8,l:std::alloc::Layout,n:usize)->*mut u8{if DENY.load(std::sync::atomic::Ordering::SeqCst){std::ptr::null_mut()}else{std::alloc::System.realloc(p,l,n)}}
 unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){std::alloc::System.dealloc(p,l)}
}
#[global_allocator]static ALLOC:Guard=Guard;
"#);
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
for scenario in 0..8{
 let(mut r,i)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let p=CrtNativePlatform::prepare(&mut r,i,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();
 let mut text:Vec<u8>=CrtNativePlatform::CONTRACT.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();if scenario==2{text[0]=0; text[1]=0xd8;}if scenario==5{text=vec![65,0].repeat(260);}if scenario==7{text[0]=0x80;}
 let name=r.map_region(0x9000,text.len() as u32,CrtRegionKind::Input,Some(&text)).unwrap();let sp=r.map_region(0xa000,64,CrtRegionKind::Stack,None).unwrap();
 r.store(sp,32,CrtValue::ProtectedReturn(77)).unwrap();r.store(r.offset(sp,4).unwrap(),32,CrtValue::Pointer(name)).unwrap();r.store(r.offset(sp,8).unwrap(),32,CrtValue::scalar(0)).unwrap();r.store(r.offset(sp,12).unwrap(),32,CrtValue::scalar(if scenario==1{8}else{0x800})).unwrap();
 let mut c=CrtCpu::new(sp,77).unwrap();c.return_pop=12;if scenario==4{c.return_id=78;}if scenario==3{r.provider_destroy(i,p.function.module).unwrap();}if scenario==6{for _ in 0..255{r.native_provider_acquire(i,p.function).unwrap();}}
 let before=r.module_references.len();r.last_os_error=Some(1114);
 DENY.store(true,std::sync::atomic::Ordering::SeqCst);
 let got=cxx_loader_effect(&mut r,&mut c,CrtResolverAccess::Initializing(i),0x415074,&mut |r,c,iat|p.call(r,c,i,iat));
 DENY.store(false,std::sync::atomic::Ordering::SeqCst);
 if scenario==0{assert_eq!(got,Ok(CrtValue::Module(p.function.module)));assert_eq!(r.module_references.len(),before+1);assert_eq!(r.last_os_error,None);assert!(c.returned);assert_eq!(CrtCpu::pointer(c.r[4]).unwrap().address(),0xa010);}
 else{assert_eq!(got,Err(match scenario{1=>"C++ executable loader flags/reserved argument",2|5=>"C++ module name bounds/encoding",3=>"CRT unloaded module",4=>"CRT active caller lifetime/return authority",6=>"CRT native provider reference budget",7=>"native platform API-set encoding",_=>unreachable!()}));assert_eq!(r.module_references.len(),before);assert_eq!(r.last_os_error,Some(1114));assert!(!c.returned);}
}
"#,
        "native-loader-no-allocation",
    );
}
