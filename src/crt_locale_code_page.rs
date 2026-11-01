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
    out.push_str(&initializer_source()?);
    out.push_str(&classifier_source()?);
    Ok(out)
}

// All original instructions are retained; unbound calls and non-UTF8 branches
// reject before their effects. The installed-code-page API is an explicit profile.
pub(crate) const INITIALIZER: &str = "8bff558bec83ec24a100c0410033c58945fc53568b750c57ff7508e817fbffff8bd8895de05985db0f84bf01000033ff8bcf8bc7894de4399870c641000f84f60000004183c030894de43df000000072e681fbe8fd00000f84d40000000fb7c350ff15cc50410085c00f84c2000000b8e9fd00003bd8752089460489be1c020000897e1866897e1c897e0833c08d7e0cabababe94d0100008d45e85053ff15d850410085c0747e68010100008d46185750e8356effff83c40c895e04837de80289be1c02000075c0807dee008d45ee742a8a480184c974230fb6380fb6c93bf977118d56192bcf03d741800a044283e90175f783c00280380075d68d461ab9fe0000008008084083e90175f7ff7604e8e5f9ffff33ff89861c02000083c40447e963ffffff393d44d141000f85bc00000083c8ffe9bd00000068010100008d46185750e8a36dffff83c40c6b45e4308945dc8d8080c641008945e48038008bc8743b8a410184c074310fb6110fb6c03bd0771f8d5e1903da81fa0001000073128a8768c641000803420fb64101433bd076e683c10280390075c88b45e44783c0088945e483ff0472b28b5de053895e04c7460801000000e83df9ffff83c40489861c0200008b45dc8d4e0c6a068d9074c641005f668b028d52026689018d490283ef0175ef56e820faffffeb0656e8b5f9ffff33c0598b4dfc5f5e33cd5be8c45effffc9c3";
pub(crate) const INITIALIZER_CALL: &str = "e8b9010000";
pub(crate) fn initializer_call_graph() -> Result<Graph, String> {
    crate::crt_startup_table::graph(&crate::crt_ptd::raw(INITIALIZER_CALL), 0x40b2c7)
}
fn initializer_source() -> Result<String, String> {
    let bytes = crate::crt_ptd::raw(INITIALIZER);
    let g = Graph::decode(&bytes, 0x40b485)?;
    let roles = std::collections::BTreeMap::from([
        (0x41c000, "CrtRegionKind::Module".into()),
        (0x41c670, "CrtRegionKind::Module".into()),
        (0x41c668, "CrtRegionKind::Module".into()),
        (0x41d144, "CrtRegionKind::Module".into()),
    ]);
    let body = crate::crt_stream_emit::emit_body_with_hooks(
        &g,
        |pc, t| {
            let next = pc + g.nodes[&pc].length;
            Ok(match t {
   Target::Direct(0x40afbc)=>format!("cpu.call_activation(rt,{next},0,|rt,c|locale_code_page_original(rt,c,inputs,platform))?;"),
   Target::Import(0x4150cc)=>format!("rt.process_image_import(inputs.image,0x4150cc,\"kernel32.dll\",\"IsValidCodePage\")?;cpu.call_activation(rt,{next},4,|rt,c|platform.valid_code_page_call(rt,c,inputs.init))?;"),
   Target::Direct(0x40b090)=>format!("cpu.call_activation(rt,{next},0,|rt,c|locale_classifier_original(rt,c,inputs))?;"),
   Target::Direct(0x40154c)=>format!("cpu.call_activation(rt,{next},0,|rt,c|locale_security_original(rt,c,inputs))?;"),
   Target::Direct(0x40b02d|0x40af7e|0x402370)|Target::Import(0x4150d8)=>"return Err(\"locale multibyte helper effect unbound\");".into(),
   _=>return Err(format!("locale initializer unexpected call {pc:x}: {t:?}"))
  })
        },
        &roles,
        4096,
        |_, _| Err("locale initializer thread effect".into()),
        |pc, _| {
            Ok(if matches!(pc, 0x40b5be | 0x40b672 | 0x40b5b6) {
                "return Err(\"locale initializer alternate code-page path unbound\");".into()
            } else {
                String::new()
            })
        },
        |_, _| Ok(Some("return cpu.finish(rt);".into())),
    )?;
    let call = crate::crt_ptd::raw(INITIALIZER_CALL);
    Ok(format!("fn locale_multibyte_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;platform.validate(rt,inputs.init)?;cpu.validate_active(rt)?;for(address,expected)in[(0x40b485u32,&{bytes:?}[..]),(0x40b2c7,&{call:?}[..])]{{let p=rt.process_image_code(inputs.image,address,expected.len()as u32)?;if rt.memory.read(p.address(),expected.len()as u32).map_err(|_|\"locale initializer code read\")?!=expected{{return Err(\"locale initializer code changed\");}}}}{body}}}"))
}

pub(crate) const CLASSIFIER:&str="8bff558bec81ec20070000a100c0410033c58945fc5356578b7d08817f04e9fd00000f840c0100008d85e8f8ffff50ff7704ff15d850410085c00f84f400000033dbbe000100008bc3888405fcfeffff403bc672f48a85eef8ffff8d8deef8ffffc685fcfeffff20eb1f0fb651010fb6c0eb0d3bc6730dc68405fcfeffff20403bc276ef83c1028a0184c075dd53ff77048d85fcf8ffff50568d85fcfeffff506a0153e85712000053ff77048d85fcfdffff5650568d85fcfeffff5056ffb71c02000053e81858000083c4408d85fcfcffff53ff77045650568d85fcfeffff506800020000ffb71c02000053e8f057000083c4248d47198bcb0fb7944dfcf8fffff6c201740c8008108a940dfcfdffffeb13f6c202740c8008208a940dfcfcffffeb028ad3418890000100004083ee0175c7eb626aa6586a865a2bd78d4f198995e4f8ffff2bc76ae75a2bd78985e0f8ffff8bbde4f8ffff33dbbe0001000003c183f81977088009108d4120eb0e8d040f83f819770a8009208d41e002c2eb028ac3888100010000418d04113bc68b85e0f8ffff72c98b4dfc5f5e33cd5be81963ffffc9c3";
pub(crate) const SECURITY: &str = "3b0d00c041007501c3e97c020000";
fn classifier_source() -> Result<String, String> {
    let bytes = crate::crt_ptd::raw(CLASSIFIER);
    let mut g = Graph::decode(&bytes, 0x40b090)?;
    // Original ADD computes a numeric byte index from a real buffer address.
    // Discarding result authority cannot introduce a new memory capability.
    g.numeric_result(0x40b1ef)?;
    let body = crate::crt_stream_emit::emit_body_with_hooks(
        &g,
        |pc, t| {
            let next = pc + g.nodes[&pc].length;
            Ok(match t{
   Target::Direct(0x40154c)=>format!("cpu.call_activation(rt,{next},0,|rt,c|locale_security_original(rt,c,inputs))?;"),
   Target::Import(0x4150d8)|Target::Direct(0x40c38f|0x410971)=>"return Err(\"locale classification NLS effect unbound\");".into(),
   _=>return Err(format!("classification unexpected call {pc:x} {t:?}"))
  })
        },
        &std::collections::BTreeMap::from([(0x41c000, "CrtRegionKind::Module".into())]),
        16384,
        |_, _| Err("classification thread effect".into()),
        |pc, _| {
            Ok(if pc == 0x40b0b8 {
                "return Err(\"locale classification non-UTF8 path unbound\");".into()
            } else {
                String::new()
            })
        },
        |_, _| Ok(None),
    )?;
    let guard = crate::crt_ptd::raw(SECURITY);
    let proof = crate::crt_stream_callees::prove_security(&guard, 0x40154c)?;
    if proof.cookie() != 0x41c000 {
        return Err("locale security cookie binding".into());
    }
    let failure = proof.failure_target();
    let sg = Graph::decode_with_exits(&guard, 0x40154c, &[failure])?;
    let mut sb = crate::crt_stream_emit::emit_body_with_exit(
        &sg,
        |_, _| Err("security call".into()),
        &std::collections::BTreeMap::from([(0x41c000, "CrtRegionKind::Module".into())]),
        16,
        |_, _| Err("security thread".into()),
        |_, _| Ok(String::new()),
        |_, _| Ok(None),
        Some(failure),
    )?;
    let terminal = format!("if pc=={failure}{{return Ok(cpu.r[0]);}}");
    if !sb.contains(&terminal) {
        return Err("locale security failure boundary missing".into());
    }
    sb = sb.replace(
        &terminal,
        &format!("if pc=={failure}{{return Err(\"locale security failure effect unbound\");}}"),
    );
    Ok(format!("fn locale_security_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,0x40154c,{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"locale security code read\")?!=&{guard:?}{{return Err(\"locale security code changed\");}}{sb}}}fn locale_classifier_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,0x40b090,{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"locale classifier code read\")?!=&{bytes:?}{{return Err(\"locale classifier code changed\");}}{body}}}",guard.len(),guard.len(),bytes.len(),bytes.len()))
}

#[test]
fn original_multibyte_graph_has_explicit_api_and_unproved_path_boundaries() {
    let code = initializer_source().expect("complete original initializer must lower");
    assert!(code.contains("platform.valid_code_page_call"));
    classifier_source().expect("original classifier must lower");
    assert!(code.contains("locale initializer alternate code-page path unbound"));
    assert!(code.contains("cpu.finish(rt)"));
    let bytes = crate::crt_ptd::raw(INITIALIZER);
    assert_eq!(bytes.len(), 517);
    let g = Graph::decode(&bytes, 0x40b485).unwrap();
    assert_eq!(
        g.nodes[&0x40b4e6].op,
        crate::crt_stream_ir::Op::Call(Target::Import(0x4150cc))
    );
    let caller =
        Graph::decode_instruction(&crate::crt_ptd::raw(INITIALIZER_CALL), 0x40b2c7).unwrap();
    assert_eq!(
        caller.op,
        crate::crt_stream_ir::Op::Call(Target::Direct(0x40b485))
    );
}

#[test]
fn word_register_load_and_zero_extension_preserve_knowledge_flags_and_no_authority() {
    let mut extra = String::new();
    for dst in 0u8..8 {
        let g = Graph::decode_linear_fragment(&[0x66, 0x8b, 0x02 | (dst << 3)], 0x1000).unwrap();
        let body = crate::crt_stream_emit::emit_linear_fragment(&g, &Default::default()).unwrap();
        extra.push_str(&format!("fn load{dst}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}"));
        if dst == 4 {
            continue;
        }
        for src in 0u8..8 {
            let g = Graph::decode_linear_fragment(&[0x0f, 0xb7, 0xc0 | (dst << 3) | src], 0x2000)
                .unwrap();
            let body =
                crate::crt_stream_emit::emit_linear_fragment(&g, &Default::default()).unwrap();
            extra.push_str(&format!("fn zx{dst}_{src}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}"));
        }
    }
    let mut cases = String::from(
        r#"
fn base()->(CrtStreamRuntime,CrtCpu){let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0xa000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,2048).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(99)).unwrap();let mut c=CrtCpu::new(sp,99).unwrap();c.flags=CrtFlags{cf:Some(true),zf:Some(false),sf:Some(true),of:Some(false)};(rt,c)}
fn flags(c:&CrtCpu){assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(Some(true),Some(false),Some(true),Some(false)));}
"#,
    );
    let mut calls = String::from("let mut checked=0u32;");
    for dst in 0u8..8 {
        calls.push_str(&format!("load_case{dst}(&mut checked);"));
        cases.push_str(&format!(r#"
#[inline(never)] fn load_case{dst}(checked:&mut u32){{
for mode in 0..5{{let(mut rt,mut c)=base();let data=rt.map_region(0x20000,if mode==4{{4}}else{{2}},CrtRegionKind::Stack,None).unwrap();rt.store(data,16,if mode==1{{CrtValue::Scalar{{bits:0x12cd,known:0xffff00ff}}}}else{{CrtValue::scalar(0x12cd)}}).unwrap();c.r[{dst}]=CrtValue::Scalar{{bits:0xdeadbeef,known:0xff00ffff}};if {dst}==4{{c.r[4]=c.entry[4];}}c.r[2]=CrtValue::Pointer(data);let old=c.r[{dst}];let prior=c.r;
if mode==4{{rt.store(data,32,CrtValue::ProtectedReturn(777)).unwrap();}}if mode==2{{rt.memory.release(data.cap,data.owner).unwrap();}}if mode==3{{c.r[2]=CrtValue::scalar(data.address());}}let result=load{dst}(&mut rt,&mut c);
if mode>=2{{assert_eq!(result,Err(if mode==2{{"CRT pointer lifetime"}}else if mode==3{{"CRT scalar address lacks provenance"}}else{{"CRT partial typed-word read"}}));assert_eq!(c.r[{dst}],if mode==3&&{dst}==2{{CrtValue::scalar(data.address())}}else{{prior[{dst}]}});}}else{{result.expect("word load must execute");let upper=if {dst}==2{{0x20000}}else if {dst}==4{{0}}else{{0xdead0000}};let knowledge=if {dst}==2||{dst}==4{{0xffff0000}}else{{0xff000000}};assert_eq!(c.r[{dst}],CrtValue::Scalar{{bits:upper|if mode==1{{0xcd}}else{{0x12cd}},known:knowledge|if mode==1{{0x00ff}}else{{0xffff}}}});assert!(CrtCpu::pointer(c.r[{dst}]).is_err());let _=old;}}flags(&c);*checked+=1;
}}
}}
"#));
        if dst == 4 {
            continue;
        }
        for src in 0u8..8 {
            calls.push_str(&format!("zx_case{dst}_{src}(&mut checked);"));
            cases.push_str(&format!(r#"
#[inline(never)] fn zx_case{dst}_{src}(checked:&mut u32){{
for partial in [false,true]{{let(mut rt,mut c)=base();c.r[{src}]=CrtValue::Scalar{{bits:0xdeadbeef,known:if partial{{0xffffff00}}else{{0x0000ffff}}}};let before=c.r;let result=zx{dst}_{src}(&mut rt,&mut c);if partial{{assert_eq!(result,Err("CRT unknown scalar bits observed"));assert_eq!(c.r,before);}}else{{result.expect("known low word must extend despite unknown upper bits");assert_eq!(c.r[{dst}],CrtValue::scalar(0xbeef));assert!(CrtCpu::pointer(c.r[{dst}]).is_err());for r in 0..8{{if r!={dst}{{assert_eq!(c.r[r],before[r]);}}}}}}flags(&c);*checked+=1;}}
}}
"#));
        }
    }
    calls.push_str("assert_eq!(checked,152,\"all declared word cases must execute\");");
    cases.push_str(&calls);
    crate::crt_stream_callees_tests::native_bounded_stack(
        &extra,
        &cases,
        "word-register-knowledge",
    );
    for bytes in [
        vec![0x66, 0x0f, 0xb7, 0xc3],
        vec![0x0f, 0xb7, 0xe0],
        vec![0xf3, 0x0f, 0xb7, 0xc3],
        vec![0x64, 0x66, 0x8b, 0x02],
        vec![0x66, 0x8b, 0xc3],
    ] {
        assert!(
            Graph::decode_linear_fragment(&bytes, 0x1000).is_err(),
            "{bytes:x?}"
        );
    }
}

#[test]
fn original_initializer_call_accounts_for_its_instruction_before_effects() {
    let g = initializer_call_graph().unwrap();
    let body=crate::crt_stream_emit::emit_body_with_exit(&g,|pc,t|{
  assert_eq!(pc,0x40b2c7);assert_eq!(t,Target::Direct(0x40b485));
  Ok("cpu.call_activation(rt,0x40b2cc,0,|rt,c|{rt.store(marker,32,CrtValue::scalar(71))?;let _=c;Err(\"declared callee boundary\")})?;".into())
 },&Default::default(),1,|_,_|Err("thread".into()),|_,_|Ok(String::new()),|_,_|Ok(None),Some(g.end)).unwrap();
    let extra=format!("fn invoke(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,marker:CrtPointer)->Result<CrtValue,&'static str>{{{body}}}");
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
 for exhausted in [true,false]{let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0xa000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,2048).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(99)).unwrap();let mut c=CrtCpu::new(sp,99).unwrap();c.steps=if exhausted{u32::MAX}else{u32::MAX-1};let marker=rt.map_region(0x20000,4,CrtRegionKind::Stack,Some(&[0;4])).unwrap();let generation=rt.generation;let result=invoke(&mut rt,&mut c,marker);assert_eq!(result,Err(if exhausted{"CRT instruction counter overflow"}else{"declared callee boundary"}));assert!(!c.returned);assert_eq!(rt.load(marker,32).unwrap(),CrtValue::scalar(if exhausted{0}else{71}));if exhausted{assert_eq!(c.r[4],CrtValue::Pointer(sp));assert_eq!(rt.generation,generation);assert_eq!(rt.tags.values().filter(|v|matches!(v,CrtValue::ProtectedReturn(_))).count(),1);}else{assert_eq!(c.steps,u32::MAX);assert!(CrtCpu::number(c.r[4]).unwrap()<sp.address());}}
 "#,
        "original-call-budget-order",
    );
}

#[test]
fn numeric_address_results_drop_authority_preserve_flags_and_reject_erased_reads() {
    let mut g = Graph::decode_linear_fragment(&[0x03, 0xc1], 0x1000).unwrap();
    g.numeric_result(0x1000).unwrap();
    assert!(g.numeric_result(0x1000).is_err());
    for bytes in [
        &[0x03, 0x01][..],
        &[0x03, 0xe1],
        &[0x8b, 0xc1],
        &[0x8d, 0x01],
    ] {
        let mut x = Graph::decode_linear_fragment(bytes, 0x1000).unwrap();
        assert!(x.numeric_result(0x1000).is_err(), "{bytes:x?}");
    }
    let body = crate::crt_stream_emit::emit_linear_fragment(&g, &Default::default()).unwrap();
    let extra=format!("fn number(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}");
    crate::crt_stream_callees_tests::native_bounded_stack(
        &extra,
        r#"
// Keep independent runtime instances in separate native frames. All vectors
// and the 512 KiB child limit are unchanged.
#[inline(never)] fn vector(base:u32,index:u32){
 let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0xa000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,2048).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(77)).unwrap();let mut c=CrtCpu::new(sp,77).unwrap();let p=rt.map_region(base,544,CrtRegionKind::Stack,None).unwrap();let addr=base+25+index;let relative=0xffffffa6u32.wrapping_sub(base);c.r[0]=CrtValue::scalar(relative);c.r[1]=CrtValue::Pointer(rt.offset(p,i64::from(25+index)).unwrap());let input=c.r;
 assert_eq!(number(&mut rt,&mut c),Ok(CrtValue::scalar(index.wrapping_sub(65))));assert!(CrtCpu::pointer(c.r[0]).is_err());for r in 1..8{assert_eq!(c.r[r],input[r]);}
 let sum=u64::from(relative)+u64::from(addr);let out=sum as u32;assert_eq!(c.flags.cf,Some(sum>u64::from(u32::MAX)));assert_eq!(c.flags.zf,Some(out==0));assert_eq!(c.flags.sf,Some(out&0x80000000!=0));assert_eq!(c.flags.of,Some((!(relative^addr)&(relative^out)&0x80000000)!=0));
 rt.memory.release(p.cap,p.owner).unwrap();c.r[0]=input[0];let old=c.r;let flags=c.flags;assert_eq!(number(&mut rt,&mut c),Err("CRT pointer lifetime"));assert_eq!(c.r,old);assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(flags.cf,flags.zf,flags.sf,flags.of));
}
#[inline(never)] fn no_authority(){
 let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0xa000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,2048).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(77)).unwrap();let mut c=CrtCpu::new(sp,77).unwrap();let src=rt.map_region(0x20000,544,CrtRegionKind::Stack,None).unwrap();let other=rt.map_region(0x30000,4,CrtRegionKind::Stack,Some(&[71,0,0,0])).unwrap();c.r[0]=CrtValue::scalar(other.address()-src.address());c.r[1]=CrtValue::Pointer(src);assert_eq!(number(&mut rt,&mut c),Ok(CrtValue::scalar(other.address())));assert_eq!(c.address(&rt,Some(0),None,1,0,None),Err("CRT scalar address lacks provenance"));assert_eq!(rt.load(other,32).unwrap(),CrtValue::scalar(71));c.r[0]=CrtValue::Scalar{bits:0,known:0};c.r[1]=CrtValue::scalar(0);let old=c.r;let flags=c.flags;assert_eq!(number(&mut rt,&mut c),Err("CRT unknown scalar bits observed"));assert_eq!(c.r,old);assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(flags.cf,flags.zf,flags.sf,flags.of));
}
let mut checked=0;for base in [0x20000u32,0x41000,0x70000000]{for index in [0u32,64,65,90,97,122,255]{vector(base,index);checked+=1;}}assert_eq!(checked,21);no_authority();
"#,
        "numeric-address-authority",
    );
}
