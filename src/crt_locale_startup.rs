//! Original locale/PTD, aligned reference and code-page execution.
//! Shared publication and exceptional/free effects retain explicit boundaries.
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
            Ok(match target{Target::Direct(0x40a2ef)=>format!("cpu.call_activation(rt,{next},0,|rt,c|locale_required_ptd(rt,c,inputs,platform,epoch))?;"),Target::Direct(0x40b235)=>format!("cpu.call_activation(rt,{next},0,|rt,c|locale_aligned_prefix(rt,c,inputs,platform,epoch))?;"),_=>return Err("locale callback unexpected target".into())})
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
    let prefix = crate::crt_ptd::raw(ALIGNED_FRAME);
    let body = crate::crt_aligned_activation::prefix(&prefix, 0x40b235)?;
    let caller_bytes = crate::crt_ptd::raw("ff7308e855fdffff");
    let caller_graph = crate::crt_startup_table::graph(&caller_bytes, 0x40b25f)?;
    let caller_body = crate::crt_stream_emit::emit_body_with_exit(
        &caller_graph,
        |pc, t| {
            if t != Target::Direct(0x40afbc) {
                return Err("locale caller target".into());
            }
            Ok(format!("cpu.call_activation(rt,{},0,|rt,c|locale_code_page_original(rt,c,inputs,platform))?;",pc+caller_graph.nodes[&pc].length))
        },
        &Default::default(),
        32,
        |_, _| Err("locale caller thread effect".into()),
        |_, _| Ok(String::new()),
        |_, _| Ok(None),
        Some(caller_graph.end),
    )?;
    let init_call_bytes = crate::crt_ptd::raw(crate::crt_locale_code_page::INITIALIZER_CALL);
    let init_call_graph = crate::crt_locale_code_page::initializer_call_graph()?;
    let init_call_body = crate::crt_stream_emit::emit_body_with_exit(
        &init_call_graph,
        |pc, target| {
            if target != Target::Direct(0x40b485) {
                return Err("locale initializer caller target".into());
            }
            Ok(format!("cpu.call_activation(rt,{},0,|rt,c|locale_multibyte_original(rt,c,inputs,platform))?;",pc+init_call_graph.nodes[&pc].length))
        },
        &Default::default(),
        1,
        |_, _| Err("locale initializer caller thread effect".into()),
        |_, _| Ok(String::new()),
        |_, _| Ok(None),
        Some(init_call_graph.end),
    )?;
    out.push_str(&format!("fn locale_aligned_prefix(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;let p=rt.process_image_code(inputs.image,0x40b235,{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"locale aligned code read\")?!=&{prefix:?}{{return Err(\"locale aligned code changed\");}}let mut aligned=CrtAlignedActivation::begin(rt,cpu)?;let _=(||->Result<CrtValue,&'static str>{{{body}}})()?;aligned.live(rt,cpu)?;cpu.tick(u32::MAX)?;cpu.call_activation(rt,0x40b25f,0,|rt,c|locale_reference_original(rt,c,inputs,epoch))?;aligned.live(rt,cpu)?;let caller=rt.process_image_code(inputs.image,0x40b25f,8)?;if rt.memory.read(caller.address(),8).map_err(|_|\"locale caller code read\")?!=[255,115,8,232,85,253,255,255]{{return Err(\"locale code-page caller changed\");}}let _=(||->Result<CrtValue,&'static str>{{{caller_body}}})()?;aligned.live(rt,cpu)?;let value=locale_selected_caller(rt,cpu,inputs,&mut aligned)?;if cpu.returned{{return Ok(value);}}aligned.live(rt,cpu)?;let value=locale_allocated_copy_original(rt,cpu,inputs,&mut aligned)?;if cpu.returned{{return Ok(value);}}aligned.live(rt,cpu)?;let q=rt.process_image_code(inputs.image,0x40b2c7,5)?;if rt.memory.read(q.address(),5).map_err(|_|\"locale initializer caller read\")?!=&{init_call_bytes:?}{{return Err(\"locale initializer code changed\");}}let _=(||->Result<CrtValue,&'static str>{{{init_call_body}}})()?;aligned.live(rt,cpu)?;let bp=CrtCpu::pointer(cpu.r[5])?;let allocation=CrtCpu::pointer(rt.load(rt.offset(bp,-4)?,32)?)?;locale_result_original(rt,cpu,inputs,platform,&mut aligned,allocation)}}",prefix.len(),prefix.len()));
    out.push_str(&reference_source()?);
    out.push_str(&crate::crt_locale_code_page::source()?);
    out.push_str(&crate::crt_malloc::source()?);
    out.push_str(&selected_source()?);
    out.push_str(&result_source()?);
    out.push_str(&crate::crt_repeat_copy::source()?);
    Ok(out)
}

pub(crate) const ALIGNED_FRAME: &str =
    "8bff538bdc515183e4f883c404558b6b04896c24048bec81ec380200005657ff7314ff7310";
pub(crate) const SELECTED_CALLER: &str =
    "8b4b1083c40c8945f48b49483b4104750733c0e9020100006820020000e8a7d4ffff";
pub(crate) const FAST_EPILOG: &str = "5f5e8be55d8be35bc3";

pub(crate) const RESULT_CALLER:&str="8bf883ceff59593bfe751be8f1c9ffffc700160000008b45fc50e865caffff8bc6e98e000000807b0c007505e829beffff8b43108b4048f00fc1304e75158b431081784840c241007409ff7048e832caffff598b45fcc700010000008b4b108941488b4b10a1b8c7410085815003000075398d43108945ec8d4dfb6a058d43148945f0588945f48945fc8d45f4508d45ec508d45fc50e847fbffff807b0c00740a8b43148b00a334c241006a00e8d2c9ffff8bc7595f5e8be55d8be35bc3";
pub(crate) const FREE_BODY:&str="8bff558bec837d0800742dff75086a00ff35c8d24100ff159850410085c0751856ff154450410050e895feffff598bf0e848ffffff89305e5dc3";
pub(crate) const MULTIBYTE_FLAG: &str = "33c0b97cce4100408701c3";

fn initializing_atomic_effect(_: u32, op: &crate::crt_stream_ir::Op) -> Result<String, String> {
    let crate::crt_stream_ir::Op::InitializingAtomic {
        destination: crate::graph::Operand::Memory(a, 32),
        source,
        add,
    } = op
    else {
        return Err("locale unbound thread effect".into());
    };
    let address = crate::crt_stream_emit::address(a, &Default::default())?;
    Ok(format!(
        "let p={address};cpu.exchange_initializing_scalar(rt,inputs.init,inputs.image,p,{},{} )?;",
        source.index, add
    ))
}

fn result_source() -> Result<String, String> {
    let bytes = crate::crt_ptd::raw(RESULT_CALLER);
    let mut graph = Graph::decode(&bytes, 0x40b2cc)?;
    graph.initializing_atomic(0x40b303)?;
    let body = crate::crt_stream_emit::emit_body_with_hooks(
        &graph,
        |pc, t| {
            let next = pc + graph.nodes[&pc].length;
            Ok(match t{
            Target::Direct(0x407126)=>format!("cpu.call_activation(rt,{next},0,|rt,c|locale_multibyte_flag_original(rt,c,inputs))?;"),
            Target::Direct(0x407d50)=>format!("cpu.call_activation(rt,{next},0,|rt,c|locale_free_original(rt,c,inputs))?;"),
            Target::Direct(0x407ccd)=>"return Err(\"locale initializer failure errno effect unbound\");".into(),
            Target::Direct(0x40aeae)=>"return Err(\"locale shared publication EH4 effect unbound at 0x40b362\");".into(),
            _=>return Err(format!("locale result unexpected call {pc:x} {t:?}")),
        })
        },
        &std::collections::BTreeMap::from([
            (0x41c7b8, "CrtRegionKind::Module".into()),
            (0x41c234, "CrtRegionKind::Module".into()),
        ]),
        512,
        initializing_atomic_effect,
        |pc, _| {
            Ok(match pc{
            0x40b300|0x40b30d|0x40b32b=>"locale_required_view(rt,platform,cpu.r[if pc==0x40b32b{1}else{0}])?;".into(),
            0x40b303=>"let p=rt.initializing_scalar_pointer(inputs.init,inputs.image,cpu.r[0])?;if p.cap==allocation.cap{return Err(\"locale result new/old allocation alias\");}cpu.r[0]=CrtValue::Pointer(p);".into(),
            0x40b322=>"if cpu.r[0]!=CrtValue::Pointer(allocation){return Err(\"locale result allocation changed\");}rt.valid(allocation,544)?;".into(),
            _=>String::new(),
        })
        },
        |_, pop| {
            if pop != 0 {
                return Err("locale result RET cleanup".into());
            }
            Ok(Some("return aligned.finish(rt,cpu);".into()))
        },
    )?;
    let flag = crate::crt_ptd::raw(MULTIBYTE_FLAG);
    let mut fg = Graph::decode(&flag, 0x407126)?;
    fg.initializing_atomic(0x40712e)?;
    let fb = crate::crt_stream_emit::emit_body_with_hooks(
        &fg,
        |_, _| Err("locale flag call".into()),
        &Default::default(),
        32,
        initializing_atomic_effect,
        |pc, _| {
            Ok(if pc == 0x40712e {
                "cpu.r[1]=CrtValue::Pointer(rt.module_word_pointer(inputs.image,cpu.r[1])?);".into()
            } else {
                String::new()
            })
        },
        |_, _| Ok(None),
    )?;
    let free = crate::crt_ptd::raw(FREE_BODY);
    let free_body = crate::crt_stream_emit::emit_body(
        &Graph::decode(&free, 0x407d50)?,
        |_, _| Ok("return Err(\"locale nonnull free API/errno effect unbound\");".into()),
        &std::collections::BTreeMap::from([(0x41d2c8, "CrtRegionKind::Module".into())]),
        256,
    )?;
    Ok(format!(
        r#"
fn locale_multibyte_flag_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,0x407126,{fl})?;if rt.memory.read(p.address(),{fl}).map_err(|_|"locale flag code read")?!=&{flag:?}{{return Err("locale flag code changed");}}{fb}}}
fn locale_free_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,0x407d50,{zl})?;if rt.memory.read(p.address(),{zl}).map_err(|_|"locale free code read")?!=&{free:?}{{return Err("locale free code changed");}}{free_body}}}
fn locale_result_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform,aligned:&mut CrtAlignedActivation,allocation:CrtPointer)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;platform.validate(rt,inputs.init)?;aligned.live(rt,cpu)?;let p=rt.process_image_code(inputs.image,0x40b2cc,{bl})?;if rt.memory.read(p.address(),{bl}).map_err(|_|"locale result code read")?!=&{bytes:?}{{return Err("locale result code changed");}}aligned.claim_continuation(rt,cpu,0x40b2cc)?;if allocation.kind!=CrtRegionKind::Buffer||allocation.address()!=allocation.base||allocation.size!=544||!rt.regions.iter().any(|r|r.pointer==allocation&&r.heap&&r.file_owner.is_none()){{return Err("locale result whole allocation identity");}}rt.valid(allocation,544)?;let bp=CrtCpu::pointer(cpu.r[5])?;if rt.load(rt.offset(bp,-4)?,32)?!=CrtValue::Pointer(allocation){{return Err("locale result local allocation changed");}}{body}}}
"#,
        fl = flag.len(),
        zl = free.len(),
        bl = bytes.len()
    ))
}

#[test]
fn initializing_atomics_require_effect_binding_and_preserve_identity_flags_and_failure() {
    assert_eq!(FREE_BODY, crate::crt_heap_free::FREE);
    let mut snippets = String::new();
    for (name, raw) in [
        ("swap", &[0x87, 0x01][..]),
        ("add", &[0xf0, 0x0f, 0xc1, 0x01][..]),
    ] {
        let mut g = Graph::decode_linear_fragment(raw, 0x1000).unwrap();
        g.initializing_atomic(0x1000).unwrap();
        assert!(g.initializing_atomic(0x1000).is_err());
        assert!(crate::crt_stream_emit::emit_linear_fragment(&g, &Default::default()).is_err());
        let body = crate::crt_stream_emit::emit_body_with_exit(
            &g,
            |_, _| Err("no call".into()),
            &Default::default(),
            1,
            |_, op| {
                let crate::crt_stream_ir::Op::InitializingAtomic {
                    destination: crate::graph::Operand::Memory(a, 32),
                    source,
                    add,
                } = op
                else {
                    panic!()
                };
                Ok(format!(
                    "let p={};cpu.exchange_initializing_scalar(rt,init,image,p,{},{} )?;",
                    crate::crt_stream_emit::address(a, &Default::default())?,
                    source.index,
                    add
                ))
            },
            |_, _| Ok(String::new()),
            |_, _| Ok(None),
            Some(g.end),
        )
        .unwrap();
        snippets.push_str(&format!("fn atomic_{name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,image:CrtProcessImage)->Result<CrtValue,&'static str>{{{body}}}"));
    }
    for raw in [
        &[0x87, 0xc1][..],
        &[0x89, 0x01],
        &[0x66, 0x87, 0x01],
        &[0xf0, 0x0f, 0xc1, 0x21],
    ] {
        if let Ok(mut g) = Graph::decode_linear_fragment(raw, 0x1000) {
            assert!(g.initializing_atomic(0x1000).is_err());
        }
    }
    crate::crt_stream_callees_tests::native_bounded_stack(
        &snippets,
        r#"
for add in [false,true]{for mode in 0..13{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let image=rt.bootstrap_main_image(init,0x400000,&[1;4096]).unwrap();let CrtValue::Heap(h)=rt.native_process_heap(init).unwrap()else{panic!()};let word=rt.native_heap_allocate(init,h,8,16).unwrap();rt.store(word,32,CrtValue::scalar(0xffffffff)).unwrap();
 let stack=rt.map_region(0xa000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(77)).unwrap();let mut c=CrtCpu::new(sp,77).unwrap();c.r[0]=CrtValue::scalar(2);c.r[1]=CrtValue::Pointer(word);c.flags=CrtFlags{cf:Some(false),zf:Some(true),sf:Some(false),of:Some(true)};let mut supplied=image;
 if mode==1{rt.memory.release(word.cap,word.owner).unwrap();}if mode==2{rt.end_initialization(init).unwrap();}if mode==3{rt.store(word,32,CrtValue::Scalar{bits:0,known:0}).unwrap();}if mode==4{rt.store(word,32,CrtValue::Pointer(stack)).unwrap();}if mode==5{c.r[1]=CrtValue::Pointer(rt.offset(word,4).unwrap());}if mode==6{c.r[1]=CrtValue::Pointer(image.root);}if mode==7{c.r[0]=CrtValue::Scalar{bits:0,known:0};}if mode==8{rt.thread+=1;}if mode==9{c.r[1]=CrtValue::scalar(word.address());}if mode==10{c.r[1]=CrtValue::Pointer(rt.offset(word,1).unwrap());}if mode==11{supplied.generation+=1;}if mode==12{c.r[1]=CrtValue::Pointer(rt.subrange(word,4).unwrap());}
 let before=c.r;let flags=c.flags;let memory=rt.memory.read(word.address(),16).map(|b|b.to_vec());rt.last_os_error=Some(71);
 let result=if add{atomic_add(&mut rt,&mut c,init,supplied)}else{atomic_swap(&mut rt,&mut c,init,supplied)};
 if mode==0{assert_eq!(result,Ok(CrtValue::scalar(0xffffffff)));assert_eq!(c.r[0],CrtValue::scalar(0xffffffff));assert_eq!(rt.load(word,32).unwrap(),CrtValue::scalar(if add{1}else{2}));assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),if add{(Some(true),Some(false),Some(false),Some(false))}else{(flags.cf,flags.zf,flags.sf,flags.of)});}
 else{let expected=match mode{1=>"CRT pointer lifetime",2|8=>"CRT initialization owner/lifetime",3|4|7=>"CRT scalar knowledge/type",5|12=>"CRT initializing whole buffer word",6=>"CRT initializing scalar permission",9=>"CRT scalar address lacks provenance",10=>"CRT initializing scalar word alignment",11=>"CRT process image owner/lifetime",_=>unreachable!()};assert_eq!(result,Err(expected),"atomic add{add} mode{mode}");assert_eq!(c.r,before);assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(flags.cf,flags.zf,flags.sf,flags.of));assert_eq!(rt.memory.read(word.address(),16).map(|b|b.to_vec()),memory);}
 assert_eq!(rt.last_os_error,Some(71));
}}
"#,
        "initializing-scalar-atomic",
    );
}

fn selected_source() -> Result<String, String> {
    let bytes = crate::crt_ptd::raw(SELECTED_CALLER);
    let tail = crate::crt_ptd::raw(FAST_EPILOG);
    let mut g = crate::crt_startup_table::graph(&bytes, 0x40b267)?;
    // These are actual disjoint instruction ranges and the actual fast-branch
    // target. The slow continuation is an explicit internal fragment boundary.
    g.nodes.extend(Graph::decode(&tail, 0x40b381)?.nodes);
    let body = crate::crt_stream_emit::emit_body_with_exit(
        &g,
        |pc, t| {
            if t != Target::Direct(0x408730) {
                return Err("locale selected caller target".into());
            }
            Ok(format!(
                "cpu.call_activation(rt,{},0,|rt,c|malloc_original_native(rt,c,inputs))?;",
                pc + g.nodes[&pc].length
            ))
        },
        &Default::default(),
        128,
        |_, _| Err("locale selected caller thread effect".into()),
        |pc, _| {
            Ok(if pc == 0x40b273 {
                "cpu.r[1]=CrtValue::Pointer(rt.module_word_pointer(inputs.image,cpu.r[1])?);".into()
            } else {
                String::new()
            })
        },
        |_, pop| {
            if pop != 0 {
                return Err("locale aligned RET cleanup".into());
            }
            Ok(Some("return aligned.finish(rt,cpu);".into()))
        },
        Some(g.end),
    )?;
    Ok(format!("fn locale_selected_caller(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,aligned:&mut CrtAlignedActivation)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;aligned.live(rt,cpu)?;for(address,bytes)in[(0x40b267u32,&{bytes:?}[..]),(0x40b381,&{tail:?}[..])]{{let p=rt.process_image_code(inputs.image,address,bytes.len()as u32)?;if rt.memory.read(p.address(),bytes.len()as u32).map_err(|_|\"locale selected caller code read\")?!=bytes{{return Err(\"locale selected caller code changed\");}}}}{body}}}"))
}
#[cfg(test)]
const ALIGNED_EPILOG: &str = "8be55d8be35bc3";

#[test]
fn original_aligned_frame_keeps_unique_return_authority() {
    let bytes = crate::crt_ptd::raw(ALIGNED_FRAME);
    let prefix = crate::crt_aligned_activation::prefix(&bytes, 0x40b235).unwrap();
    let epilog = crate::crt_ptd::raw(ALIGNED_EPILOG);
    let graph = Graph::decode(&epilog, 0x40b383).unwrap();
    let tail = crate::crt_stream_emit::emit_body_with_hooks(
        &graph,
        |_, _| Err("epilog call".into()),
        &Default::default(),
        32,
        |_, _| Err("epilog FS".into()),
        |_, _| Ok(String::new()),
        |_, pop| {
            assert_eq!(pop, 0);
            Ok(Some("return aligned.finish(rt,cpu);".into()))
        },
    )
    .unwrap();
    let mut small = bytes.clone();
    small[25..29].copy_from_slice(&32u32.to_le_bytes());
    let small = crate::crt_aligned_activation::prefix(&small, 0x1000).unwrap();
    let extra = format!(
        r#"
fn original_prefix(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,aligned:&mut CrtAlignedActivation,small:bool)->Result<CrtValue,&'static str>{{if small{{{small}}}else{{{prefix}}}}}
fn original_epilog(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,aligned:&mut CrtAlignedActivation)->Result<CrtValue,&'static str>{{{tail}}}
// An independent declared body for frame/return conformance, not locale work.
fn frame(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,depth:u32,small:bool)->Result<CrtValue,&'static str>{{
 let mut aligned=CrtAlignedActivation::begin(rt,cpu)?;
 original_prefix(rt,cpu,&mut aligned,small)?;aligned.live(rt,cpu)?;
 let mirror=aligned.mirror.unwrap();assert_eq!(rt.load(mirror,32)?,CrtValue::scalar(aligned.pc));assert!(CrtCpu::pointer(rt.load(mirror,32)?).is_err());
 assert_eq!(rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(cpu.return_id)).count(),1);
 if depth>0{{for i in 0..4{{cpu.push(rt,CrtValue::scalar(i))?;}}cpu.call_activation(rt,0x123400+depth,0,|rt,child|{{assert!(aligned.live(rt,child).is_err());frame(rt,child,depth-1,!small)}})?;cpu.discard(rt,16)?;aligned.live(rt,cpu)?;}}
 cpu.discard(rt,8)?;cpu.r[7]=cpu.pop(rt)?;cpu.r[6]=cpu.pop(rt)?;
 let value=original_epilog(rt,cpu,&mut aligned)?;assert!(aligned.live(rt,cpu).is_err());assert!(aligned.finish(rt,cpu).is_err());Ok(value)
}}
"#
    );
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
for offset in [8192,8196]{for small in [false,true]{
 let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0xa000,16384,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,offset).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(99)).unwrap();let mut c=CrtCpu::new(sp,99).unwrap();c.clobber(CrtValue::scalar(71));
 assert!(CrtAlignedActivation::begin(&rt,&c).is_err());
 for n in 1..=4{c.push(&mut rt,CrtValue::scalar(n)).unwrap();}
 let original=c.r;let result=c.call_activation(&mut rt,0x40b465,0,|rt,child|frame(rt,child,2,small));
 assert_eq!(result,Ok(CrtValue::scalar(71)));assert_eq!(c.r,original);c.discard(&mut rt,16).unwrap();assert_eq!(c.finish(&mut rt),Ok(CrtValue::scalar(71)));assert!(rt.tags.values().all(|v|!matches!(v,CrtValue::ProtectedReturn(_))));
}}
// Independent malformed/lifetime cases: no successful-return fallback.
for mode in 0..18{
 let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0xa000,16384,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,8192).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(99)).unwrap();let mut c=CrtCpu::new(sp,99).unwrap();c.clobber(CrtValue::scalar(71));for n in 1..=4{c.push(&mut rt,CrtValue::scalar(n)).unwrap();}
 let result=c.call_activation(&mut rt,0x1005,0,|rt,cpu|{
  let mut aligned=CrtAlignedActivation::begin(rt,cpu).expect("negative fixture begins with actual CALL authority");original_prefix(rt,cpu,&mut aligned,false).expect("negative fixture prefix must execute");aligned.live(rt,cpu).expect("negative fixture starts live");let mirror=aligned.mirror.unwrap();let entry=aligned.entry;
  match mode{
   0=>{rt.store(mirror,32,CrtValue::scalar(0x1006))?;aligned.live(rt,cpu)?;},
   1=>{rt.tags.remove(&entry.address());rt.store(entry,32,CrtValue::scalar(aligned.pc))?;aligned.live(rt,cpu)?;},
   2=>{rt.memory.release(entry.cap,entry.owner).unwrap();aligned.live(rt,cpu)?;},
   3=>{cpu.return_site=Some((cpu.return_id+1,aligned.pc));aligned.live(rt,cpu)?;},
   4=>{aligned.copy_return(rt,cpu,mirror,CrtValue::ProtectedReturn(cpu.return_id))?;},
   5=>{cpu.return_site=None;aligned.live(rt,cpu)?;},
   6=>{let other=rt.map_region(0x10000,4096,CrtRegionKind::Stack,None)?;let mut fresh=CrtAlignedActivation{anchor:rt.anchor,thread:rt.thread,fiber:rt.fiber,entry,identity:cpu.return_id,pc:aligned.pc,mirror:None,done:false};fresh.copy_return(rt,cpu,other,CrtValue::ProtectedReturn(cpu.return_id))?;},
   7=>{let mut fresh=CrtAlignedActivation{anchor:rt.anchor,thread:rt.thread,fiber:rt.fiber,entry,identity:cpu.return_id,pc:aligned.pc,mirror:None,done:false};fresh.copy_return(rt,cpu,entry,CrtValue::ProtectedReturn(cpu.return_id))?;},
   8=>{let mut fresh=CrtAlignedActivation{anchor:rt.anchor,thread:rt.thread,fiber:rt.fiber,entry,identity:cpu.return_id,pc:aligned.pc,mirror:None,done:false};fresh.copy_return(rt,cpu,mirror,CrtValue::scalar(aligned.pc))?;},
   9=>{let failed=cpu.call_activation(rt,0x2000,0,|rt,child|{child.push(rt,CrtValue::scalar(42))?;Err("unproved child unwind")});assert_eq!(failed,Err("unproved child unwind"));assert_eq!(rt.load(CrtCpu::pointer(cpu.r[4])?,32)?,CrtValue::scalar(42));aligned.live(rt,cpu)?;},
   10=>{cpu.discard(rt,8)?;cpu.r[7]=cpu.pop(rt)?;cpu.r[6]=cpu.pop(rt)?;cpu.r[6]=CrtValue::scalar(0);return original_epilog(rt,cpu,&mut aligned);},
   11=>{rt.store(rt.offset(entry,-600)?,32,CrtValue::scalar(55))?;let failed:Result<(),&str>=Err("unproved nonlocal cleanup");assert!(failed.is_err());assert_eq!(rt.load(rt.offset(entry,-600)?,32)?,CrtValue::scalar(55));return Err("unproved nonlocal cleanup");},
   12=>{rt.thread+=1;aligned.live(rt,cpu)?;},
   13=>{let (other,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();aligned.live(&other,cpu)?;},
   14=>{rt.bind_fiber(rt.thread)?;aligned.live(rt,cpu)?;},
   15=>{cpu.r[4]=CrtValue::Pointer(mirror);return aligned.finish(rt,cpu);},
   16=>{cpu.discard(rt,8)?;cpu.r[7]=cpu.pop(rt)?;cpu.r[6]=cpu.pop(rt)?;cpu.r[3]=CrtValue::Pointer(rt.offset(entry,-32)?);return original_epilog(rt,cpu,&mut aligned);},
   17=>{rt.memory.release(rt.anchor,rt.file_view.owner).unwrap();aligned.live(rt,cpu)?;},
   _=>unreachable!()
  }
  panic!("negative aligned mode {mode} unexpectedly continued");
 });let expected=match mode{0=>"CRT aligned return mirror changed",1=>"CRT active caller lifetime/return authority",2=>"CRT pointer lifetime",3|5|9|12|13|14=>"CRT aligned activation lifetime",4|6|7|8=>"CRT aligned return copy authority/range",10=>"CRT callee saved restoration",11=>"unproved nonlocal cleanup",15|16=>"CRT caller stack identity",17=>"CRT aligned runtime lifetime",_=>unreachable!()};assert_eq!(result,Err(expected),"negative aligned mode {mode}");assert!(!c.returned);
}
// Insufficient local extent fails after, not before, the original mirror store.
{
 let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0xa000,128,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,96).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(99)).unwrap();let mut c=CrtCpu::new(sp,99).unwrap();c.clobber(CrtValue::scalar(71));for n in 1..=4{c.push(&mut rt,CrtValue::scalar(n)).unwrap();}
 let result=c.call_activation(&mut rt,0x3005,0,|rt,child|{let mut aligned=CrtAlignedActivation::begin(rt,child)?;original_prefix(rt,child,&mut aligned,false)});assert_eq!(result,Err("CRT pointer complete range/identity"));assert!(!c.returned);let bp=CrtCpu::pointer(c.r[5]).unwrap();assert_eq!(rt.load(rt.offset(bp,4).unwrap(),32).unwrap(),CrtValue::scalar(0x3005));let source=rt.load(rt.offset(CrtCpu::pointer(c.r[3]).unwrap(),4).unwrap(),32).unwrap();assert!(matches!(source,CrtValue::ProtectedReturn(_)));assert_eq!(rt.tags.values().filter(|&&v|v==source).count(),1);
}
// Alignment retains only existing, live, in-range stack capabilities.
let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0xa004,4096,CrtRegionKind::Stack,None).unwrap();let mut c=CrtCpu::new(stack,99).unwrap();
assert!(c.binary(&rt,4,CrtValue::Pointer(stack),CrtValue::scalar(!7),32).is_err());
let p=rt.offset(stack,16).unwrap();let aligned=c.binary(&rt,4,CrtValue::Pointer(p),CrtValue::scalar(!7),32).unwrap();assert_eq!(CrtCpu::pointer(aligned).unwrap(),rt.offset(p,-4).unwrap());assert_eq!((c.flags.cf,c.flags.of,c.flags.zf,c.flags.sf),(Some(false),Some(false),Some(false),Some(false)));
assert!(matches!(c.binary(&rt,4,CrtValue::scalar(p.address()),CrtValue::scalar(!7),32).unwrap(),CrtValue::Scalar{..}));
assert!(matches!(c.binary(&rt,4,CrtValue::Pointer(p),CrtValue::scalar(0xffff_fffa),32).unwrap(),CrtValue::Scalar{..}));
assert!(matches!(c.binary(&rt,4,CrtValue::Pointer(p),CrtValue::Scalar{bits:!7,known:!1},32).unwrap(),CrtValue::Scalar{..}));
assert!(matches!(c.binary(&rt,4,CrtValue::Pointer(p),CrtValue::scalar(!7),16).unwrap(),CrtValue::Scalar{..}));
rt.store(rt.offset(p,-4).unwrap(),32,CrtValue::ProtectedReturn(123)).unwrap();assert_eq!(c.binary(&rt,4,CrtValue::Pointer(p),CrtValue::scalar(!7),32),Err("CRT alignment crosses protected stack"));rt.memory.release(stack.cap,stack.owner).unwrap();assert!(c.binary(&rt,4,CrtValue::Pointer(p),CrtValue::scalar(!7),32).is_err());
"#,
        "aligned-return-authority",
    );
}

pub(crate) const REFERENCE_BODY:&str="6a0c6860b64100e8ca6affff33f68975e48b7d08a1b8c74100858750030000740e39774c74098b774885f6746deb596a05e80f0a0000598975fc8b77488975e48b5d0c3b33742785f6741883c8fff00fc106750f81fe40c24100740756e864c9ffff598b338977488975e4f0ff06c745fcfeffffffe805000000ebad8b75e46a05e8070a000059c38bc68b4df064890d00000000595f5e5bc9c3e8d6c3ffffcc";

fn reference_source() -> Result<String, String> {
    let raw = crate::crt_ptd::raw;
    let helper = raw(crate::crt_ucrt_locale::PROLOG);
    let p = crate::crt_exception_wrapper::PrologProof::prove(
        crate::crt_exception_wrapper::Region {
            bytes: &helper,
            origin: 0x401e60,
        },
        12,
        0x41b660,
        0x41c000,
        0x402210,
    )?;
    let eb = raw("8b4df064890d00000000595f5e5bc9c3");
    let ep = crate::crt_exception_wrapper::EpilogProof::prove(
        crate::crt_exception_wrapper::Region {
            bytes: &eb,
            origin: 0x40b414,
        },
        &p,
    )?;
    let mut out = format!(
        "{}{}",
        p.emit("locale_reference_prolog")?,
        ep.emit("locale_reference_epilog")?
    );
    let bytes = raw(REFERENCE_BODY);
    let g = crate::crt_startup_table::graph(&bytes[..bytes.len() - 1], 0x40b38a)?;
    let cleanup = bytes[0x7f..0x88].to_vec();
    let cg = Graph::decode(&cleanup, 0x40b409)?;
    let cb = crate::crt_stream_emit::emit_body(
        &cg,
        |pc, t| {
            if t != Target::Direct(0x40be17) {
                return Err("reference cleanup target".into());
            }
            let next = pc + cg.nodes[&pc].length;
            Ok(format!("cpu.call_activation(rt,{next},0,|rt,c|startup_second_lock(rt,c,inputs,false,held))?;"))
        },
        &Default::default(),
        64,
    )?;
    out.push_str(&format!("fn locale_reference_cleanup(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,held:&mut Option<CrtGlobalLock>)->Result<CrtValue,&'static str>{{{cb}}}"));
    let body = crate::crt_stream_emit::emit_body_with_exit(
        &g,
        |pc, t| {
            let next = pc + g.nodes[&pc].length;
            Ok(match t{
 Target::Direct(0x401e60)=>"let id=rt.generation.checked_add(1).filter(|n|*n<1u64<<63).ok_or(\"reference helper identity\")?|(1u64<<63);if rt.tags.values().any(|v|*v==CrtValue::ProtectedReturn(id)){return Err(\"reference helper collision\");}rt.generation=id&!(1u64<<63);cpu.push(rt,CrtValue::ProtectedReturn(id))?;locale_reference_prolog(rt,cpu,id,b.token,|rt,c,record,head|b.install(rt,c,epoch,record,head))?;".into(),
 Target::Direct(0x40bdcf)=>format!("cpu.call_activation(rt,{next},0,|rt,c|startup_second_lock(rt,c,inputs,true,&mut held))?;"),
 Target::Direct(0x40b409)=>format!("cpu.call_activation(rt,{next},0,|rt,c|locale_reference_cleanup(rt,c,inputs,&mut held))?;"),
 Target::Direct(0x407d50)=>"return Err(\"locale reference free effect unbound\");".into(),
 Target::Direct(0x4077ff)=>"return Err(\"locale reference null termination unbound\");".into(),
 Target::Direct(0x40be17)=>"return Err(\"reference inline cleanup requires owned call\");".into(),
 _=>return Err(format!("reference helper call {pc:x} {t:?}"))})
        },
        &std::collections::BTreeMap::from([(0x41c7b8, "CrtRegionKind::Module".into())]),
        512,
        |pc, op| {
            use crate::crt_stream_ir::Op;
            match op{
 Op::LockedExchangeAdd{destination:crate::graph::Operand::Memory(a,32),source} if pc==0x40b3d8=>{let address=crate::crt_stream_emit::address(a,&Default::default())?;Ok(format!("b.authority(rt,epoch)?;let lease=held.ok_or(\"locale reference lock missing\")?;let pointer={address};cpu.exchange_add_reference(rt,inputs.init,inputs.image,lease,pointer,{})?;",source.index))},
 Op::LockedIncrement(_) if pc==0x40b3f5=>Ok("b.authority(rt,epoch)?;let lease=held.ok_or(\"locale reference lock missing\")?;let pointer=rt.module_word_pointer(inputs.image,cpu.r[6])?;cpu.increment_reference(rt,inputs.init,inputs.image,lease,pointer)?;".into()),
 _=>Ok("return Err(\"reference unresolved thread effect\");".into())}
        },
        |pc, _| {
            let mut code = String::new();
            if pc == 0x40b414 {
                code.push_str("if held.is_some(){return Err(\"reference epilog lock still held\");}return locale_reference_epilog(rt,cpu,epoch,&mut b);");
            }
            if matches!(pc, 0x40b3d8 | 0x40b3cd) {
                let reg = if pc == 0x40b3d8 { 6 } else { 3 };
                code.push_str(&format!("cpu.r[{reg}]=CrtValue::Pointer(rt.module_word_pointer(inputs.image,cpu.r[{reg}])?);"));
            }
            Ok(code)
        },
        |_, _| Ok(None),
        Some(g.end),
    )?;
    let terminal = format!("if pc=={}{{return Ok(cpu.r[0]);}}", g.end);
    if !body.contains(&terminal) {
        return Err("reference terminal missing".into());
    }
    let body = body.replace(
        &terminal,
        &format!(
            "if pc=={}{{return Err(\"reference terminal trap\");}}",
            g.end
        ),
    );
    out.push_str(&format!("fn locale_reference_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let sp=CrtCpu::pointer(cpu.entry[4])?;let arg=rt.load(rt.offset(sp,4)?,32)?;let pointer=CrtCpu::pointer(arg)?;let view=rt.heap_ptds.iter().find(|v|v.pointer==pointer&&v.layout==CrtPtdLayout::Ucrt).ok_or(\"reference UCRT allocation view\")?;rt.heap_ptd_layout_view(pointer,view.slot,CrtPtdLayout::Ucrt)?;if rt.fls.get(&view.slot.index).map(|x|x.1)!=Some(arg){{return Err(\"reference UCRT publication\");}}for(address,expected)in[(0x40b38au32,&{bytes:?}[..]),(0x401e60,&{helper:?}[..])]{{let q=rt.process_image_code(inputs.image,address,expected.len()as u32)?;if rt.memory.read(q.address(),expected.len()as u32).map_err(|_|\"reference code read\")?!=expected{{return Err(\"locale reference code changed\");}}}}let mut b=CrtNormalBinding::bind_initializing(rt,cpu,epoch,locale_reference_epilog_layout(),inputs.init)?;let mut held=None;{body}}}"));
    Ok(out)
}
