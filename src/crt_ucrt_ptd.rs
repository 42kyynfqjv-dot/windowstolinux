//! Original UCRT lazy acquisition; distinct from the 40-byte dispatcher PTD.
use crate::crt_stream_ir::{Graph, Target};
pub(crate) const CALLOC: &str = "8bff558bec568b750885f6740c6ae033d258f7f63b450c72370faf750c33c04085f60f44f0eb14e8a4f4ffff85c0742056e89a4c00005985c07415566a08ff35c8d24100ff159450410085c074d9eb0de888ffffffc7000c00000033c05e5dc3";
pub(crate) const INIT: &str = "8bff558bec83ec148b450833c9416a438948188b4508c700f05e41008b45088988500300008b4508596a05c7404840c241008b45086689486c8b4508668988720100008d4dff8b450883a04c030000008d45088945f0588945f88945ec8d45f8508d45f0508d45ec50e826feffff8d45088945f48d4dff6a048d450c8945f8588945ec8945f08d45ec508d45f4508d45f050e80fffffffc9c3";

pub(crate) fn source() -> Result<String, String> {
    let mut out = String::new();
    let roles = std::collections::BTreeMap::from_iter(
        [0x41c170, 0x41d2c8, 0x41ce80].map(|a| (a, "CrtRegionKind::Module".into())),
    );
    let thunk = crate::crt_ptd::raw(crate::crt_ptd::SET_THUNK);
    let pre = crate::crt_stream_emit::emit_linear_fragment(
        &Graph::decode_linear_fragment(&thunk[..6], 0x40806d)?,
        &Default::default(),
    )?;
    for (name, hex, origin) in [
        ("ucrt_lazy_native", crate::crt_ptd::LAZY, 0x40a1ee),
        ("ucrt_calloc_native", CALLOC, 0x407cf0),
        ("ucrt_initialize_native", INIT, 0x40a067),
    ] {
        let bytes = crate::crt_ptd::raw(hex);
        let graph = Graph::decode(&bytes, origin)?;
        let body = crate::crt_stream_emit::emit_body(
            &graph,
            |pc, target| {
                let next = pc + graph.nodes[&pc].length;
                Ok(match target {
                Target::Import(0x415044) => format!("rt.process_image_import(inputs.image,0x415044,\"kernel32.dll\",\"GetLastError\")?;cpu.call_activation(rt,{next},0,|rt,c|{{c.clobber(rt.last_os_error.map(CrtValue::scalar).unwrap_or(CrtValue::Scalar{{bits:0,known:0}}));c.finish(rt)}})?;"),
                Target::Import(0x415048) => format!("rt.process_image_import(inputs.image,0x415048,\"kernel32.dll\",\"SetLastError\")?;cpu.call_activation(rt,{next},4,|rt,c|{{let sp=CrtCpu::pointer(c.r[4])?;let v=rt.load(rt.offset(sp,4)?,32)?;if !matches!(v,CrtValue::Scalar{{..}}){{return Err(\"UCRT LastError scalar\");}}rt.last_os_error=v.known_scalar().ok();c.clobber(CrtValue::Scalar{{bits:0,known:0}});c.finish_pop(rt,4)}})?;"),
                Target::Direct(0x40806d) => format!("let p=rt.process_image_code(inputs.image,0x40806d,12)?;if rt.memory.read(p.address(),12).map_err(|_|\"UCRT setter code read\")?!=&{thunk:?}{{return Err(\"UCRT setter code changed\");}}rt.process_image_import(inputs.image,0x4150a4,\"kernel32.dll\",\"FlsSetValue\")?;cpu.call_activation(rt,{next},8,|rt,cpu|{{let _=(||->Result<CrtValue,&'static str>{{{pre}}})()?;platform.fls_set_call(rt,cpu,inputs.init,platform.fls_set.ok_or(\"UCRT setter provider absent\")?)}})?;"),
                Target::Direct(0x407cf0) => format!("let fiber=rt.fiber.ok_or(\"UCRT current fiber absent\")?;let index=rt.load(rt.process_image_pointer(inputs.image,0x41c170,4)?,32)?.known_scalar()?;let slot=rt.fls.get(&index).ok_or(\"UCRT sentinel slot missing\")?.0;let ticket=rt.begin_heap_ptd_allocation(fiber,slot)?;let v=cpu.call_activation(rt,{next},0,|rt,c|ucrt_calloc_native(rt,c,inputs,platform,epoch))?;match v{{CrtValue::Pointer(p)=>rt.bind_heap_ptd_layout(ticket,p,CrtPtdLayout::Ucrt)?,CrtValue::Scalar{{bits:0,known:u32::MAX}}=>{{}},_=>return Err(\"UCRT allocation return authority\")}};"),
                Target::Import(0x415094) => format!("rt.process_image_import(inputs.image,0x415094,\"kernel32.dll\",\"HeapAlloc\")?;cpu.call_activation(rt,{next},12,|rt,c|{{c.validate_active(rt)?;if c.r[4]!=c.entry[4]||[3,5,6,7].iter().any(|&n|c.r[n]!=c.entry[n]){{return Err(\"UCRT HeapAlloc saved frame\");}}let sp=CrtCpu::pointer(c.r[4])?;rt.offset(sp,16)?;rt.memory.validate_writable(sp.cap,sp.owner,sp.address(),16).map_err(|_|\"UCRT HeapAlloc stack permission\")?;let CrtValue::Heap(heap)=rt.load(rt.offset(sp,4)?,32)?else{{return Err(\"UCRT HeapAlloc canonical heap\")}};let flags=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;let size=rt.load(rt.offset(sp,12)?,32)?.known_scalar()?;let p=rt.native_heap_allocate(inputs.init,heap,flags,size)?;c.clobber(CrtValue::Pointer(p));c.finish_pop(rt,12)}})?;"),
                Target::Direct(0x4071c0) | Target::Direct(0x40c9c0) | Target::Direct(0x407ccd) => "return Err(\"UCRT allocation retry/errno contract unbound\");".into(),
                Target::Direct(0x407d50) => format!("cpu.call_activation(rt,{next},0,|rt,c|ucrt_free_null(rt,c,inputs))?;"),
                Target::Direct(0x40a067) => format!("cpu.call_activation(rt,{next},0,|rt,c|ucrt_initialize_native(rt,c,inputs,platform,epoch))?;"),
                Target::Direct(0x409efb) => format!("cpu.call_activation(rt,{next},12,|rt,c|ucrt_mb_acquire(rt,c,inputs,epoch))?;"),
                Target::Direct(0x40a00d) => format!("cpu.call_activation(rt,{next},12,|rt,c|ucrt_locale_acquire(rt,c,inputs,epoch))?;"),
                _ => return Err(format!("UCRT unexpected original call at {pc:#x}: {target:?}")),
            })
            },
            &roles,
            8192,
        )?;
        let bind = if name == "ucrt_initialize_native" {
            "let sp=CrtCpu::pointer(cpu.r[4])?;let p=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;let v=rt.heap_ptds.iter().find(|v|v.pointer==p&&v.layout==CrtPtdLayout::Ucrt).ok_or(\"UCRT initialized object layout\")?;rt.heap_ptd_layout_view(p,v.slot,CrtPtdLayout::Ucrt)?;if rt.fls.get(&v.slot.index).map(|x|x.1)!=Some(CrtValue::Pointer(p)){return Err(\"UCRT initializer unpublished object\");}"
        } else if name == "ucrt_calloc_native" {
            "let sp=CrtCpu::pointer(cpu.r[4])?;if rt.load(rt.offset(sp,4)?,32)?.known_scalar()?==0||rt.load(rt.offset(sp,8)?,32)?.known_scalar()?==0{return Err(\"UCRT zero calloc request unsupported\");}"
        } else {
            ""
        };
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;platform.validate(rt,inputs.init)?;cpu.validate_active(rt)?;let code=rt.process_image_code(inputs.image,{origin},{})?;if rt.memory.read(code.address(),{}).map_err(|_|\"UCRT original code read\")?!=&{bytes:?}{{return Err(\"UCRT original code changed\");}}{bind}{body}}}\n",bytes.len(),bytes.len()));
    }
    out.push_str(&crate::crt_ucrt_locale::source()?);
    out.push_str(&crate::crt_ucrt_locale_replace::source()?);
    let free=crate::crt_ptd::raw("8bff558bec837d0800742dff75086a00ff35c8d24100ff159850410085c0751856ff154450410050e895feffff598bf0e848ffffff89305e5dc3");
    let g = Graph::decode(&free, 0x407d50)?;
    let body = crate::crt_stream_emit::emit_body(
        &g,
        |_, _| Ok("return Err(\"UCRT nonnull free/errno contract unbound\");".into()),
        &std::collections::BTreeMap::from([(0x41d2c8, "CrtRegionKind::Module".into())]),
        128,
    )?;
    out.push_str(&format!("fn ucrt_free_null(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,0x407d50,{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"UCRT free code read\")?!=&{free:?}{{return Err(\"UCRT free code changed\");}}{body}}}",free.len(),free.len()));
    Ok(out)
}

#[test]
fn ucrt_views_preserve_allocation_identity_and_reject_other_layouts() {
    crate::crt_stream_callees_tests::native(
        "",
        r#"
for mode in 0..21 {
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();
 let CrtValue::Heap(heap)=(if mode==18{rt.process_heap_result(init,true,Some(false))}else{rt.native_process_heap(init)}).unwrap()else{panic!()};
 let fiber=rt.bind_fiber(9).unwrap();let index=rt.native_fls_allocate(init,None).unwrap();
 rt.native_fls_set(init,fiber,index.index,CrtValue::scalar(u32::MAX)).unwrap();let slot=rt.fls.get(&index.index).unwrap().0;
 let old=rt.native_heap_allocate(init,heap,8,868).unwrap();
 let ticket=rt.begin_heap_ptd_allocation(fiber,slot).unwrap();
 let size=if mode==1{40}else if mode==2{864}else{868};
 let allocated=rt.native_heap_allocate(init,heap,8,size).unwrap();let mut p=allocated;
 if mode==20{p=rt.allocate(868,false,true).unwrap().unwrap();}if mode==3{p=old;}if mode==4{rt.store(p,32,CrtValue::scalar(1)).unwrap();}
 if mode==5{p=rt.subrange(p,40).unwrap();}if mode==6{p=rt.offset(p,4).unwrap();}
 if mode==7{rt.native_fls_set(init,fiber,index.index,CrtValue::scalar(0)).unwrap();}
 if mode==8{rt.free_allocation(p).unwrap();}
 let binding=rt.bind_heap_ptd_layout(ticket,p,CrtPtdLayout::Ucrt);
 if (1..=8).contains(&mode)||mode==20{assert!(binding.is_err(),"mode {mode} must reject");assert!(rt.heap_ptds.is_empty());continue;}
 binding.expect("fresh canonical zeroed UCRT allocation must bind");assert_eq!(p,allocated);assert_eq!(p.kind,CrtRegionKind::Buffer);assert_eq!(rt.heap_ptds[0].layout,CrtPtdLayout::Ucrt);
 assert!(rt.dispatcher_ptd(p).is_err());assert!(rt.heap_ptd_view(p,slot).is_err());assert!(rt.claim_file_buffer(p,0x8000).is_err());
 rt.native_fls_set(init,fiber,index.index,CrtValue::Pointer(p)).unwrap();assert_eq!(rt.native_fls_read(init,fiber,index.index).unwrap(),CrtValue::Pointer(p));
 rt.store(rt.offset(p,864).unwrap(),32,CrtValue::scalar(123)).unwrap();assert!(rt.load(rt.offset(p,868).unwrap(),8).is_err());
 if mode==9{rt.free_allocation(p).unwrap();assert!(rt.free_allocation(p).is_err());assert!(rt.native_fls_read(init,fiber,index.index).is_err());}
 if mode==10{rt.thread+=1;assert!(rt.heap_ptd_layout_view(p,slot,CrtPtdLayout::Ucrt).is_err());assert!(rt.native_fls_read(init,fiber,index.index).is_err());}
 if mode==11{rt.fiber=None;let other=rt.bind_fiber(9).unwrap();assert!(rt.native_fls_read(init,other,index.index).is_err());assert!(rt.native_fls_set(init,other,index.index,CrtValue::Pointer(p)).is_err());}
 if mode==12{let second=rt.native_fls_allocate(init,None).unwrap();assert!(rt.native_fls_set(init,fiber,second.index,CrtValue::Pointer(p)).is_err());}
 if mode==13{rt.fls_indices.get_mut(&index.index).unwrap().certain=false;assert!(rt.heap_ptd_layout_view(p,slot,CrtPtdLayout::Ucrt).is_err());}
 if mode==14{let cell=rt.offset(p,848).unwrap();rt.store(cell,32,CrtValue::scalar(7)).unwrap();assert!(rt.store(rt.offset(p,868).unwrap(),32,CrtValue::scalar(9)).is_err());assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(7));}
 if mode==15{let old_error=rt.last_os_error;let n=rt.regions.len();assert_eq!(rt.native_heap_allocate(init,heap,8,u32::MAX),Err("CRT allocation contract/budget"));assert_eq!(rt.regions.len(),n);assert_eq!(rt.last_os_error,old_error);assert_eq!(rt.native_fls_read(init,fiber,index.index).unwrap(),CrtValue::Pointer(p));}
 if mode==16{let before=rt.regions.len();let(mut other,oi)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let CrtValue::Heap(foreign)=other.native_process_heap(oi).unwrap()else{panic!()};assert!(rt.native_heap_allocate(init,foreign,8,868).is_err());assert_eq!(rt.regions.len(),before);}
 if mode==18{rt.heap_free_result(heap,0,p,0,Some(5)).unwrap();assert!(rt.heap_ptds.is_empty());assert!(rt.heap_ptd_layout_view(p,slot,CrtPtdLayout::Ucrt).is_err());assert!(rt.native_fls_read(init,fiber,index.index).is_err());assert_eq!(rt.last_os_error,Some(5));}
 if mode==19{rt.native_fls_set(init,fiber,index.index,CrtValue::Pointer(p)).unwrap();assert_eq!(rt.heap_ptds.len(),1);assert_eq!(rt.heap_ptds[0].pointer,p);}
 if mode==17{let q=rt.native_heap_allocate(init,heap,8,40).unwrap();rt.native_fls_set(init,fiber,index.index,CrtValue::scalar(u32::MAX)).unwrap();let t=rt.begin_heap_ptd_allocation(fiber,slot).unwrap();assert!(rt.bind_heap_ptd_return(t,q).is_err(),"pre-existing allocation cannot receive a new role");assert!(rt.heap_ptd_layout_view(p,slot,CrtPtdLayout::Ucrt).is_ok());}
}
"#,
        "ucrt-layout-ownership",
    );
}

#[test]
fn original_word_stores_preserve_source_flags_and_adjacent_bytes() {
    let mut extra = String::new();
    for index in [0u8, 1, 2, 3, 6, 7] {
        let bytes = [0x66, 0x89, 0x45 | (index << 3), 1];
        let g = Graph::decode_linear_fragment(&bytes, 0x1000).unwrap();
        let body = crate::crt_stream_emit::emit_linear_fragment(&g, &Default::default()).unwrap();
        extra.push_str(&format!("fn word_{index}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}"));
    }
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
for (index,run) in [(0,word_0 as fn(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>),(1,word_1),(2,word_2),(3,word_3),(6,word_6),(7,word_7)]{
 for mode in 0..5 {
  let mut rt=CrtStreamRuntime::new(7,9,0x8000,65536).unwrap();let data=rt.map_region(0x7000,if mode==2{2}else{4},CrtRegionKind::Module,Some(if mode==2{&[0xaa,0xbb][..]}else{&[0xaa,0xbb,0xcc,0xdd][..]})).unwrap();let stack=rt.map_region(0x9000,512,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,384).unwrap();let mut cpu=CrtCpu::new(sp,71).unwrap();cpu.r[5]=CrtValue::Pointer(data);
  cpu.r[index]=if mode==4{CrtValue::ProtectedReturn(777)}else if mode==3{CrtValue::Pointer(data)}else{CrtValue::Scalar{bits:0xa5a51234,known:if mode==1{0x00ff}else{u32::MAX}}};let before=cpu.r;cpu.flags=CrtFlags{cf:Some(true),zf:Some(false),sf:Some(true),of:Some(false)};
  let result=run(&mut rt,&mut cpu);if mode==2||mode==4{assert!(result.is_err(),"protected token or truncated word must reject");assert_eq!(rt.load(data,8).unwrap(),CrtValue::scalar(0xaa));}else{result.expect("word store must execute");assert_eq!(rt.load(data,8).unwrap(),CrtValue::scalar(0xaa));assert_eq!(rt.load(rt.offset(data,3).unwrap(),8).unwrap(),CrtValue::scalar(0xdd));let word=rt.load(rt.offset(data,1).unwrap(),16).unwrap();if mode==0{assert_eq!(word,CrtValue::scalar(0x1234));}else if mode==3{assert_eq!(word,CrtValue::scalar(0x7000));assert!(CrtCpu::pointer(word).is_err());}else{assert_eq!(word,CrtValue::Scalar{bits:0x34,known:0xffff00ff});}}
  assert_eq!(cpu.r,before);assert_eq!((cpu.flags.cf,cpu.flags.zf,cpu.flags.sf,cpu.flags.of),(Some(true),Some(false),Some(true),Some(false)));
 }
}
"#,
        "ucrt-word-store",
    );
}
