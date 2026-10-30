//! Original descriptor startup composed with shared registered frames and native effects.
use crate::crt_stream_ir::{Graph, Target};
pub(crate) const CALLBACK: &str = "6a0c68c0b54100e8bd97ffff6a07e8253700005933db885de7895dfc53e8713800005985c0750fe874feffffe81fffffffb301885de7c745fcfeffffffe8150000008ac3";
pub(crate) const CALLBACK_EPILOG: &str = "8b4df064890d00000000595f5e5bc9c3";
pub(crate) const CALLBACK_CLEANUP: &str = "6a07e82237000059c3";
pub(crate) const MANAGER: &str = "6a1068a0b64100e82a5fffff817d08002000007221e889bdffff6a095e8930e801bcffff8bc68b4df064890d00000000595f5e5bc9c333f68975e46a07e863feffff598975fc8bfea108d14100897de03945087c1f3934bd08cf41007531e8edfeffff8904bd08cf410085c075146a0c5e8975e4c745fcfeffffffe815000000eba2a108d1410083c040a308d1410047ebbb";
pub(crate) const MANAGER_EPILOG: &str = "8b4df064890d00000000595f5e5bc9c3";
pub(crate) const MANAGER_CLEANUP: &str = "6a07e851feffff59c3";
pub(crate) const CONSTRUCT: &str = "8bff558bec515153566a386a40e864beffff8bf033db8975f8595985f675048bf3eb4b8d86000e00003bf07441578d7e208bf05368a00f00008d47e050e8bdc1ffff834ff8ff80670df8891f8d7f38895fcc8d47e0c747d000000a0ac647d40a895fd6885fda3bc675c98b75f85f53e862beffff598bc65e5bc9c3";
pub(crate) const INHERIT: &str = "8bff558bec83ec488d45b850ff153850410066837dea000f8491000000578b7dec85ff0f84840000008b0753568d5f04be0020000003d83bc60f4cf056e8b13900003b3508d14100590f4f3508d141008975fc33f68b45fc85c0744f833bff7442833bfe743d8a4c3e04f6c1017434f6c108750cff33ff15bc50410085c074208bc68bce83e03fc1f9066bd0388b0303148d08cf41008942188a443e048842288b45fc4683c3043bf075b15e5b5fc9c3";
pub(crate) fn source() -> Result<String, String> {
    let mut out = String::new();
    let helper = crate::crt_ptd::raw(crate::crt_ucrt_locale::PROLOG);
    for (name, origin, eporigin, cleanuporigin, scope, size, hex, ephex, cleanhex) in [
        (
            "startup_lowio",
            0x408697,
            0x4086db,
            0x4086ee,
            0x41b5c0,
            12,
            CALLBACK,
            CALLBACK_EPILOG,
            CALLBACK_CLEANUP,
        ),
        (
            "startup_descriptor_manager",
            0x40bf2a,
            0x40bf50,
            0x40bfbf,
            0x41b6a0,
            16,
            MANAGER,
            MANAGER_EPILOG,
            MANAGER_CLEANUP,
        ),
    ] {
        let p = crate::crt_exception_wrapper::PrologProof::prove(
            crate::crt_exception_wrapper::Region {
                bytes: &helper,
                origin: 0x401e60,
            },
            size,
            scope,
            0x41c000,
            0x402210,
        )?;
        let epbytes = crate::crt_ptd::raw(ephex);
        let ep = crate::crt_exception_wrapper::EpilogProof::prove(
            crate::crt_exception_wrapper::Region {
                bytes: &epbytes,
                origin: eporigin,
            },
            &p,
        )?;
        out.push_str(&p.emit(&format!("{name}_prolog"))?);
        out.push_str(&ep.emit(&format!("{name}_epilog"))?);
        let clean = crate::crt_ptd::raw(cleanhex);
        let cg = Graph::decode(&clean, cleanuporigin)?;
        let cb = crate::crt_stream_emit::emit_body(
            &cg,
            |pc, t| {
                if t != Target::Direct(0x40be17) {
                    return Err("descriptor cleanup call".into());
                }
                let next = pc + cg.nodes[&pc].length;
                Ok(format!("cpu.call_activation(rt,{next},0,|rt,c|startup_second_lock(rt,c,inputs,false,held))?;"))
            },
            &Default::default(),
            64,
        )?;
        out.push_str(&format!("fn {name}_cleanup(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,held:&mut Option<CrtGlobalLock>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,{cleanuporigin},{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"descriptor cleanup code read\")?!=&{clean:?}{{return Err(\"descriptor cleanup code changed\");}}{cb}}}",clean.len(),clean.len()));
        let bytes = crate::crt_ptd::raw(hex);
        let end = origin + bytes.len() as u32;
        let mut d = iced_x86::Decoder::with_ip(
            32,
            &bytes,
            u64::from(origin),
            iced_x86::DecoderOptions::NONE,
        );
        let mut nodes = std::collections::BTreeMap::new();
        while d.can_decode() {
            let i = d.decode();
            let pc = i.ip() as u32;
            let at = (pc - origin) as usize;
            let n = Graph::decode_instruction(&bytes[at..at + i.len()], pc)?;
            if (eporigin..eporigin + epbytes.len() as u32).contains(&pc) {
                continue;
            }
            nodes.insert(pc, n);
        }
        let g = Graph { origin, end, nodes };
        for n in g.nodes.values() {
            for t in &n.successors {
                if !g.nodes.contains_key(t) && *t != eporigin {
                    return Err(format!("{name}: unbound original edge {t:x}"));
                }
            }
        }
        let body = crate::crt_stream_emit::emit_body_with_exit(
            &g,
            |pc, t| {
                let next = pc + g.nodes[&pc].length;
                Ok(match t{
   Target::Direct(0x401e60)=>format!("let n=rt.generation.checked_add(1).filter(|n|*n<1u64<<63).ok_or(\"descriptor helper generation\")?;let id=n|(1u64<<63);if rt.tags.values().any(|v|*v==CrtValue::ProtectedReturn(id)){{return Err(\"descriptor helper identity collision\");}}rt.generation=n;cpu.push(rt,CrtValue::ProtectedReturn(id))?;{name}_prolog(rt,cpu,id,b.token,|rt,c,record,head|b.install(rt,c,epoch,record,head))?;"),
   Target::Direct(0x40bdcf)=>format!("cpu.call_activation(rt,{next},0,|rt,c|startup_second_lock(rt,c,inputs,true,&mut held))?;"),
   Target::Direct(0x4086ee)|Target::Direct(0x40bfbf)=>format!("b.authority(rt,epoch)?;cpu.call_activation(rt,{next},0,|rt,c|{name}_cleanup(rt,c,inputs,&mut held))?;"),
   Target::Direct(0x40bf2a)=>format!("cpu.call_activation(rt,{next},0,|rt,c|startup_descriptor_manager(rt,c,inputs,platform,epoch))?;"),
   Target::Direct(0x40be7a)=>format!("b.authority(rt,epoch)?;rt.check_global(held.ok_or(\"descriptor allocation without manager lock\")?)?;cpu.call_activation(rt,{next},0,|rt,c|startup_descriptor_construct(rt,c,inputs,platform,epoch))?;"),
   Target::Direct(0x408537)=>format!("cpu.call_activation(rt,{next},0,|rt,c|startup_inherit_native(rt,c,inputs))?;"),
   Target::Direct(0x4085e7)=>"return Err(\"startup standard-handle acquisition unbound\");".into(),
   Target::Direct(0x407ccd)|Target::Direct(0x407b4f)=>"return Err(\"startup descriptor invalid-request errno effect unbound\");".into(),
   _=>return Err(format!("descriptor startup unexpected call {pc:x}"))})
            },
            &std::collections::BTreeMap::from([
                (0x41cf08, "CrtRegionKind::Module".into()),
                (0x41d108, "CrtRegionKind::Module".into()),
            ]),
            16384,
            |_, _| Err("descriptor startup thread effect".into()),
            |_, _| Ok(String::new()),
            |_, _| Ok(None),
            Some(eporigin),
        )?;
        let terminal = format!("if pc=={eporigin}{{return Ok(cpu.r[0]);}}");
        if !body.contains(&terminal) {
            return Err("descriptor epilog cut missing".into());
        }
        let body=body.replace(&terminal,&format!("if pc=={eporigin}{{if held.is_some(){{return Err(\"descriptor epilog with held lease\");}}return {name}_epilog(rt,cpu,epoch,&mut b);}}"));
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;platform.validate(rt,inputs.init)?;cpu.validate_active(rt)?;for(address,expected)in [({origin}u32,&{bytes:?}[..]),({eporigin},&{epbytes:?}[..]),(0x401e60,&{helper:?}[..])]{{let p=rt.process_image_code(inputs.image,address,expected.len()as u32)?;if rt.memory.read(p.address(),expected.len()as u32).map_err(|_|\"descriptor startup code read\")?!=expected{{return Err(\"descriptor startup code changed\");}}}}let mut b=CrtNormalBinding::bind_initializing(rt,cpu,epoch,{name}_epilog_layout(),inputs.init)?;let mut held=None;{body}}}"));
    }
    out.push_str(&constructor_source()?);
    Ok(out)
}
fn constructor_source() -> Result<String, String> {
    let bytes = crate::crt_ptd::raw(CONSTRUCT);
    let g = Graph::decode(&bytes, 0x40be7a)?;
    let body = crate::crt_stream_emit::emit_body(
        &g,
        |pc, t| {
            let next = pc + g.nodes[&pc].length;
            Ok(match t{
  Target::Direct(0x407cf0)=>format!("cpu.call_activation(rt,{next},0,|rt,c|startup_descriptor_calloc(rt,c,inputs,platform,epoch))?;"),
  Target::Direct(0x408079)=>format!("cpu.call_activation(rt,{next},12,|rt,c|startup_descriptor_lock(rt,c,inputs,platform))?;"),
  Target::Direct(0x407d50)=>format!("cpu.call_activation(rt,{next},0,|rt,c|ucrt_free_null(rt,c,inputs))?;"),
  _=>return Err("descriptor constructor unexpected call".into())})
        },
        &Default::default(),
        8192,
    )?;
    let thunk = crate::crt_ptd::raw("8bff558bec5dff25ac504100");
    let tg = Graph::decode_linear_fragment(&thunk[..6], 0x408079)?;
    let pre = crate::crt_stream_emit::emit_linear_fragment(&tg, &Default::default())?;
    let inherited = crate::crt_ptd::raw(INHERIT);
    let ig = Graph::decode(&inherited, 0x408537)?;
    let ib = crate::crt_stream_emit::emit_body(
        &ig,
        |pc, t| {
            if t != Target::Import(0x415038) {
                return Ok(
                    "return Err(\"startup inherited handle producer contract unbound\");".into(),
                );
            }
            Ok(format!("rt.process_image_import(inputs.image,0x415038,\"kernel32.dll\",\"GetStartupInfoW\")?;return Err(\"startup GetStartupInfoW effects unbound at {pc:#x}\");"))
        },
        &std::collections::BTreeMap::from([
            (0x41cf08, "CrtRegionKind::Module".into()),
            (0x41d108, "CrtRegionKind::Module".into()),
        ]),
        4096,
    )?;
    Ok(format!("fn startup_descriptor_construct(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,0x40be7a,{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"descriptor constructor code read\")?!=&{bytes:?}{{return Err(\"descriptor constructor code changed\");}}{body}}}
fn startup_descriptor_lock(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;platform.validate(rt,inputs.init)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,0x408079,12)?;if rt.memory.read(p.address(),12).map_err(|_|\"descriptor thunk code read\")?!=&{thunk:?}{{return Err(\"descriptor thunk code changed\");}}rt.process_image_import(inputs.image,0x4150ac,\"kernel32.dll\",\"InitializeCriticalSectionEx\")?;let _=(||->Result<CrtValue,&'static str>{{{pre}}})()?;if cpu.return_pop!=12||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){{return Err(\"descriptor lock ABI\");}}let sp=CrtCpu::pointer(cpu.r[4])?;rt.offset(sp,16)?;rt.memory.validate_writable(sp.cap,sp.owner,sp.address(),16).map_err(|_|\"descriptor lock stack permission\")?;let p=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;let spin=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;let flags=rt.load(rt.offset(sp,12)?,32)?.known_scalar()?;if spin!=4000{{return Err(\"descriptor lock spin domain\");}}let result=rt.native_record_initialize(inputs.init,platform.function,p,flags)?;cpu.clobber(CrtValue::scalar(u32::from(result)));cpu.finish_pop(rt,12)}}
fn startup_inherit_native(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,0x408537,{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"startup inherit code read\")?!=&{inherited:?}{{return Err(\"startup inherit code changed\");}}{ib}}}",bytes.len(),bytes.len(),inherited.len(),inherited.len()))
}

#[test]
fn native_descriptor_resources_preserve_partial_construction_and_identity() {
    crate::crt_stream_callees_tests::native(
        r#"
struct Guard;
static DENY:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
unsafe impl std::alloc::GlobalAlloc for Guard{
 unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{if DENY.load(std::sync::atomic::Ordering::SeqCst){std::ptr::null_mut()}else{unsafe{std::alloc::System.alloc(l)}}}
 unsafe fn alloc_zeroed(&self,l:std::alloc::Layout)->*mut u8{if DENY.load(std::sync::atomic::Ordering::SeqCst){std::ptr::null_mut()}else{unsafe{std::alloc::System.alloc_zeroed(l)}}}
 unsafe fn realloc(&self,p:*mut u8,l:std::alloc::Layout,n:usize)->*mut u8{if DENY.load(std::sync::atomic::Ordering::SeqCst){std::ptr::null_mut()}else{unsafe{std::alloc::System.realloc(p,l,n)}}}
 unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){unsafe{std::alloc::System.dealloc(p,l)}}
}
#[global_allocator]static ALLOC:Guard=Guard;
"#,
        r#"
for mode in 0..12{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let CrtValue::Heap(heap)=rt.native_process_heap(init).unwrap()else{panic!()};let t=rt.provider_begin(init,"kernelbase.dll",0x700000,1).unwrap();let m=rt.provider_publish(init,&t).unwrap();let d=rt.provider_export(init,m,m,"InitializeCriticalSectionEx",0x701000).unwrap();let f=rt.bind_native_sync(init,d).unwrap();
 if mode==2{let n=rt.regions.len();for size in [0,55,57,65*56]{assert!(rt.native_descriptor_allocate(init,heap,8,size).is_err());}assert_eq!(rt.regions.len(),n);continue;}
 let p=rt.native_descriptor_allocate(init,heap,8,5*56).unwrap();assert_eq!(p.kind,CrtRegionKind::Descriptor);let q=rt.offset(p,4*56).unwrap();
 if mode==0||mode==1{
  let count=if mode==0{0}else{4};for n in 0..count{assert!(rt.native_record_initialize(init,f,rt.offset(p,n*56).unwrap(),0).unwrap());}
  assert_eq!(rt.record_objects.len(),count as usize);rt.last_os_error=Some(77);DENY.store(true,std::sync::atomic::Ordering::SeqCst);let result=rt.native_record_initialize(init,f,q,0);DENY.store(false,std::sync::atomic::Ordering::SeqCst);
  assert_eq!(result,Err("CRT native descriptor lock storage unavailable"));assert_eq!(rt.record_objects.len(),count as usize);assert_eq!(rt.load(q,32).unwrap(),CrtValue::scalar(0));assert_eq!(rt.last_os_error,Some(77));for n in 0..count{rt.record_lock_live(rt.offset(p,n*56).unwrap()).unwrap();}continue;
 }
 let pointer=if mode==3{rt.offset(p,1).unwrap()}else if mode==4{rt.native_heap_allocate(init,heap,8,56).unwrap()}else{p};
 if mode==5{rt.free_initialization(init,p).unwrap();}if mode==6{rt.provider_destroy(init,m).unwrap();}if mode==7{rt.end_initialization(init).unwrap();}if mode==8{rt.thread+=1;}
 if mode<=8{let before=rt.record_objects.len();assert!(rt.native_record_initialize(init,f,pointer,0).is_err(),"mode {mode} must reject");assert_eq!(rt.record_objects.len(),before);continue;}
 rt.native_record_initialize(init,f,p,0).expect("valid descriptor lock must construct");assert_eq!(rt.record_objects.len(),1);assert!(rt.native_record_initialize(init,f,p,0).is_err());assert!(rt.free_initialization(init,p).is_err());
 if mode==9{let held=rt.lock_record(rt.thread,p).unwrap();assert!(rt.destroy_record_lock(init,p).is_err());rt.unlock_record(held).unwrap();assert!(rt.unlock_record(held).is_err());}
 if mode==10{assert!(rt.native_record_initialize(init,f,q,1).is_err());assert_eq!(rt.load(q,32).unwrap(),CrtValue::scalar(0));}
 rt.destroy_record_lock(init,p).unwrap();assert!(rt.destroy_record_lock(init,p).is_err());rt.free_initialization(init,p).unwrap();assert!(rt.record_lock_live(p).is_err());assert!(rt.native_record_initialize(init,f,p,0).is_err());
}
"#,
        "native-descriptor-resources",
    );
}
