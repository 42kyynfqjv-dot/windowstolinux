//! Original malloc success and explicit rejected retry/errno boundaries.
use crate::crt_stream_ir::{Graph, Target};
pub(crate) const CODE: &str = "8bff558bec568b750883fee0773333c04085f60f44f0eb14e873eaffff85c0742056e8694200005985c07415566a00ff35c8d24100ff159450410085c074d9eb0de857f5ffffc7000c00000033c05e5dc3";
pub(crate) const MODE: &str = "a180ce410090c3";
pub(crate) fn source() -> Result<String, String> {
    let raw = crate::crt_ptd::raw;
    let bytes = raw(CODE);
    let g = Graph::decode(&bytes, 0x408730)?;
    let body = crate::crt_stream_emit::emit_body(
        &g,
        |pc, t| {
            let next = pc + g.nodes[&pc].length;
            Ok(match t {
                Target::Import(0x415094) => format!("rt.process_image_import(inputs.image,0x415094,\"kernel32.dll\",\"HeapAlloc\")?;cpu.call_activation(rt,{next},12,|rt,c|allocate(rt,c,inputs))?;"),
                Target::Direct(0x4071c0) => format!("cpu.call_activation(rt,{next},0,|rt,c|malloc_mode_original(rt,c,inputs))?;"),
                Target::Direct(0x40c9c0) => "return Err(\"malloc new-handler effect unbound\");".into(),
                Target::Direct(0x407ccd) => "return Err(\"malloc errno acquisition unbound\");".into(),
                _ => return Err(format!("malloc original call {pc:x} {t:?}")),
            })
        },
        &std::collections::BTreeMap::from([(0x41d2c8, "CrtRegionKind::Module".into())]),
        512,
    )?;
    let mode = raw(MODE);
    let mode_body = crate::crt_stream_emit::emit_body(
        &Graph::decode(&mode, 0x4071c0)?,
        |_, _| Err("malloc mode unexpected call".into()),
        &std::collections::BTreeMap::from([(0x41ce80, "CrtRegionKind::Module".into())]),
        16,
    )?;
    Ok(format!(
        r#"
fn malloc_mode_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,0x4071c0,{ml})?;if rt.memory.read(p.address(),{ml}).map_err(|_|"malloc mode code read")?!=&{mode:?}{{return Err("malloc mode code changed");}}{mode_body}}}
// The callback is a declared API-effect boundary for conformance tests. Actual
// entry binds only native_heap_buffer_call; fixtures do not issue native outcomes.
fn malloc_original_with(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,allocate:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,&CrtEntropyInputs)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,0x408730,{len})?;if rt.memory.read(p.address(),{len}).map_err(|_|"malloc code read")?!=&{bytes:?}{{return Err("malloc original code changed");}}{body}}}
fn malloc_original_native(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{malloc_original_with(rt,cpu,inputs,&mut |rt,c,inputs|c.native_heap_buffer_call(rt,inputs.init))}}
"#,
        ml = mode.len(),
        len = bytes.len()
    ))
}

#[test]
fn native_uninitialized_buffer_preserves_unknown_bytes_identity_and_failure_atomicity() {
    crate::crt_stream_callees_tests::native(
        "",
        r#"
for size in [1,4,7,544]{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();
 let CrtValue::Heap(heap)=rt.native_process_heap(init).unwrap()else{panic!("canonical heap")};
 let p=rt.native_heap_allocate(init,heap,0,size).expect("actual flags0 allocation");let q=rt.native_heap_allocate(init,heap,0,size).unwrap();assert_ne!(p.cap,q.cap);assert_eq!(p.kind,CrtRegionKind::Buffer);
 for i in 0..size{let at=rt.offset(p,i64::from(i)).unwrap();assert_eq!(rt.memory.read(at.address(),1),Err(guest_memory::Fault::Uninitialized));assert!(rt.load(at,8).unwrap().known_scalar().is_err());}
 if size>=4{assert!(CrtCpu::pointer(rt.load(p,32).unwrap()).is_err());}
 rt.store(p,8,CrtValue::scalar(0xa5)).unwrap();assert_eq!(rt.load(p,8).unwrap(),CrtValue::scalar(0xa5));assert!(rt.load(q,8).unwrap().known_scalar().is_err());
 if size>1{assert!(rt.load(rt.offset(p,1).unwrap(),8).unwrap().known_scalar().is_err());}
 let zero=rt.native_heap_allocate(init,heap,8,size).unwrap();assert_eq!(rt.memory.read(zero.address(),size).unwrap(),vec![0;size as usize]);
 let alias=rt.offset(p,i64::from(size-1)).unwrap();rt.free_allocation(p).unwrap();assert!(rt.load(alias,8).is_err());assert!(rt.load(q,8).unwrap().known_scalar().is_err());
}
for mode in 0..10{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let CrtValue::Heap(heap)=rt.native_process_heap(init).unwrap()else{panic!()};
 rt.last_os_error=Some(71);let before=rt.regions.len();
 let result=match mode{0=>rt.native_heap_allocate(init,heap,0,0),1=>rt.native_heap_allocate(init,heap,0,u32::MAX),2=>rt.native_heap_allocate(init,heap,1,4),3=>rt.native_heap_allocate(init,heap,16,4),4=>rt.native_heap_allocate(init,heap,32,4),5=>rt.native_descriptor_allocate(init,heap,0,56),6=>{let(mut other,oi)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let CrtValue::Heap(h)=other.native_process_heap(oi).unwrap()else{panic!()};rt.native_heap_allocate(init,h,0,4)},7=>{let mut h=heap;h.exceptions=Some(true);rt.native_heap_allocate(init,h,0,4)},8=>{rt.end_initialization(init).unwrap();rt.native_heap_allocate(init,heap,0,4)},9=>{rt.memory.release(rt.anchor,rt.file_view.owner).unwrap();rt.native_heap_allocate(init,heap,0,4)},_=>unreachable!()};
 assert!(result.is_err(),"negative flags0 allocation mode {mode}");assert_eq!(rt.regions.len(),before);assert_eq!(rt.last_os_error,Some(71));
}
for mode in 0..5{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let heap=rt.native_process_heap(init).unwrap();let stack=rt.map_region(0xa000,128,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,32).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(99)).unwrap();for(i,v)in [(4,heap),(8,CrtValue::scalar(0)),(12,CrtValue::scalar(17))]{rt.store(rt.offset(sp,i).unwrap(),32,v).unwrap();}
 let mut c=CrtCpu::new(sp,99).unwrap();c.return_pop=12;rt.last_os_error=Some(77);
 if mode==1{c.return_pop=0;}if mode==2{c.r[3]=CrtValue::scalar(5);}if mode==3{rt.store(rt.offset(sp,8).unwrap(),32,CrtValue::Scalar{bits:0,known:0}).unwrap();}if mode==4{rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::scalar(0x700000)).unwrap();}
 let n=rt.regions.len();let result=c.native_heap_buffer_call(&mut rt,init);
 if mode==0{let p=CrtCpu::pointer(result.expect("native HeapAlloc checked ABI")).unwrap();assert!(c.returned);assert_eq!(p.size,17);assert!(rt.load(p,32).unwrap().known_scalar().is_err());assert_eq!(rt.regions.len(),n+1);}
 else{assert!(result.is_err(),"invalid allocation API mode {mode}");assert!(!c.returned);assert_eq!(rt.regions.len(),n);assert_eq!(rt.last_os_error,Some(77));assert_eq!(rt.load(sp,32).unwrap(),CrtValue::ProtectedReturn(99));}
}
"#,
        "native-uninitialized-buffer",
    );
}
