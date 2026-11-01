//! Synthetic-only environment contracts; never acquire or log host variables.
#[test]
fn environment_snapshot_owns_readonly_copies_and_exact_free_lifetimes() {
    crate::crt_stream_callees_tests::native_bounded_stack(
        "",
        r#"
#[inline(never)]fn one(mode:u32){
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let values=if mode==0{vec![]}else{vec![("W2L_ALPHA".into(),"one".into()),("W2L_EMPTY".into(),"".into()),("W2L_UNICODE".into(),"雪😀".into())]};rt.declare_environment(init,"w2l-controlled-environment-v1",0x20000,&values).unwrap();let a=rt.environment_snapshot(init).unwrap();let b=rt.environment_snapshot(init).unwrap();assert_ne!(a.cap,b.cap);let data=rt.memory.read(a.address(),a.size).unwrap().to_vec();let expected=if mode==0{"\0\0"}else{"W2L_ALPHA=one\0W2L_EMPTY=\0W2L_UNICODE=雪😀\0\0"};let oracle:Vec<u8>=expected.encode_utf16().flat_map(u16::to_le_bytes).collect();assert_eq!(data,oracle);assert_eq!(&data[data.len()-4..],&[0;4]);assert_eq!(rt.memory.read(b.address(),b.size).unwrap(),data);assert!(rt.store(a,16,CrtValue::scalar(7)).is_err());assert!(rt.memory.write(a.address(),&[1,0]).is_err());assert!(rt.retire_region(a).is_err());let CrtValue::Heap(heap)=rt.native_process_heap(init).unwrap()else{panic!()};assert!(rt.heap_free_result(heap,0,a,1,None).is_err());let fact=rt.memory.prove_read(a.cap,a.owner,a.address(),a.size).unwrap();let alias=rt.offset(a,2).unwrap();
 if mode==2{let narrow=rt.subrange(a,a.size-2).unwrap();assert!(rt.free_environment_snapshot(init,narrow).is_err());assert!(rt.free_environment_snapshot(init,alias).is_err());assert_eq!(rt.memory.read(a.address(),a.size).unwrap(),data);}
 if mode==3{let(mut other,oi)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();other.declare_environment(oi,"w2l-controlled-environment-v1",0x20000,&values).unwrap();let foreign=other.environment_snapshot(oi).unwrap();assert!(rt.free_environment_snapshot(init,foreign).is_err());}
 if mode==4{rt.end_initialization(init).unwrap();let count=rt.environment.as_ref().unwrap().blocks.len();assert!(rt.free_environment_snapshot(init,a).is_err());assert!(rt.environment_snapshot(init).is_err());assert_eq!(rt.environment.as_ref().unwrap().blocks.len(),count);return;}
 let result=rt.free_environment_snapshot(init,a).unwrap();assert!(matches!(result,CrtValue::NonZero{..}));assert!(rt.load(alias,16).is_err());assert!(rt.memory.read_proven(fact,a.owner).is_err());assert!(rt.free_environment_snapshot(init,a).is_err());assert_eq!(rt.memory.read(b.address(),b.size).unwrap(),data);rt.free_environment_snapshot(init,b).unwrap();assert!(rt.environment.as_ref().unwrap().blocks.is_empty());let c=rt.environment_snapshot(init).unwrap();assert_ne!(c.cap,a.cap);assert_eq!(rt.memory.read(c.address(),c.size).unwrap(),data);
}
for mode in 0..5{one(mode);}
"#,
        "environment-owned",
    );
}
#[test]
fn environment_declaration_and_mapping_failures_do_not_publish_partial_state() {
    crate::crt_stream_callees_tests::native_bounded_stack(
        "",
        r#"
for mode in 0..8{let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let entries=match mode{0=>vec![("A".into(),"ok".into()),("a".into(),"bad".into())],1=>vec![("A=B".into(),"x".into())],2=>vec![("A".into(),"x\0y".into())],3=>vec![("雪".into(),"x".into())],4=>vec![("".into(),"x".into())],5=>vec![("A".into(),"x".repeat(32767))],_=>vec![("A".into(),"x".into())]};let result=rt.declare_environment(init,if mode==6{"host-environment"}else{"w2l-controlled-environment-v1"},0x20000,&entries);if mode<7{assert!(result.is_err(),"invalid input {mode}");assert!(rt.environment.is_none());}else{result.unwrap();assert!(rt.declare_environment(init,"w2l-controlled-environment-v1",0x30000,&entries).is_err());let p=rt.map_region(0x20000,4096,CrtRegionKind::Module,Some(&[0x6a;4096])).unwrap();let count=rt.regions.len();rt.last_os_error=Some(91);assert!(rt.environment_snapshot(init).is_err());assert_eq!(rt.regions.len(),count);assert!(rt.environment.as_ref().unwrap().blocks.is_empty());assert_eq!(rt.environment.as_ref().unwrap().next,0x20000);assert_eq!(rt.last_os_error,Some(91));assert_eq!(rt.load(p,8).unwrap(),CrtValue::scalar(0x6a));}}
"#,
        "environment-failures",
    );
}

#[test]
fn environment_api_preflights_stack_saved_state_and_matching_free_abi() {
    crate::crt_stream_callees_tests::native_bounded_stack(
        crate::crt_resident_loader::TYPES,
        r#"
#[inline(never)]fn one(mode:u32){
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let platform=CrtNativePlatform::prepare(&mut rt,init,CrtNativePlatform::PROFILE,0x700000,0x701000).unwrap();rt.declare_environment(init,"w2l-controlled-environment-v1",0x20000,&[("W2L_KEY".into(),"synthetic".into())]).unwrap();let stack=rt.map_region(0x40000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(73)).unwrap();let mut cpu=CrtCpu::new(sp,73).unwrap();
 if mode==1{cpu.return_pop=4;}if mode==2{cpu.r[3]=CrtValue::scalar(0);}if mode==3{rt.store(rt.offset(sp,-32).unwrap(),32,CrtValue::ProtectedReturn(73)).unwrap();}if mode==4{rt.end_initialization(init).unwrap();}if mode==5{rt.closed=true;}let before=rt.regions.len();let got=platform.environment_call(&mut rt,&mut cpu,init,false);
 if (1..=5).contains(&mode){assert!(got.is_err(),"get ABI negative {mode}");assert!(!cpu.returned);assert_eq!(rt.regions.len(),before);assert!(rt.environment.as_ref().unwrap().blocks.is_empty());return;}
 let CrtValue::Pointer(p)=got.unwrap()else{panic!("owned pointer")};assert!(cpu.returned);assert!(rt.load(p,16).is_ok());assert!(platform.environment_call(&mut rt,&mut cpu,init,false).is_err());
 rt.store(sp,32,CrtValue::ProtectedReturn(74)).unwrap();let mut c=CrtCpu::new(sp,74).unwrap();c.return_pop=if mode==9{0}else{4};rt.store(rt.offset(sp,4).unwrap(),32,if mode==7{CrtValue::Pointer(rt.offset(p,2).unwrap())}else if mode==8{CrtValue::scalar(0)}else{CrtValue::Pointer(p)}).unwrap();let got=platform.environment_call(&mut rt,&mut c,init,true);if (7..=9).contains(&mode){assert!(got.is_err(),"free ABI negative {mode}");assert!(!c.returned);assert!(rt.load(p,16).is_ok());}else{assert!(matches!(got,Ok(CrtValue::NonZero{..})));assert!(c.returned);assert!(rt.load(p,16).is_err());}
}for mode in 0..10{one(mode);}
"#,
        "environment-API",
    );
}
