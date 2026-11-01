//! Synthetic-only environment contracts; never acquire or log host variables.
#[test]
fn environment_snapshot_owns_readonly_copies_and_exact_free_lifetimes() {
    crate::crt_stream_callees_tests::native_bounded_stack(
        "",
        r#"
#[inline(never)]fn one(mode:u32){
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let values=if mode==0{vec![]}else{vec![("W2L_ALPHA".into(),"one".into()),("W2L_EMPTY".into(),"".into()),("W2L_UNICODE".into(),"雪😀".into())]};rt.declare_environment(init,"w2l-controlled-environment-v1",0x20000,&values).unwrap();let a=rt.environment_snapshot(init).unwrap();let b=rt.environment_snapshot(init).unwrap();assert_ne!(a.cap,b.cap);let data=rt.memory.read(a.address(),a.size).unwrap().to_vec();assert_eq!(&data[data.len()-4..],&[0;4]);assert_eq!(rt.memory.read(b.address(),b.size).unwrap(),data);assert!(rt.store(a,16,CrtValue::scalar(7)).is_err());assert!(rt.memory.write(a.address(),&[1,0]).is_err());assert!(rt.retire_region(a).is_err());let CrtValue::Heap(heap)=rt.native_process_heap(init).unwrap()else{panic!()};assert!(rt.heap_free_result(heap,0,a,1,None).is_err());let fact=rt.memory.prove_read(a.cap,a.owner,a.address(),a.size).unwrap();let alias=rt.offset(a,2).unwrap();
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
