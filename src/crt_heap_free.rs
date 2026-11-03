//! Original free instructions with conservative failure ownership and canonical errno.
use crate::crt_stream_ir::{Graph, Target};
use std::collections::BTreeMap;
pub(crate) const FREE: &str = "8bff558bec837d0800742dff75086a00ff35c8d24100ff159850410085c0751856ff154450410050e895feffff598bf0e848ffffff89305e5dc3";
pub(crate) const MAPPER: &str = "8bff558bec568b750883fe01722f83fe0d77098b04f534604100eb4081fe1807000077196a2d683860410056e850ffffff83c40c85c074058b4004eb1f8d4eed83f91177056a0d58eb126a0e8d8644ffffff593bc81bc023c183c0085e5dc3";
pub(crate) const SEARCH: &str = "8bff558bec83ec0c8b4d1033d253568b75088d41ff578b7d0c8945f48bc1d1e8744df6c1018d58ff0f45d88d0c13894df88d0ccf8b318975fc8b75083b31742b3b75fc8bc88b45f80f42cb403b75fc8b5df84b0f43d03b75fc0f435df4895df43bd376b833c05f5e5bc9c38bc1ebf785c974f18d04d733c93b300f45c1ebe7";
pub(crate) const UPDATER: &str =
    "8bff558bec8b4508568b750c50c6462401894620e865ffffff59c6461c018946185e5dc3";
pub(crate) const TABLE: &str = "0100000016000000020000000200000003000000020000000400000018000000050000000d0000000600000009000000070000000c000000080000000c000000090000000c0000000a000000070000000b000000080000000c000000160000000d000000160000000f00000002000000100000000d00000011000000120000001200000002000000210000000d0000003500000002000000410000000d00000043000000020000005000000011000000520000000d000000530000000d0000005700000016000000590000000b0000006c0000000d0000006d00000020000000700000001c0000007200000009000000800000000a000000810000000a00000082000000090000008300000016000000840000000d00000091000000290000009e0000000d000000a100000002000000a40000000b000000a70000000d000000b700000011000000ce00000002000000d70000000b000000590400002a000000180700000c000000";

pub(crate) fn source(bytes: &[u8]) -> Result<String, String> {
    if bytes != crate::crt_ptd::raw(FREE) {
        return Err("original free code binding".into());
    }
    let graph = Graph::decode(bytes, 0x407d50)?;
    let body = crate::crt_stream_emit::emit_body(
        &graph,
        |pc, target| {
            let next = pc + graph.nodes[&pc].length;
            let (pop,call)=match target {
            Target::Import(0x415098)=>(12,r#"let sp=CrtCpu::pointer(child.r[4])?;
let CrtValue::Heap(heap)=rt.load(rt.offset(sp,4)?,32)? else{return Err("free opaque heap authority")};
let flags=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;
let pointer=CrtCpu::pointer(rt.load(rt.offset(sp,12)?,32)?)?;
if effect.is_some(){return Err("free repeated API observation");}
rt.heap_free_preflight(heap,flags,pointer)?;
let (raw,error)=outcome(rt,heap,flags,pointer)?;
effect=Some(rt.heap_free_result(heap,flags,pointer,raw,error)?);
child.clobber(CrtValue::scalar(raw));child.finish_pop(rt,12)"#),
            Target::Import(0x415044)=>(0,"child.clobber(rt.last_os_error.map(CrtValue::scalar).unwrap_or(CrtValue::Scalar{bits:0,known:0}));child.finish(rt)"),
            Target::Direct(0x407c12)=>(0,"let sp=CrtCpu::pointer(child.r[4])?;let scratch=rt.offset(sp,-68)?;rt.valid(scratch,68)?;if rt.overlapping_tags(scratch.address(),68).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_))){return Err(\"free errno private scratch crosses protected activation\");}let error=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;for i in (0..68).step_by(4){rt.store(rt.offset(scratch,i)?,32,CrtValue::Scalar{bits:0,known:0})?;}child.clobber(CrtValue::scalar(free_errno_map(error)?));child.finish(rt)"),
            Target::Direct(0x407ccd)=>(0,"errno_routed_call(rt,child,|rt,c|errno_lookup(rt,c))"),
            _=>return Err("original free unbound call".into()),
        };
            Ok(format!(
                "cpu.call_activation(rt,{next},{pop},|rt,child|{{{call}}})?;"
            ))
        },
        &BTreeMap::from([(0x41d2c8, "CrtRegionKind::Module".into())]),
        256,
    )?;
    Ok(format!(
        r#"fn original_free(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,
 outcome:&mut impl FnMut(&mut CrtStreamRuntime,CrtHeap,u32,CrtPointer)->Result<(u32,Option<u32>),&'static str>,
 errno_lookup:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{
let mut effect=None;
let value=(||->Result<CrtValue,&'static str>{{{body}}})()?;
if !cpu.returned{{return Err("original free missing return");}}
if let Some(effect)=effect{{rt.complete_heap_free(effect)?;}}
Ok(value)
}}"#
    ))
}
pub(crate) fn fixture_source() -> String {
    format!(
        "{}{}",
        crate::crt_standard_handles_tests::errno_source(),
        fixture_source_without_errno()
    )
}
pub(crate) fn fixture_source_without_errno() -> String {
    use crate::crt_error_map::{prove, Region};
    let m = crate::crt_ptd::raw(MAPPER);
    let s = crate::crt_ptd::raw(SEARCH);
    let u = crate::crt_ptd::raw(UPDATER);
    let t = crate::crt_ptd::raw(TABLE);
    let proof = prove(
        Region {
            va: 0x407c12,
            bytes: &m,
        },
        Region {
            va: 0x407b93,
            bytes: &s,
        },
        Region {
            va: 0x407c94,
            bytes: &u,
        },
        Region {
            va: 0x416038,
            bytes: &t,
        },
        (0x400000, 0x41e000),
    )
    .unwrap();
    format!(
        "{}{}",
        proof.source("free_errno").unwrap(),
        source(&crate::crt_ptd::raw(FREE)).unwrap()
    )
}
#[test]
fn original_free_failure_executes_mapping_and_owned_errno_without_lifetime_claim() {
    crate::crt_stream_callees_tests::native(
        &fixture_source(),
        r#"
for mode in 0..18 {
 let(mut rt,init)=CrtStreamRuntime::new_initializing(1,2,0x8000,65536).unwrap();
 let heap=rt.process_heap_result(init,true,Some(false)).unwrap();
 let CrtValue::Heap(h)=heap else{panic!()};
 rt.map_region(0x41d2c8,4,CrtRegionKind::Module,None).map(|p|rt.store(p,32,heap).unwrap()).unwrap();
 let p=rt.allocate(40,true,true).unwrap().unwrap();let alias=rt.offset(p,12).unwrap();
 let other=rt.allocate(40,true,true).unwrap().unwrap();rt.store(other,32,CrtValue::scalar(91)).unwrap();
 let ptd=rt.map_region(0x7000,32,CrtRegionKind::ThreadData,None).unwrap();let cell=rt.offset(ptd,16).unwrap();rt.store(cell,32,CrtValue::scalar(73)).unwrap();
 let fallback=rt.map_region(0x41c130,4,CrtRegionKind::Module,Some(&37u32.to_le_bytes())).unwrap();
 let stack=rt.map_region(0x9000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,3072).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();
 let arg=if mode==0{CrtValue::scalar(0)}else if mode==10{CrtValue::Pointer(alias)}else{CrtValue::Pointer(p)};
 rt.store(rt.offset(sp,4).unwrap(),32,arg).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();let saved=cpu.r;rt.last_os_error=Some(99);
 let before=rt.serial;let mut api=0;let mut lookup=0;
 let scratch_word=rt.offset(sp,-64).unwrap();if mode==16{rt.store(scratch_word,32,CrtValue::ProtectedReturn(999)).unwrap();}if mode==17{rt.store(scratch_word,32,CrtValue::scalar(0x12345678)).unwrap();}
 if mode==11{rt.free_allocation(p).unwrap();}
 let result=original_free(&mut rt,&mut cpu,&mut|rt,heap,flags,got|{
  api+=1;assert_eq!(heap,h);assert_eq!(flags,0);assert_eq!(got,if mode==10{alias}else{p});
  rt.store(other,32,CrtValue::scalar(92))?;
  if mode==12{return Err("independent API interruption");}
  Ok((if mode==1{7}else{0},if mode==5{None}else{Some(match mode{3=>87,4=>u32::MAX,_=>5})}))
 },&mut|rt,c|{
  lookup+=1;assert!(rt.valid(p,0).is_err());assert_eq!(rt.load(other,32)?,CrtValue::scalar(92));
  if mode==6{rt.store(other,32,CrtValue::scalar(93))?;return Err("independent errno acquisition failure");}
  if mode==7{rt.retire_region(ptd)?;}
  c.clobber(if mode==8{CrtValue::scalar(0)}else if mode==9{CrtValue::Pointer(p)}else if mode==13{CrtValue::scalar(ptd.address())}else{CrtValue::Pointer(ptd)});
  c.finish(rt)
 });
 match mode{
  0=>{result.unwrap();assert_eq!(api,0);assert_eq!(lookup,0);assert_eq!(rt.last_os_error,Some(99));rt.valid(p,40).unwrap();},
  1=>{result.unwrap();assert_eq!(api,1);assert_eq!(lookup,0);assert!(rt.valid(alias,1).is_err());assert!(rt.uncertain_allocations.is_empty());rt.take_ptd_free_completion(p,before).unwrap();assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(73));},
  2|3|4|8|14|15|17=>{result.unwrap();assert_eq!(api,1);assert_eq!(lookup,1);let expected=match mode{3=>22,4=>22,_=>13};assert_eq!(rt.errno,Some(expected));assert_eq!(rt.load(if mode==8{fallback}else{cell},32).unwrap(),CrtValue::scalar(expected as u32));assert!(rt.valid(alias,0).is_err());assert_eq!(rt.uncertain_allocations,[p]);assert!(rt.memory.validate(p.cap,p.owner).is_ok());assert!(rt.free_allocation(p).is_err());assert!(rt.store(alias,8,CrtValue::scalar(0)).is_err());assert!(rt.retired.iter().all(|q|q.cap!=p.cap));
   if mode==14{assert_eq!(rt.take_ptd_free_completion(p,rt.serial),Err("C++ PTD free effect missing"));}
   if mode==15{assert_eq!(rt.take_ptd_free_completion(other,before),Err("C++ PTD free effect missing"));}
   rt.take_ptd_free_completion(p,before).unwrap();assert_eq!(rt.take_ptd_free_completion(p,before),Err("C++ PTD free effect missing"));},
  5|6|7|9|10|11|12|13|16=>{assert_eq!(result,Err(match mode{5=>"CRT scalar knowledge/type",6=>"independent errno acquisition failure",7|9|11=>"CRT stale/foreign pointer",10=>"CRT HeapFree whole unowned buffer",12=>"independent API interruption",13=>"errno PTD unknown or forged pointer",16=>"free errno private scratch crosses protected activation",_=>unreachable!()}),"mode {mode}");assert!(!cpu.returned);if !matches!(mode,10..=12){assert_eq!(rt.uncertain_allocations,[p]);assert_eq!(rt.take_ptd_free_completion(p,before),Err("C++ PTD free effect missing"));}if mode==7{assert_eq!(rt.load(cell,32),Err("CRT stale/foreign pointer"));}else{assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(73));}},
  _=>unreachable!()
 }
 if matches!(mode,0..=4|8|14|15|17){assert!(cpu.returned);for r in [3,5,6,7]{assert_eq!(cpu.r[r],saved[r]);}assert!(original_free(&mut rt,&mut cpu,&mut|_,_,_,_|panic!("replayed API"),&mut|_,_|panic!("replayed errno")).is_err());}
 if mode==6{assert_eq!(rt.load(other,32).unwrap(),CrtValue::scalar(93));}
 if mode==16{assert_eq!(rt.load(scratch_word,32).unwrap(),CrtValue::ProtectedReturn(999));}
 if mode==17{assert_eq!(rt.load(scratch_word,32).unwrap(),CrtValue::Scalar{bits:0,known:0});}
}
"#,
        "free-errno-owned",
    );
}
#[test]
fn original_free_rejects_changed_code_and_mapping() {
    use crate::crt_error_map::{prove, Region};
    let mapper = crate::crt_ptd::raw(MAPPER);
    let search = crate::crt_ptd::raw(SEARCH);
    let updater = crate::crt_ptd::raw(UPDATER);
    let table = crate::crt_ptd::raw(TABLE);
    for at in [0, 1, 2, 3] {
        let mut wrong = mapper.clone();
        wrong[at] = 0xcc;
        assert!(prove(
            Region {
                va: 0x407c12,
                bytes: &wrong
            },
            Region {
                va: 0x407b93,
                bytes: &search
            },
            Region {
                va: 0x407c94,
                bytes: &updater
            },
            Region {
                va: 0x416038,
                bytes: &table
            },
            (0x400000, 0x41e000)
        )
        .is_err());
    }

    let bytes = crate::crt_ptd::raw(FREE);
    for at in [0, 8, 22, 26, 39, 48, 53, 57] {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        assert_eq!(source(&changed), Err("original free code binding".into()));
    }
}

#[test]
fn failed_free_receipt_cannot_cross_runtime_thread_or_reauthorize_aliases() {
    crate::crt_stream_callees_tests::native(
        "",
        r#"
for mode in 0..10 {
 let(mut rt,init)=CrtStreamRuntime::new_initializing(1,2,0x8000,32768).unwrap();let CrtValue::Heap(heap)=rt.process_heap_result(init,true,Some(false)).unwrap()else{panic!()};
 let p=rt.allocate(40,true,true).unwrap().unwrap();let alias=rt.offset(p,16).unwrap();let other=rt.allocate(40,true,true).unwrap().unwrap();let before=rt.serial;
 let(mut foreign,fi)=CrtStreamRuntime::new_initializing(1,2,0x8000,32768).unwrap();let CrtValue::Heap(fh)=foreign.process_heap_result(fi,true,Some(false)).unwrap()else{panic!()};
 if mode==0{assert_eq!(rt.heap_free_result(fh,0,p,0,Some(5)).err(),Some("CRT heap owner/lifetime"));rt.valid(p,40).unwrap();continue;}
 if mode==1{assert_eq!(rt.heap_free_result(heap,1,p,0,Some(5)).err(),Some("CRT HeapFree domain"));rt.valid(p,40).unwrap();continue;}
 if mode==2{let cut=rt.subrange(p,20).unwrap();assert_eq!(rt.heap_free_result(heap,0,cut,0,Some(5)).err(),Some("CRT HeapFree whole unowned buffer"));rt.valid(p,40).unwrap();continue;}
 let receipt=rt.heap_free_result(heap,0,p,0,Some(5)).unwrap();assert_eq!(rt.last_error(),Ok(5));
 assert!(rt.valid(alias,0).is_err());assert!(rt.offset(alias,0).is_err());assert!(rt.load(alias,32).is_err());assert!(rt.free_allocation(p).is_err());assert!(rt.bind_errno_cell(alias).is_err());rt.valid(other,40).unwrap();
 assert_eq!(rt.memory.read(p.address(),40).unwrap(),[0;40]);assert!(rt.map_region(p.address(),40,CrtRegionKind::Context,None).is_err());
 assert_eq!(rt.take_ptd_free_completion(p,before),Err("C++ PTD free effect missing"));
 if mode==3{assert_eq!(foreign.complete_heap_free(receipt),Err("CRT HeapFree foreign completion"));}
 else if mode==4{rt.thread+=1;assert_eq!(rt.complete_heap_free(receipt),Err("CRT HeapFree foreign completion"));rt.thread-=1;}
 else if mode==5{drop(receipt);}
 else{rt.complete_heap_free(receipt).unwrap();if mode==6{assert_eq!(rt.take_ptd_free_completion(p,rt.serial),Err("C++ PTD free effect missing"));}
  if mode==7{assert_eq!(rt.take_ptd_free_completion(other,before),Err("C++ PTD free effect missing"));}
  rt.take_ptd_free_completion(p,before).unwrap();
 }
 assert_eq!(rt.take_ptd_free_completion(p,before),Err("C++ PTD free effect missing"));assert!(rt.heap_free_result(heap,0,p,1,None).is_err());assert!(rt.memory.validate(p.cap,p.owner).is_ok());
}
"#,
        "free-receipt-lifetime",
    );
}
