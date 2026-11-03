//! Original standard-handle initialization component, not process startup proof.
use super::{
    crt_stream_emit,
    crt_stream_ir::{Graph, Target},
};
fn standard_source() -> String {
    let bytes:Vec<u8>="8bff53565733ff8bc78bcf83e03fc1f9066bf03803348d08cf4100837e18ff740c837e18fe7406804e2880eb758bc7c646288183e800741083e801740783e8016af4eb066af5eb026af65850ff157c5041008bd883fbff742b85db742753ff15bc50410085c0741c0fb6c0895e1883f8027506804e2840eb2983f8037524804e2808eb1e804e2840c74618feffffffa130cd410085c0740a8b04b8c74010feffffff4783ff030f855bffffff5f5e5bc3".as_bytes().chunks_exact(2).map(|x|u8::from_str_radix(std::str::from_utf8(x).unwrap(),16).unwrap()).collect();
    let graph = Graph::decode(&bytes, 0x4085e7).unwrap();
    let body=crt_stream_emit::emit_body(&graph,|pc,target|{
 let next=pc+graph.nodes[&pc].length;
 let kind=match target{Target::Import(0x41507c)=>0,Target::Import(0x4150bc)=>1,_=>return Err("unbound original low-I/O call".into())};
 Ok(format!("cpu.call_activation(rt,{next},4,|rt,child|{{let sp=CrtCpu::pointer(child.r[4])?;let argument=rt.load(rt.offset(sp,4)?,32)?;let index=CrtCpu::number(child.r[7])? as usize;events.push(({kind},index));child.r[0]=if {kind}==0{{if argument.known_scalar()?!=u32::MAX-9-index as u32{{return Err(\"standard selector\");}}match handles[index]{{CrtValue::Handle(id)=>rt.descriptor_identity(id)?,CrtValue::Scalar{{bits:0|u32::MAX,known:u32::MAX}}=>{{}},_=>return Err(\"standard handle effect provenance\")}};handles[index]}}else{{if argument!=handles[index]{{return Err(\"GetFileType handle identity\");}}types[index]}};child.flags=CrtFlags::unknown();child.r[1]=CrtValue::Scalar{{bits:0,known:0}};child.r[2]=CrtValue::Scalar{{bits:0,known:0}};child.finish_pop(rt,4)}})?;"))
 },&std::collections::BTreeMap::from([(0x41cf08,"CrtRegionKind::Module".into()),(0x41cd30,"CrtRegionKind::Module".into())]),4096).unwrap();
    format!("fn original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,handles:[CrtValue;3],types:[CrtValue;3],events:&mut Vec<(u32,usize)>)->Result<CrtValue,&'static str>{{{body}}}")
}
#[test]
fn original_standard_handles_preserve_inheritance_and_classify_api_results() {
    let extra = standard_source();
    super::crt_stream_callees_tests::native(
        &extra,
        r#"
for fault in 0..5{
for (kind,want,valid) in [(1,0x81,true),(2,0xc1,true),(3,0x89,true),(0x8002,0xc1,true),(0,0xc1,false)] {
 let(mut rt,init)=CrtStreamRuntime::new_initializing_array(1,2,0x4000,3,32768).unwrap();
 let block=rt.map_region(0x5000,168,CrtRegionKind::Descriptor,None).unwrap();let dt=rt.map_region(0x41cf08,4,CrtRegionKind::Module,None).unwrap();rt.store(dt,32,CrtValue::Pointer(block)).unwrap();
 let table=rt.map_region(0x7000,12,CrtRegionKind::Module,None).unwrap();let global=rt.map_region(0x41cd30,4,CrtRegionKind::Module,None).unwrap();rt.store(global,32,CrtValue::Pointer(table)).unwrap();
 let id=rt.bind_descriptor(0,44).unwrap();let acquired=rt.bind_descriptor(2,55).unwrap();
 for i in 0..3{rt.store(rt.offset(table,i*4).unwrap(),32,CrtValue::Pointer(rt.offset(rt.file(),i*56).unwrap())).unwrap();rt.store(rt.offset(rt.file(),i*56+16).unwrap(),32,CrtValue::scalar(91+i as u32)).unwrap();rt.store(rt.offset(block,i*56+24).unwrap(),32,if i==0{CrtValue::Handle(id)}else{CrtValue::scalar(u32::MAX)}).unwrap();rt.store(rt.offset(block,i*56+40).unwrap(),8,CrtValue::scalar(1)).unwrap();}
 let stack=rt.map_region(0x8000,256,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,224).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();let saved=cpu.r;let mut events=vec![];
 let foreign=if fault==3{let(mut other,_)=CrtStreamRuntime::new_initializing(1,2,0x4000,32768).unwrap();Some(other.bind_descriptor(2,55).unwrap())}else{None};
 if fault==2{rt.store(dt,32,CrtValue::scalar(block.address())).unwrap();}if fault==4{rt.store(dt,32,CrtValue::Pointer(rt.offset(block,164).unwrap())).unwrap();}
 let result=original(&mut rt,&mut cpu,[CrtValue::Scalar{bits:0,known:0},CrtValue::scalar(0),CrtValue::Handle(foreign.unwrap_or(acquired))],[CrtValue::Scalar{bits:0,known:0},CrtValue::Scalar{bits:0,known:0},if fault==1{CrtValue::Scalar{bits:0,known:0}}else{CrtValue::scalar(kind)}],&mut events);
 if fault!=0{assert!(result.is_err());assert!(!cpu.returned);if fault==1||fault==3{assert_eq!(rt.load(rt.offset(rt.file(),56+16).unwrap(),32).unwrap(),CrtValue::scalar(u32::MAX-1));assert_eq!(rt.load(rt.offset(block,112+40).unwrap(),8).unwrap(),CrtValue::scalar(0x81));}else{assert!(events.is_empty());}continue;}result.unwrap();
 assert_eq!(events,[(0,1),(0,2),(1,2)]);assert!(cpu.returned);for r in [3,5,6,7]{assert_eq!(cpu.r[r],saved[r]);}
 assert_eq!(rt.load(rt.offset(block,40).unwrap(),8).unwrap(),CrtValue::scalar(0x81));assert_eq!(rt.load(rt.offset(block,56+40).unwrap(),8).unwrap(),CrtValue::scalar(0xc1));assert_eq!(rt.load(rt.offset(block,112+40).unwrap(),8).unwrap(),CrtValue::scalar(want));
 assert_eq!(rt.load(rt.offset(block,112+24).unwrap(),32).unwrap(),if valid{CrtValue::Handle(acquired)}else{CrtValue::scalar(u32::MAX-1)});
 assert_eq!(rt.load(rt.offset(rt.file(),16).unwrap(),32).unwrap(),CrtValue::scalar(91));assert_eq!(rt.load(rt.offset(rt.file(),56+16).unwrap(),32).unwrap(),CrtValue::scalar(u32::MAX-1));assert_eq!(rt.load(rt.offset(rt.file(),112+16).unwrap(),32).unwrap(),CrtValue::scalar(if valid{93}else{u32::MAX-1}));rt.end_initialization(init).unwrap();
}}
"#,
        "standard-handles",
    );
}

fn inherited_source() -> String {
    inherited_source_for(None)
}
pub(super) fn inherited_source_for(registered_allocator: Option<&str>) -> String {
    let inherited:Vec<u8>="8bff558bec83ec488d45b850ff153850410066837dea000f8491000000578b7dec85ff0f84840000008b0753568d5f04be0020000003d83bc60f4cf056e8b13900003b3508d14100590f4f3508d141008975fc33f68b45fc85c0744f833bff7442833bfe743d8a4c3e04f6c1017434f6c108750cff33ff15bc50410085c074208bc68bce83e03fc1f9066bd0388b0303148d08cf41008942188a443e048842288b45fc4683c3043bf075b15e5b5fc9c3".as_bytes().chunks_exact(2).map(|x|u8::from_str_radix(std::str::from_utf8(x).unwrap(),16).unwrap()).collect();
    let graph = Graph::decode(&inherited, 0x408537).unwrap();
    let body=crt_stream_emit::emit_body(&graph,|pc,target|{
 let next=pc+graph.nodes[&pc].length;
 let code=match target{
 Target::Import(0x415038)=>"let p=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;rt.valid(p,68)?;rt.store(rt.offset(p,50)?,16,CrtValue::scalar(if disabled{0}else{serialized.size}))?;if !disabled{rt.store(rt.offset(p,52)?,32,CrtValue::Pointer(serialized))?;}child.finish_pop(rt,4)".to_string(),
 Target::Direct(0x40bf2a)=>registered_allocator.unwrap_or("let n=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;allocations.push(n);if n>3{return Err(\"descriptor allocation effect unclosed\");}child.r[0]=CrtValue::scalar(0);child.finish(rt)").to_string(),
 Target::Import(0x4150bc)=>"let value=rt.load(rt.offset(sp,4)?,32)?;let CrtValue::Handle(id)=value else{return Err(\"inherited handle provenance\");};rt.descriptor_identity(id)?;queries.push(id.number);child.r[0]=if id.number==0{CrtValue::scalar(1)}else{CrtValue::Scalar{bits:0,known:0}};child.finish_pop(rt,4)".to_string(),
 _=>return Err("unbound inherited call".into())};
 let pop=if target==Target::Direct(0x40bf2a){0}else{4};
 Ok(format!("cpu.call_activation(rt,{next},{pop},|rt,child|{{let sp=CrtCpu::pointer(child.r[4])?;child.clobber(CrtValue::Scalar{{bits:0,known:0}});{code}}})?;"))
 },&std::collections::BTreeMap::from([(0x41cf08,"CrtRegionKind::Module".into()),(0x41d108,"CrtRegionKind::Module".into())]),4096).unwrap();
    let name = if registered_allocator.is_some() {
        "inherit_registered"
    } else {
        "inherit"
    };
    let more = if registered_allocator.is_some() {
        ",e:&mut NormalCallEpoch<'_>,init:CrtInitialization"
    } else {
        ""
    };
    format!("{}\nfn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,serialized:CrtPointer,disabled:bool,allocations:&mut Vec<u32>,queries:&mut Vec<u32>{more})->Result<CrtValue,&'static str>{{{body}}}",if registered_allocator.is_some(){String::new()}else{standard_source()})
}
#[test]
fn original_inherited_records_feed_standard_initialization_with_checked_bounds() {
    let extra = inherited_source();
    super::crt_stream_callees_tests::native(
        &extra,
        r#"
for fault in 0..7 {
 let(mut rt,init)=CrtStreamRuntime::new_initializing_array(1,2,0x4000,3,32768).unwrap();let block=rt.map_region(0x5000,168,CrtRegionKind::Descriptor,Some(&[0;168])).unwrap();
 let dt=rt.map_region(0x41cf08,4,CrtRegionKind::Module,None).unwrap();rt.store(dt,32,CrtValue::Pointer(block)).unwrap();rt.map_region(0x41d108,4,CrtRegionKind::Module,Some(&3u32.to_le_bytes())).unwrap();rt.map_region(0x41cd30,4,CrtRegionKind::Module,Some(&[0;4])).unwrap();
 let ids=[rt.bind_descriptor(0,44).unwrap(),rt.bind_descriptor(1,45).unwrap(),rt.bind_descriptor(2,46).unwrap()];for i in 0..3{rt.store(rt.offset(block,i*56+24).unwrap(),32,CrtValue::scalar(u32::MAX)).unwrap();}
 let serialized=rt.map_region(0x9000,19,CrtRegionKind::Result,None).unwrap();rt.store(serialized,32,if fault==2{CrtValue::Scalar{bits:0,known:0}}else{CrtValue::scalar(3)}).unwrap();for(i,f)in[1,9,1].into_iter().enumerate(){rt.store(rt.offset(serialized,4+i as i64).unwrap(),8,CrtValue::scalar(f)).unwrap();}
 rt.store(rt.offset(serialized,7).unwrap(),32,CrtValue::Handle(ids[0])).unwrap();rt.store(rt.offset(serialized,11).unwrap(),32,CrtValue::Handle(ids[1])).unwrap();rt.store(rt.offset(serialized,15).unwrap(),32,CrtValue::scalar(u32::MAX)).unwrap();
 if fault==3{rt.store(rt.offset(serialized,7).unwrap(),32,CrtValue::scalar(44)).unwrap();}if fault==4{rt.store(serialized,32,CrtValue::scalar(4)).unwrap();}
 let serialized=if fault==1{rt.subrange(serialized,12).unwrap()}else{serialized};let stack=rt.map_region(0xa000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,3072).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();let saved=cpu.r;let(mut alloc,mut queries)=(vec![],vec![]);
 if fault==5{rt.retire_region(serialized).unwrap();}
 let result=inherit(&mut rt,&mut cpu,serialized,fault==6,&mut alloc,&mut queries);
 if fault==6{result.unwrap();assert!(alloc.is_empty());assert!(queries.is_empty());assert!(cpu.returned);continue;}
 if fault!=0{assert!(result.is_err());assert!(!cpu.returned);if fault==1{assert_eq!(queries,[0]);assert_eq!(rt.load(rt.offset(block,24).unwrap(),32).unwrap(),CrtValue::Handle(ids[0]));assert_eq!(rt.load(rt.offset(block,80).unwrap(),32).unwrap(),CrtValue::scalar(u32::MAX));}continue;}result.unwrap();assert_eq!(alloc,[3]);assert_eq!(queries,[0]);for i in[3,5,6,7]{assert_eq!(cpu.r[i],saved[i]);}
 assert_eq!(rt.load(rt.offset(block,24).unwrap(),32).unwrap(),CrtValue::Handle(ids[0]));assert_eq!(rt.load(rt.offset(block,80).unwrap(),32).unwrap(),CrtValue::Handle(ids[1]));
 rt.store(sp,32,CrtValue::ProtectedReturn(2)).unwrap();let mut cpu=CrtCpu::new(sp,2).unwrap();let mut events=vec![];
 original(&mut rt,&mut cpu,[CrtValue::Scalar{bits:0,known:0},CrtValue::Scalar{bits:0,known:0},CrtValue::Handle(ids[2])],[CrtValue::Scalar{bits:0,known:0},CrtValue::Scalar{bits:0,known:0},CrtValue::scalar(3)],&mut events).unwrap();assert_eq!(events,[(0,2),(1,2)]);
 for(i,want)in[0x81,0x89,0x89].into_iter().enumerate(){assert_eq!(rt.load(rt.offset(block,i as i64*56+40).unwrap(),8).unwrap(),CrtValue::scalar(want));}rt.end_initialization(init).unwrap();
}
"#,
        "inherited-handles",
    );
}

#[test]
fn word_compare_and_signed_selection_keep_independent_boundaries() {
    let emit = |bytes: &[u8], name: &str| {
        let graph = Graph::decode(bytes, 0x1000).unwrap();
        let body = crt_stream_emit::emit_body(
            &graph,
            |_, _| Err("unexpected call".into()),
            &Default::default(),
            16,
        )
        .unwrap();
        format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}")
    };
    let extra = [
        emit(&[0x66, 0x83, 0x3f, 1, 0xc3], "word"),
        emit(&[0x66, 0x83, 0x3f, 0xff, 0xc3], "negative_word"),
        emit(&[0x39, 0xc8, 0x0f, 0x4c, 0xc2, 0xc3], "less"),
        emit(&[0x39, 0xc8, 0x0f, 0x4f, 0x07, 0xc3], "greater"),
        emit(&[0x0f, 0x4c, 0xc2, 0xc3], "unknown"),
    ]
    .join("\n");
    for bytes in [
        &[0x66, 0x83, 0xf8, 0, 0xc3][..],
        &[0x66, 0x89, 0xc7, 0xc3], // word register destination remains unsupported
        &[0x67, 0x66, 0x89, 0x07, 0xc3],
        &[0xf0, 0x66, 0x89, 0x07, 0xc3],
        &[0x67, 0x66, 0x83, 0x3f, 0, 0xc3],
        &[0xf0, 0x66, 0x83, 0x3f, 0, 0xc3],
    ] {
        assert!(Graph::decode(bytes, 0x1000).is_err());
    }
    super::crt_stream_callees_tests::native(
        &extra,
        r#"
for (value,want) in [(0,[true,false,true,false]),(1,[false,true,false,false]),(0x7fff,[false,false,false,false]),(0x8000,[false,false,false,true]),(0xffff,[false,false,true,false])] {
 let mut rt=CrtStreamRuntime::new(1,2,0x4000,32768).unwrap();let p=rt.map_region(0x5000,4,CrtRegionKind::Module,None).unwrap();rt.store(p,16,CrtValue::scalar(value)).unwrap();let s=rt.map_region(0x8000,64,CrtRegionKind::Stack,None).unwrap();rt.store(s,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(s,1).unwrap();cpu.r[7]=CrtValue::Pointer(p);cpu.entry=cpu.r;word(&mut rt,&mut cpu).unwrap();assert_eq!([cpu.flags.cf.unwrap(),cpu.flags.zf.unwrap(),cpu.flags.sf.unwrap(),cpu.flags.of.unwrap()],want);
}
for (value,want) in [(0,[true,false,false,false]),(0x8000,[true,false,true,false]),(0x7fff,[true,false,true,true])] {
 let mut rt=CrtStreamRuntime::new(1,2,0x4000,32768).unwrap();let p=rt.map_region(0x5000,2,CrtRegionKind::Module,None).unwrap();rt.store(p,16,CrtValue::scalar(value)).unwrap();let sp=rt.map_region(0x8000,64,CrtRegionKind::Stack,None).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut c=CrtCpu::new(sp,1).unwrap();c.r[7]=CrtValue::Pointer(p);c.entry=c.r;negative_word(&mut rt,&mut c).unwrap();assert_eq!([c.flags.cf.unwrap(),c.flags.zf.unwrap(),c.flags.sf.unwrap(),c.flags.of.unwrap()],want);
}
for (x,y,small,big) in [(0x80000000,0x7fffffff,77,0x80000000),(0x7fffffff,0x80000000,0x7fffffff,99),(u32::MAX,0,77,u32::MAX),(0,u32::MAX,0,99),(1,1,1,1)] {
 for use_greater in [false,true]{let mut rt=CrtStreamRuntime::new(1,2,0x4000,32768).unwrap();let p=rt.map_region(0x5000,4,CrtRegionKind::Module,Some(&99u32.to_le_bytes())).unwrap();let s=rt.map_region(0x8000,64,CrtRegionKind::Stack,None).unwrap();rt.store(s,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(s,1).unwrap();cpu.r[0]=CrtValue::scalar(x);cpu.r[1]=CrtValue::scalar(y);cpu.r[2]=CrtValue::scalar(77);cpu.r[7]=CrtValue::Pointer(p);cpu.entry=cpu.r;let result=if use_greater{greater(&mut rt,&mut cpu)}else{less(&mut rt,&mut cpu)}.unwrap();assert_eq!(result,CrtValue::scalar(if use_greater{big}else{small}));}
}
let mut rt=CrtStreamRuntime::new(1,2,0x4000,32768).unwrap();let p=rt.map_region(0x5000,2,CrtRegionKind::Module,None).unwrap();let s=rt.map_region(0x8000,64,CrtRegionKind::Stack,None).unwrap();rt.store(s,32,CrtValue::ProtectedReturn(1)).unwrap();let mut c=CrtCpu::new(s,1).unwrap();c.r[0]=CrtValue::scalar(0);c.r[1]=CrtValue::scalar(1);c.r[2]=CrtValue::scalar(77);c.r[7]=CrtValue::Pointer(p);c.entry=c.r;
assert!(greater(&mut rt,&mut c).is_err());assert!(!c.returned);assert_eq!(rt.load(s,32).unwrap(),CrtValue::ProtectedReturn(1));c.flags=CrtFlags::unknown();assert!(unknown(&mut rt,&mut c).is_err());assert!(word(&mut rt,&mut c).is_err());assert!(!c.returned);
"#,
        "word-and-signed",
    );
}

fn descriptor_source() -> String {
    descriptor_source_with_allocator(None)
}
fn descriptor_source_with_allocator(allocator: Option<&str>) -> String {
    let descriptor_constructor:Vec<u8>="8bff558bec515153566a386a40e864beffff8bf033db8975f8595985f675048bf3eb4b8d86000e00003bf07441578d7e208bf05368a00f00008d47e050e8bdc1ffff834ff8ff80670df8891f8d7f38895fcc8d47e0c747d000000a0ac647d40a895fd6885fda3bc675c98b75f85f53e862beffff598bc65e5bc9c3".as_bytes().chunks_exact(2).map(|x|u8::from_str_radix(std::str::from_utf8(x).unwrap(),16).unwrap()).collect();
    let descriptor_destructor:Vec<u8>="8bff558bec568b750885f67425538d9e000e0000578bfe3bf3740e57ff155450410083c7383bfb75f256e82cbeffff595f5b5e5dc3".as_bytes().chunks_exact(2).map(|x|u8::from_str_radix(std::str::from_utf8(x).unwrap(),16).unwrap()).collect();
    let mut extra = inherited_source();
    for (bytes, entry, name) in [
        (&descriptor_constructor, 0x40be7a, "construct"),
        (&descriptor_destructor, 0x40bef5, "destroy"),
    ] {
        let graph = Graph::decode(bytes, entry).unwrap();
        let body=crt_stream_emit::emit_body(&graph,|pc,target|{
            let next=pc+graph.nodes[&pc].length;
            let (pop,code)=match target {
                Target::Direct(0x407cf0)=>(0,allocator.unwrap_or("let n=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;let size=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;if size!=56{return Err(\"descriptor allocator element size\");}child.r[0]=match rt.alloc_descriptor_block(init,n,available)?{Some(p)=>{*allocated=Some(p);CrtValue::Pointer(p)},None=>CrtValue::scalar(0)};child.finish(rt)")),
                Target::Direct(0x408079)=>(12,"let p=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;if rt.load(rt.offset(sp,8)?,32)?.known_scalar()?!=4000{return Err(\"descriptor spin count\");}let flags=rt.load(rt.offset(sp,12)?,32)?.known_scalar()?;let result=if *calls==fail_at{0}else{1};*calls+=1;if !rt.construct_record_lock_result(init,p,flags,result)?{return Err(\"original continuation after failed lock is unclosed\");}child.r[0]=CrtValue::scalar(result);child.finish_pop(rt,12)"),
                Target::Import(0x415054)=>(4,"let p=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;rt.destroy_record_lock(init,p)?;*calls+=1;child.finish_pop(rt,4)"),
                Target::Direct(0x407d50)=>(0,"match rt.load(rt.offset(sp,4)?,32)?{CrtValue::Scalar{bits:0,known:u32::MAX}=>{},CrtValue::Pointer(p)=>rt.free_initialization(init,p)?,_=>return Err(\"free provenance\")};child.finish(rt)"),
                _=>return Err("descriptor call unbound".into()),
            };
            Ok(format!("cpu.call_activation(rt,{next},{pop},|rt,child|{{let sp=CrtCpu::pointer(child.r[4])?;child.clobber(CrtValue::Scalar{{bits:0,known:0}});{code}}})?;"))
        },&Default::default(),8192).unwrap();
        extra.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,available:bool,fail_at:usize,calls:&mut usize,allocated:&mut Option<CrtPointer>)->Result<CrtValue,&'static str>{{{body}}}"));
    }
    extra
}
#[test]
fn original_descriptor_construction_connects_inheritance_and_destruction() {
    let extra = descriptor_source();
    super::crt_stream_callees_tests::native(
        &extra,
        r#"
for fault in 0..4 {
 let(mut rt,init)=CrtStreamRuntime::new_initializing_array(1,2,0x4000,3,32768).unwrap();
 let stack=rt.map_region(0xa000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,3072).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();cpu.r[1]=CrtValue::Scalar{bits:0,known:0};let saved=cpu.r;let(mut calls,mut allocated)=(0,None);
 let result=construct(&mut rt,&mut cpu,init,fault!=1,if fault==2{1}else{usize::MAX},&mut calls,&mut allocated);
 if fault==1{assert_eq!(result.unwrap(),CrtValue::scalar(0));assert!(cpu.returned);assert_eq!(calls,0);assert!(allocated.is_none());continue;}
 let block=allocated.unwrap();assert_eq!(block.kind,CrtRegionKind::Descriptor);
 if fault==2{assert!(result.is_err());assert!(!cpu.returned);assert_eq!(calls,2);assert_eq!(rt.record_objects.len(),1);assert_eq!(rt.load(rt.offset(block,24).unwrap(),32).unwrap(),CrtValue::scalar(u32::MAX));assert!(rt.load(rt.offset(block,56).unwrap(),32).unwrap().known_scalar().is_err());assert!(rt.free_initialization(init,block).is_err());continue;}
 assert_eq!(result.unwrap(),CrtValue::Pointer(block));assert_eq!(calls,64);for r in [3,5,6,7]{assert_eq!(cpu.r[r],saved[r]);}
 for i in 0..64 {let record=rt.offset(block,i*56).unwrap();assert!(rt.load(record,8).is_err());for(offset,width,value)in[(24,32,u32::MAX),(32,32,0),(36,32,0),(40,32,0x0a0a0000),(44,8,10),(46,32,0),(50,8,0)]{assert_eq!(rt.load(rt.offset(record,offset).unwrap(),width).unwrap(),CrtValue::scalar(value));}}
 let dt=rt.map_region(0x41cf08,4,CrtRegionKind::Module,None).unwrap();rt.store(dt,32,CrtValue::Pointer(block)).unwrap();rt.map_region(0x41d108,4,CrtRegionKind::Module,Some(&64u32.to_le_bytes())).unwrap();rt.map_region(0x41cd30,4,CrtRegionKind::Module,Some(&[0;4])).unwrap();
 let ids=[rt.bind_descriptor(0,44).unwrap(),rt.bind_descriptor(1,45).unwrap(),rt.bind_descriptor(2,46).unwrap()];
 let serialized=rt.map_region(0x9000,19,CrtRegionKind::Result,None).unwrap();rt.store(serialized,32,CrtValue::scalar(3)).unwrap();for(i,f)in[1,9,1].into_iter().enumerate(){rt.store(rt.offset(serialized,4+i as i64).unwrap(),8,CrtValue::scalar(f)).unwrap();}
 for(i,v)in[CrtValue::Handle(ids[0]),CrtValue::Handle(ids[1]),CrtValue::scalar(u32::MAX)].into_iter().enumerate(){rt.store(rt.offset(serialized,7+i as i64*4).unwrap(),32,v).unwrap();}
 rt.store(sp,32,CrtValue::ProtectedReturn(2)).unwrap();let mut cpu=CrtCpu::new(sp,2).unwrap();let(mut alloc,mut queries)=(vec![],vec![]);inherit(&mut rt,&mut cpu,serialized,false,&mut alloc,&mut queries).unwrap();assert_eq!(queries,[0]);assert_eq!(alloc,[3]);
 rt.store(sp,32,CrtValue::ProtectedReturn(3)).unwrap();let mut cpu=CrtCpu::new(sp,3).unwrap();let mut events=vec![];original(&mut rt,&mut cpu,[CrtValue::Scalar{bits:0,known:0},CrtValue::Scalar{bits:0,known:0},CrtValue::Handle(ids[2])],[CrtValue::Scalar{bits:0,known:0},CrtValue::Scalar{bits:0,known:0},CrtValue::scalar(3)],&mut events).unwrap();assert_eq!(events,[(0,2),(1,2)]);for(i,want)in[0x81,0x89,0x89].into_iter().enumerate(){assert_eq!(rt.load(rt.offset(block,i as i64*56+40).unwrap(),8).unwrap(),CrtValue::scalar(want));}
 let held=if fault==3{Some(rt.lock_record(2,rt.offset(block,56).unwrap()).unwrap())}else{None};
 rt.store(sp,32,CrtValue::ProtectedReturn(4)).unwrap();rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::Pointer(block)).unwrap();let mut cpu=CrtCpu::new(sp,4).unwrap();calls=0;let result=destroy(&mut rt,&mut cpu,init,true,usize::MAX,&mut calls,&mut allocated);
 if let Some(held)=held{assert!(result.is_err());assert_eq!(calls,1);assert_eq!(rt.record_objects.len(),63);assert!(rt.load(rt.offset(block,24).unwrap(),32).is_ok());rt.unlock_record(held).unwrap();assert!(!cpu.returned);}else{result.unwrap();assert_eq!(calls,64);assert!(rt.record_objects.is_empty());assert!(rt.offset(block,0).is_err());assert!(rt.free_initialization(init,block).is_err());}
}
"#,
        "descriptor-construction",
    );
}

pub(super) fn manager_source() -> String {
    manager_source_with_allocator(None)
}
pub(super) fn manager_source_with_allocator(allocator: Option<&str>) -> String {
    let global_enter: Vec<u8> = "8bff558bec6b4508180550d1410050ff154c5041005dc3"
        .as_bytes()
        .chunks_exact(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
        .collect();
    let global_leave: Vec<u8> = "8bff558bec6b4508180550d1410050ff15505041005dc3"
        .as_bytes()
        .chunks_exact(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
        .collect();
    let enter = super::crt_global_lock::Proof::prove(&global_enter, 0x40bdcf, 0x41d150, 0x41504c)
        .unwrap()
        .emit("global_enter")
        .unwrap();
    let leave = super::crt_global_lock::Proof::prove(&global_leave, 0x40be17, 0x41d150, 0x415050)
        .unwrap()
        .emit("global_leave")
        .unwrap();

    let manager:Vec<u8>="33f68975e46a07e863feffff598975fc8bfea108d14100897de03945087c1f3934bd08cf41007531e8edfeffff8904bd08cf410085c075146a0c5e8975e4c745fcfeffffffe815000000eba2a108d1410083c040a308d1410047ebbb".as_bytes().chunks_exact(2).map(|x|u8::from_str_radix(std::str::from_utf8(x).unwrap(),16).unwrap()).collect();
    let manager_cleanup: Vec<u8> = "6a07e851feffff59c3"
        .as_bytes()
        .chunks_exact(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
        .collect();
    let cg = Graph::decode(&manager_cleanup, 0x40bfbf).unwrap();
    let cb=crt_stream_emit::emit_body(&cg,|pc,target|{if target!=Target::Direct(0x40be17){return Err("cleanup target changed".into());}let next=pc+cg.nodes[&pc].length;Ok(format!("cpu.call_activation(rt,{next},0,|rt,child|{{global_leave(rt,child,|rt,index|{{let lease=held.ok_or(\"cleanup without manager lease\")?;if index!=lease.index{{return Err(\"cleanup lock index\");}}rt.check_global(lease)?;if release_fails{{return Err(\"declared LeaveCriticalSection effect failed\");}}rt.unlock_global(lease)?;*held=None;events.push(2);Ok(())}})}})?;"))},&Default::default(),64).unwrap();
    let graph = Graph::decode_with_exits(&manager, 0x40bf60, &[0x40bf4e]).unwrap();
    let body=crt_stream_emit::emit_body_with_exit(&graph,|pc,target|{let next=pc+graph.nodes[&pc].length;let code=match target {
 Target::Direct(0x40bdcf)=>"global_enter(rt,child,|rt,index|{if index!=7{return Err(\"manager lock index\");}if acquire_fails{return Err(\"declared EnterCriticalSection effect failed\");}*held=Some(rt.lock_global(rt.thread,index)?);events.push(1);Ok(())})",
 Target::Direct(0x40be7a)=>"rt.check_global(held.ok_or(\"allocation without manager lock\")?)?;let mut calls=0;let mut allocated=None;construct(rt,child,init,allocations<successes,usize::MAX,&mut calls,&mut allocated)?;allocations+=1;Ok(child.r[0])",
 Target::Direct(0x40bfbf)=>"if rt.load(rt.offset(CrtCpu::pointer(child.r[5])?,-4)?,32)?.known_scalar()?!=u32::MAX-1{return Err(\"cleanup before scope disable\");}cleanup(rt,child,held,events,release_fails)",
 _=>return Err("manager call changed".into())};Ok(format!("cpu.call_activation(rt,{next},0,|rt,child|{{{code}}})?;"))},&std::collections::BTreeMap::from([(0x41cf08,"CrtRegionKind::Module".into()),(0x41d108,"CrtRegionKind::Module".into())]),16384,|_,_|Err("unbound FS".into()),|_,_|Ok(String::new()),|_,_|Ok(None),Some(0x40bf4e)).unwrap();
    let extra=format!("{enter} {leave} {} fn cleanup(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,held:&mut Option<CrtGlobalLock>,events:&mut Vec<u32>,release_fails:bool)->Result<CrtValue,&'static str>{{{cb}}} fn manager(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,successes:usize,acquire_fails:bool,release_fails:bool,held:&mut Option<CrtGlobalLock>,events:&mut Vec<u32>)->Result<CrtValue,&'static str>{{let mut allocations=0;{body}}}",descriptor_source_with_allocator(allocator));
    extra
}
#[test]
fn original_allocation_manager_scope_orders_lock_publication_and_cleanup() {
    let extra = manager_source();
    super::crt_stream_callees_tests::native(
        &extra,
        r#"
for fault in 0..6 {
 let(mut rt,init)=CrtStreamRuntime::new_initializing(1,2,0x4000,65536).unwrap();let lock=rt.map_region(0x41d1f8,24,CrtRegionKind::Module,None).unwrap();rt.construct_global_lock(init,7,lock,1).unwrap();
 let table=rt.map_region(0x41cf08,128*4,CrtRegionKind::Module,Some(&[0;512])).unwrap();let capacity=rt.map_region(0x41d108,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes())).unwrap();let stack=rt.map_region(0xa000,4096,CrtRegionKind::Stack,None).unwrap();let frame=rt.offset(stack,3072).unwrap();let sp=rt.offset(frame,-128).unwrap();rt.store(rt.offset(frame,8).unwrap(),32,CrtValue::scalar(if fault==4{0}else{64})).unwrap();rt.store(rt.offset(frame,-4).unwrap(),32,CrtValue::scalar(u32::MAX-1)).unwrap();rt.store(frame,32,CrtValue::OpaqueSaved(5)).unwrap();
 let mut cpu=CrtCpu::new(sp,700).unwrap();cpu.r[5]=CrtValue::Pointer(frame);cpu.r[1]=CrtValue::Scalar{bits:0,known:0};let(mut held,mut events)=(None,vec![]);
 let result=manager(&mut rt,&mut cpu,init,if fault==1{1}else if fault==5{0}else{2},fault==2,fault==3,&mut held,&mut events);
 let cap=rt.load(capacity,32).unwrap().known_scalar().unwrap();
 if fault==2{assert!(result.is_err());assert_eq!(cap,0);assert!(held.is_none());assert!(events.is_empty());assert_eq!(rt.load(rt.offset(frame,-4).unwrap(),32).unwrap(),CrtValue::scalar(u32::MAX-1));continue;}
 if fault==3{assert!(result.is_err());assert_eq!(cap,128);rt.check_global(held.unwrap()).unwrap();assert_eq!(events,[1]);assert_eq!(rt.load(rt.offset(frame,-4).unwrap(),32).unwrap(),CrtValue::scalar(u32::MAX-1));continue;}
 result.unwrap();assert!(!cpu.returned);assert!(held.is_none());assert_eq!(events,[1,2]);assert_eq!(cap,if fault==1{64}else if fault==4{64}else if fault==5{0}else{128});assert_eq!(CrtCpu::number(cpu.r[6]).unwrap(),if fault==1||fault==5{12}else{0});assert_eq!(rt.load(rt.offset(frame,-4).unwrap(),32).unwrap(),CrtValue::scalar(u32::MAX-1));
 if cap>0{let CrtValue::Pointer(p)=rt.load(table,32).unwrap() else{panic!()};assert_eq!(p.kind,CrtRegionKind::Descriptor);assert!(rt.record_lock_live(p).is_ok());}if fault==1{assert_eq!(rt.load(rt.offset(table,4).unwrap(),32).unwrap(),CrtValue::scalar(0));}
}
"#,
        "allocation-manager",
    );
}

pub(super) fn allocator_source() -> String {
    allocator_source_with_errno(None)
}
pub(super) fn allocator_source_with_errno(accessor: Option<&str>) -> String {
    allocator_source_mode(accessor, false)
}
pub(super) fn live_allocator_source(accessor: &str) -> String {
    allocator_source_mode(Some(accessor), true)
}
pub(super) fn live_allocator_with_lookup_source() -> String {
    live_allocator_source("errno_routed_call(rt,child,&mut *lookup)")
        .replace("expected_heap:CrtHeap,", "expected_heap:CrtHeap,lookup:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>,")
        .replace("expected_heap,success_after", "expected_heap,lookup,success_after")
}
fn allocator_source_mode(accessor: Option<&str>, live: bool) -> String {
    let heap_producer: Vec<u8> = "ff15f850410085c0a3c8d241000f95c0c3"
        .as_bytes()
        .chunks_exact(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
        .collect();
    let calloc_body:Vec<u8>="8bff558bec568b750885f6740c6ae033d258f7f63b450c72370faf750c33c04085f60f44f0eb14e8a4f4ffff85c0742056e89a4c00005985c07415566a08ff35c8d24100ff159450410085c074d9eb0de888ffffffc7000c00000033c05e5dc3".as_bytes().chunks_exact(2).map(|x|u8::from_str_radix(std::str::from_utf8(x).unwrap(),16).unwrap()).collect();
    let mode_getter: Vec<u8> = "a180ce410090c3"
        .as_bytes()
        .chunks_exact(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
        .collect();
    let mut extra = String::new();
    for (bytes, origin, name) in [
        (&heap_producer, 0x40c8f0, "heap_producer"),
        (&mode_getter, 0x4071c0, "mode_getter"),
        (&calloc_body, 0x407cf0, "calloc_original"),
    ] {
        if live && name == "heap_producer" {
            continue;
        }
        let graph = Graph::decode(bytes, origin).unwrap();
        let body=crt_stream_emit::emit_body(&graph,|pc,target|{let next=pc+graph.nodes[&pc].length;let(pop,code)=match target{
   Target::Import(0x4150f8)=>(0,"let value=rt.process_heap_result(init,heap_available,policy)?;child.clobber(value);child.finish(rt)"),
   Target::Import(0x415094)=>(12,"let sp=CrtCpu::pointer(child.r[4])?;let CrtValue::Heap(heap)=rt.load(rt.offset(sp,4)?,32)? else{return Err(\"HeapAlloc opaque heap identity\")};let flags=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;let size=rt.load(rt.offset(sp,12)?,32)?.known_scalar()?;allocations.push(size);let available=allocations.len()<=success_after.0||allocations.len()>success_after.1;child.clobber(match rt.heap_alloc_result(init,heap,flags,size,descriptor,available)?{Some(p)=>CrtValue::Pointer(p),None=>CrtValue::scalar(0)});child.finish_pop(rt,12)"),
   Target::Direct(0x4071c0)=>(0,"mode_getter(rt,child,init,heap_available,policy,success_after,descriptor,errno,allocations,handler)"),
   Target::Direct(0x40c9c0)=>(0,"let requested=rt.load(rt.offset(CrtCpu::pointer(child.r[4])?,4)?,32)?.known_scalar()?;let retry=handler(rt,requested)?;child.clobber(CrtValue::scalar(u32::from(retry)));child.finish(rt)"),
   Target::Direct(0x407ccd)=>(0,accessor.unwrap_or("rt.valid(errno,4)?;if errno.kind!=CrtRegionKind::Context||errno.size!=4||errno.address!=errno.base||!rt.regions.iter().any(|r|r.pointer==errno){return Err(\"errno owned thread-context role\");}child.clobber(CrtValue::Pointer(errno));child.finish(rt)")),
   _=>return Err("unbound allocator call".into())};Ok(format!("cpu.call_activation(rt,{next},{pop},|rt,child|{{{code}}})?;"))},&std::collections::BTreeMap::from([(0x41d2c8,"CrtRegionKind::Module".into()),(0x41ce80,"CrtRegionKind::Module".into())]),2048).unwrap();
        let entry = if name == "calloc_original" {
            "let sp=CrtCpu::pointer(cpu.r[4])?;if rt.load(rt.offset(sp,4)?,32)?.known_scalar()?==0||rt.load(rt.offset(sp,8)?,32)?.known_scalar()?==0{return Err(\"zero-request calloc domain unbound\");}"
        } else {
            ""
        };
        extra.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,init:CrtInitialization,heap_available:bool,policy:Option<bool>,success_after:(usize,usize),descriptor:bool,errno:CrtPointer,allocations:&mut Vec<u32>,handler:&mut impl FnMut(&mut CrtStreamRuntime,u32)->Result<bool,&'static str>)->Result<CrtValue,&'static str>{{{entry}{body}}}"));
    }
    if live {
        extra=extra.replace("let sp=CrtCpu::pointer(cpu.r[4])?;if rt.load(rt.offset(sp,4)?,32)?.known_scalar()?==0", "rt.heap_identity(expected_heap)?;if descriptor{return Err(\"live calloc descriptor authority rejected\");}let sp=CrtCpu::pointer(cpu.r[4])?;if rt.load(rt.offset(sp,4)?,32)?.known_scalar()?==0")
          .replace("init:CrtInitialization,heap_available:bool,policy:Option<bool>","expected_heap:CrtHeap")
          .replace("init,heap_available,policy,success_after","expected_heap,success_after")
          .replace("rt.heap_alloc_result(init,heap,flags,size,descriptor,available)?","{if descriptor||heap!=expected_heap{return Err(\"live calloc heap/role authority\");}rt.live_heap_alloc_result(heap,flags,size,available)?}")
          .replace("calloc_original(","calloc_live_original(").replace("mode_getter(","mode_getter_live(");
    }
    extra
}
#[test]
fn original_heap_producer_calloc_and_descriptor_constructor_preserve_error_paths() {
    let mut extra = allocator_source();
    extra.push_str(&descriptor_source_with_allocator(Some("let errno=rt.resolve_absolute(0x7000,CrtRegionKind::Context)?;let mut requests=vec![];let result=calloc_original(rt,child,init,true,Some(false),if available{(1,1)}else{(0,usize::MAX)},true,errno,&mut requests,&mut |_,_|Err(\"new handler remains unbound\"))?;if let CrtValue::Pointer(p)=result{*allocated=Some(p);}Ok(result)")));
    super::crt_stream_callees_tests::native(
        &extra,
        r#"
for fault in 0..13{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(1,2,0x8000,32768).unwrap();let heap_cell=rt.map_region(0x41d2c8,4,CrtRegionKind::Module,None).unwrap();let mode=rt.map_region(0x41ce80,4,CrtRegionKind::Module,None).unwrap();let errno=rt.map_region(0x7000,4,CrtRegionKind::Context,Some(&73u32.to_le_bytes())).unwrap();let observable=rt.map_region(0x7100,4,CrtRegionKind::Result,Some(&[0;4])).unwrap();
 rt.store(mode,32,if fault==4{CrtValue::Scalar{bits:0,known:0}}else{CrtValue::scalar(if fault==3||fault==5||fault==10||fault==11||fault==12{1}else{0})}).unwrap();let stack=rt.map_region(0x9000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,3072).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(77)).unwrap();let mut cpu=CrtCpu::new(sp,77).unwrap();let mut allocations=vec![];let mut handler_calls=0;let mut handler=|rt:&mut CrtStreamRuntime,size:u32|{assert_eq!(size,3584);handler_calls+=1;rt.store(observable,32,CrtValue::scalar(91))?;if fault==5{return Err("unbound handler continuation after prior write");}if fault==12{rt.retire_region(errno)?;}Ok(fault!=11&&fault!=12)};
 heap_producer(&mut rt,&mut cpu,init,fault!=6,if fault==7{None}else{Some(false)},(0,0),true,errno,&mut allocations,&mut handler).unwrap();assert!(cpu.returned);if fault!=6{assert!(cpu.r[0].known_scalar().is_err());assert!(CrtCpu::number(rt.load(heap_cell,32).unwrap()).is_err());assert_eq!(cpu.flags.sf,None);assert!(cpu.condition(10).is_err());}assert_eq!(cpu.get(0,8,0).unwrap(),CrtValue::scalar(if fault==6{0}else{1}));
 rt.store(sp,32,CrtValue::ProtectedReturn(78)).unwrap();rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::scalar(if fault==2{u32::MAX}else if fault==9{0}else{64})).unwrap();rt.store(rt.offset(sp,8).unwrap(),32,CrtValue::scalar(56)).unwrap();let mut cpu=CrtCpu::new(sp,78).unwrap();let saved=cpu.r;let outcome=calloc_original(&mut rt,&mut cpu,init,true,Some(false),if fault==0||fault==8{(1,1)}else if fault==3{(0,1)}else{(0,usize::MAX)},true,errno,&mut allocations,&mut handler);
 if [4,5,6,7,9,10,12].contains(&fault){assert!(outcome.is_err());assert!(!cpu.returned);if fault==12{assert!(rt.load(errno,32).is_err());assert_eq!(rt.load(observable,32).unwrap(),CrtValue::scalar(91));continue;}assert_eq!(rt.load(errno,32).unwrap(),CrtValue::scalar(73));if fault==5||fault==10{assert_eq!(rt.load(observable,32).unwrap(),CrtValue::scalar(91));}continue;}
 let result=outcome.unwrap();assert!(cpu.returned);assert_eq!(cpu.r[6],saved[6]);assert_eq!(cpu.r[5],saved[5]);
 if fault==1||fault==2||fault==11{assert_eq!(result,CrtValue::scalar(0));assert_eq!(rt.load(errno,32).unwrap(),CrtValue::scalar(12));assert_eq!(allocations.len(),if fault==2{0}else{1});}else{let CrtValue::Pointer(p)=result else{panic!()};assert_eq!(p.size,3584);assert_eq!(rt.load(p,32).unwrap(),CrtValue::scalar(0));assert_eq!(rt.load(errno,32).unwrap(),CrtValue::scalar(73));if fault==8{rt.store(sp,32,CrtValue::ProtectedReturn(79)).unwrap();let mut c=CrtCpu::new(sp,79).unwrap();c.r[1]=CrtValue::Scalar{bits:0,known:0};let(mut locks,mut block)=(0,None);let v=construct(&mut rt,&mut c,init,true,usize::MAX,&mut locks,&mut block).unwrap();assert_eq!(v,CrtValue::Pointer(block.unwrap()));assert_eq!(locks,64);assert_eq!(rt.record_objects.len(),64);assert_eq!(rt.load(rt.offset(block.unwrap(),24).unwrap(),32).unwrap(),CrtValue::scalar(u32::MAX));}if fault==3{assert_eq!(allocations,[3584,3584]);assert_eq!(rt.load(observable,32).unwrap(),CrtValue::scalar(91));}}
}
"#,
        "heap-calloc",
    );
}

#[test]
fn two_operand_imul_keeps_signed_overflow_unknowns_and_memory_ownership() {
    let mut extra = String::new();
    for (bytes, name) in [
        (&[0x0f, 0xaf, 0xc1, 0xc3][..], "register_product"),
        (&[0x0f, 0xaf, 0x07, 0xc3][..], "memory_product"),
    ] {
        let g = Graph::decode(bytes, 0x1000).unwrap();
        let body = crt_stream_emit::emit_body(
            &g,
            |_, _| Err("unexpected multiply call".into()),
            &Default::default(),
            4,
        )
        .unwrap();
        extra.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}"));
    }
    super::crt_stream_callees_tests::native(
        &extra,
        r#"
for(a,b,result,overflow)in[(2u32,3u32,6u32,false),(0x80000000,0xffffffff,0x80000000,true),(0x7fffffff,2,0xfffffffe,true),(0x7fffffff,0xffffffff,0x80000001,false),(0x80000000,1,0x80000000,false),(0xffffffff,0xffffffff,1,false),(65536,65536,0,true)]{
 for memory in [false,true]{let mut rt=CrtStreamRuntime::new(1,2,0x8000,32768).unwrap();let stack=rt.map_region(0x9000,256,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,224).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let p=rt.map_region(0x7000,4,CrtRegionKind::Input,Some(&b.to_le_bytes())).unwrap();let mut c=CrtCpu::new(sp,1).unwrap();c.r[0]=CrtValue::scalar(a);c.r[1]=CrtValue::scalar(b);c.r[7]=CrtValue::Pointer(p);c.entry=c.r;let v=if memory{memory_product(&mut rt,&mut c)}else{register_product(&mut rt,&mut c)}.unwrap();assert_eq!(v,CrtValue::scalar(result));assert_eq!(c.flags.cf,Some(overflow));assert_eq!(c.flags.of,Some(overflow));assert_eq!(c.flags.zf,None);assert_eq!(c.flags.sf,None);}
}
let mut rt=CrtStreamRuntime::new(1,2,0x8000,32768).unwrap();let stack=rt.map_region(0x9000,256,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,224).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut c=CrtCpu::new(sp,1).unwrap();c.r[0]=CrtValue::scalar(2);c.r[1]=CrtValue::Scalar{bits:3,known:0};assert!(register_product(&mut rt,&mut c).is_err());assert_eq!(c.r[0],CrtValue::scalar(2));assert!(!c.returned);
"#,
        "multiply-two-operands",
    );
    for bytes in [
        &[0x66, 0x0f, 0xaf, 0xc1, 0xc3][..],
        &[0xf0, 0x0f, 0xaf, 0xc1, 0xc3][..],
    ] {
        assert!(Graph::decode(bytes, 0x1000).is_err());
    }
}

pub(super) fn errno_source() -> String {
    let errno_router: Vec<u8> = "e8602600008bd0b830c1410085d28d4a100f45c1c3"
        .as_bytes()
        .chunks_exact(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
        .collect();
    let graph = Graph::decode(&errno_router, 0x407ccd).unwrap();
    let body=crt_stream_emit::emit_body_with_hooks(&graph,|pc,target|{if target!=Target::Direct(0x40a332){return Err("errno PTD target changed".into());}let next=pc+graph.nodes[&pc].length;Ok(format!("cpu.call_activation(rt,{next},0,|rt,child|{{let ptd=lookup(rt,child)?;match ptd{{CrtValue::Pointer(p)=>{{rt.valid(p,20)?;if p.kind!=CrtRegionKind::ThreadData||p.address!=p.base||!rt.regions.iter().any(|r|r.pointer==p){{return Err(\"errno PTD owner/extent\");}}}},CrtValue::Scalar{{bits:0,known:u32::MAX}}=>{{}},_=>return Err(\"errno PTD unknown or forged pointer\")}};Ok(ptd)}})?;"))},&Default::default(),32,|_,_|Err("no FS in errno router".into()),|_,_|Ok(String::new()),|_,pop|{if pop!=0{return Err("errno RET changed".into());}Ok(Some("let p=match cpu.r[0]{CrtValue::Pointer(p)=>{if p.kind!=CrtRegionKind::ThreadData{return Err(\"errno PTD result role\");}p},CrtValue::Scalar{bits:0x41c130,known:u32::MAX}=>rt.resolve_absolute(0x41c130,CrtRegionKind::Module)?,_=>return Err(\"errno result provenance\")};cpu.r[0]=CrtValue::Pointer(rt.bind_errno_cell(p)?);return cpu.finish(rt);".into()))}).unwrap();
    format!("fn errno_routed_call(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,mut lookup:impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{{body}}}fn errno_routed(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,mut lookup:impl FnMut(&mut CrtStreamRuntime)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{errno_routed_call(rt,cpu,|rt,child|{{let value=lookup(rt)?;child.clobber(value);child.finish(rt)}})}}")
}
#[test]
fn original_errno_router_binds_ptd_or_fallback_without_alias_or_lifetime_renewal() {
    super::crt_stream_callees_tests::native(
        &errno_source(),
        r#"
for fault in 0..9{
 let mut rt=CrtStreamRuntime::new(1,2,0x8000,32768).unwrap();let fallback=rt.map_region(0x41c130,4,CrtRegionKind::Module,Some(&73u32.to_le_bytes())).unwrap();let ptd=rt.map_region(0x7000,32,if fault==3{CrtRegionKind::Context}else{CrtRegionKind::ThreadData},None).unwrap();let cell=rt.offset(ptd,16).unwrap();rt.store(cell,32,CrtValue::scalar(19)).unwrap();let stack=rt.map_region(0x9000,256,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,224).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut c=CrtCpu::new(sp,1).unwrap();
 if fault==4{rt.retire_region(ptd).unwrap();}let foreign=if fault==7{let mut other=CrtStreamRuntime::new(1,2,0x8000,32768).unwrap();Some(other.map_region(0x7000,32,CrtRegionKind::ThreadData,None).unwrap())}else{None};let input=match fault{7=>CrtValue::Pointer(foreign.unwrap()),0=>CrtValue::scalar(0),2=>CrtValue::scalar(ptd.address()),5=>CrtValue::Scalar{bits:0,known:0},_=>CrtValue::Pointer(ptd)};
 let observed=rt.map_region(0x7200,4,CrtRegionKind::Result,Some(&[0;4])).unwrap();let result=errno_routed(&mut rt,&mut c,|rt|{if fault==8{rt.store(observed,32,CrtValue::scalar(91))?;return Err("unresolved lookup after prior effect");}Ok(input)});
 if [2,3,4,5,7,8].contains(&fault){assert!(result.is_err());assert!(rt.errno_cell.is_none());assert!(!c.returned);if fault==8{assert_eq!(rt.load(observed,32).unwrap(),CrtValue::scalar(91));}continue;}
 let selected=CrtCpu::pointer(result.unwrap()).unwrap();assert_eq!(selected.address(),if fault==0{fallback.address()}else{cell.address()});assert_eq!(rt.errno,Some(if fault==0{73}else{19}));
 rt.store(selected,32,CrtValue::scalar(12)).unwrap();assert_eq!(rt.errno,Some(12));let lock=rt.lock(2).unwrap();rt.set_errors(lock,Some(22),Some(5)).unwrap();assert_eq!(rt.load(selected,32).unwrap(),CrtValue::scalar(22));rt.set_errors(lock,None,None).unwrap();assert!(rt.load(selected,32).unwrap().known_scalar().is_err());assert_eq!(rt.errno,None);rt.unlock(lock).unwrap();assert!(rt.store(selected,32,CrtValue::Pointer(stack)).is_err());
 if fault==6{rt.retire_region(ptd).unwrap();assert_eq!(rt.errno,None);let lock=rt.lock(2).unwrap();assert!(rt.set_errors(lock,Some(7),None).is_err());rt.unlock(lock).unwrap();assert!(rt.load(selected,32).is_err());}
}
"#,
        "errno-route",
    );
}

#[test]
fn original_calloc_uses_live_heap_without_startup_or_descriptor_authority() {
    let extra=format!("{}{}",errno_source(),live_allocator_source("errno_routed(rt,child,|rt|Ok(CrtValue::Pointer(rt.resolve_absolute(0x7100,CrtRegionKind::ThreadData)?)))"));
    super::crt_stream_callees_tests::native(
        &extra,
        r#"
for mode in 0..9 {
 let(mut rt,init)=CrtStreamRuntime::new_initializing(1,2,0x8000,32768).unwrap();let CrtValue::Heap(heap)=rt.process_heap_result(init,true,Some(false)).unwrap()else{panic!()};
 let cell=rt.map_region(0x41d2c8,4,CrtRegionKind::Module,None).unwrap();rt.store(cell,32,CrtValue::Heap(heap)).unwrap();
 rt.map_region(0x41ce80,4,CrtRegionKind::Module,Some(&(if mode==2||mode==3{1u32}else{0}).to_le_bytes())).unwrap();
 let ptd=rt.map_region(0x7100,32,CrtRegionKind::ThreadData,None).unwrap();let errno=rt.offset(ptd,16).unwrap();rt.store(errno,32,CrtValue::scalar(73)).unwrap();rt.end_initialization(init).unwrap();
 assert!(rt.heap_alloc_result(init,heap,8,40,false,true).is_err());
 let(mut other,oi)=CrtStreamRuntime::new_initializing(1,2,0x8000,32768).unwrap();let CrtValue::Heap(foreign)=other.process_heap_result(oi,true,Some(false)).unwrap()else{panic!()};
 if mode==8{rt.retire_region(ptd).unwrap();}
 let stack=rt.map_region(0x9000,2048,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,1536).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();
 for(i,v)in [if mode==4{u32::MAX}else if mode==5{0}else{1},40].into_iter().enumerate(){rt.store(rt.offset(sp,4+i as i64*4).unwrap(),32,CrtValue::scalar(v)).unwrap();}
 let mut cpu=CrtCpu::new(sp,1).unwrap();let mut allocations=vec![];let mut retries=0;
 let result=calloc_live_original(&mut rt,&mut cpu,if mode==6{foreign}else{heap},if mode==0{(1,1)}else if mode==2{(0,1)}else{(0,usize::MAX)},mode==7,errno,&mut allocations,&mut|_,n|{assert_eq!(n,40);retries+=1;Ok(mode==2)});
 match mode{
  0|2=>{let p=CrtCpu::pointer(result.unwrap()).unwrap();assert_eq!(p.kind,CrtRegionKind::Buffer);assert_eq!(p.size,40);assert_eq!(rt.memory.read(p.address(),40).unwrap(),[0;40]);assert_eq!(allocations,if mode==0{vec![40]}else{vec![40,40]});assert_eq!(retries,if mode==0{0}else{1});assert_eq!(rt.load(errno,32).unwrap(),CrtValue::scalar(73));},
  1|3|4=>{assert_eq!(result.unwrap(),CrtValue::scalar(0));assert_eq!(rt.load(errno,32).unwrap(),CrtValue::scalar(12));assert_eq!(rt.errno,Some(12));assert_eq!(retries,usize::from(mode==3));if mode==4{assert!(allocations.is_empty());}},
  5|6|7|8=>{assert_eq!(result,Err(match mode{5=>"zero-request calloc domain unbound",6=>"CRT heap owner/lifetime",7=>"live calloc descriptor authority rejected",8=>"CRT undeclared absolute region/role",_=>unreachable!()}),"mode {mode}");assert!(!cpu.returned);if mode!=8{assert!(allocations.is_empty());}},
  _=>unreachable!()
 }
 if mode<=4{assert!(cpu.returned);assert_eq!(rt.initialization,None);}
}
"#,
        "live-heap-calloc",
    );
}
