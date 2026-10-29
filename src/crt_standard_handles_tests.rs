//! Original standard-handle initialization component, not process startup proof.
use super::{
    crt_stream_emit,
    crt_stream_ir::{Graph, Target},
};
#[test]
fn original_standard_handles_preserve_inheritance_and_classify_api_results() {
    let bytes:Vec<u8>="8bff53565733ff8bc78bcf83e03fc1f9066bf03803348d08cf4100837e18ff740c837e18fe7406804e2880eb758bc7c646288183e800741083e801740783e8016af4eb066af5eb026af65850ff157c5041008bd883fbff742b85db742753ff15bc50410085c0741c0fb6c0895e1883f8027506804e2840eb2983f8037524804e2808eb1e804e2840c74618feffffffa130cd410085c0740a8b04b8c74010feffffff4783ff030f855bffffff5f5e5bc3".as_bytes().chunks_exact(2).map(|x|u8::from_str_radix(std::str::from_utf8(x).unwrap(),16).unwrap()).collect();
    let graph = Graph::decode(&bytes, 0x4085e7).unwrap();
    let body=crt_stream_emit::emit_body(&graph,|pc,target|{
 let next=pc+graph.nodes[&pc].length;
 let kind=match target{Target::Import(0x41507c)=>0,Target::Import(0x4150bc)=>1,_=>return Err("unbound original low-I/O call".into())};
 Ok(format!("cpu.call_activation(rt,{next},4,|rt,child|{{let sp=CrtCpu::pointer(child.r[4])?;let argument=rt.load(rt.offset(sp,4)?,32)?;let index=CrtCpu::number(child.r[7])? as usize;events.push(({kind},index));child.r[0]=if {kind}==0{{if argument.known_scalar()?!=u32::MAX-9-index as u32{{return Err(\"standard selector\");}}match handles[index]{{CrtValue::Handle(id)=>rt.descriptor_identity(id)?,CrtValue::Scalar{{bits:0|u32::MAX,known:u32::MAX}}=>{{}},_=>return Err(\"standard handle effect provenance\")}};handles[index]}}else{{if argument!=handles[index]{{return Err(\"GetFileType handle identity\");}}types[index]}};child.flags=CrtFlags::unknown();child.r[1]=CrtValue::Scalar{{bits:0,known:0}};child.r[2]=CrtValue::Scalar{{bits:0,known:0}};child.finish_pop(rt,4)}})?;"))
 },&std::collections::BTreeMap::from([(0x41cf08,"CrtRegionKind::Module".into()),(0x41cd30,"CrtRegionKind::Module".into())]),4096).unwrap();
    let extra=format!("fn original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,handles:[CrtValue;3],types:[CrtValue;3],events:&mut Vec<(u32,usize)>)->Result<CrtValue,&'static str>{{{body}}}");
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
