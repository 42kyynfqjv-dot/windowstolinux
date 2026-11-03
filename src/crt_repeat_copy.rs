//! Consumer-bound repeated copies and original post-allocation instruction path.
use crate::crt_stream_ir::Graph;
#[cfg(test)]
use crate::crt_stream_ir::Op;
pub(crate) const POST_ALLOC:&str="8945fc5985c0750e50e8b9caffff83c8ffe9e10000008b73108dbdc8fdffffba880000008bca508b7648ff75f4f3a58bca8db5c8fdffff8bf8f3a5832000";
pub(crate) const NULL_EPILOG: &str = "595f5e8be55d8be35bc3";
pub(crate) fn source() -> Result<String, String> {
    let bytes = crate::crt_ptd::raw(POST_ALLOC);
    let tail = crate::crt_ptd::raw(NULL_EPILOG);
    let mut g = crate::crt_startup_table::graph(&bytes, 0x40b289)?;
    g.nodes.extend(Graph::decode(&tail, 0x40b380)?.nodes);
    let body = crate::crt_stream_emit::emit_body_with_repeat_copy(
        &g,
        |_, _| Ok("return Err(\"locale allocation failure cleanup unbound\");".into()),
        &Default::default(),
        256,
        |_, _| Err("locale post-allocation thread effect".into()),
        |_, _| Ok(String::new()),
        |_, pop| {
            if pop != 0 {
                return Err("locale post-allocation RET cleanup".into());
            }
            Ok(Some("return aligned.finish(rt,cpu);".into()))
        },
        Some(g.end),
        |_, _, _| Ok(None),
        |_, _| Err("locale post-allocation indirect effect".into()),
        |pc, width| {
            if width != 32 || !matches!(pc, 0x40b2b6 | 0x40b2c2) {
                return Err("locale repeated copy effect location/width".into());
            }
            Ok(format!(
                "inputs.validate(rt)?;aligned.live(rt,cpu)?;{}cpu.repeat_move_dwords(rt,136)?;",
                if pc == 0x40b2b6 {
                    "if cpu.r[1].known_scalar()?!=0{cpu.r[6]=CrtValue::Pointer(rt.module_word_pointer(inputs.image,cpu.r[6])?);}"
                } else {
                    ""
                }
            ))
        },
    )?;
    Ok(format!("fn locale_allocated_copy_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,aligned:&mut CrtAlignedActivation)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;aligned.live(rt,cpu)?;let p=CrtCpu::pointer(cpu.r[0])?;rt.valid(p,p.size)?;if p.kind!=CrtRegionKind::Buffer||p.address()!=p.base||p.size!=544||!rt.regions.iter().any(|r|r.heap&&r.pointer==p&&r.file_owner.is_none()){{return Err(\"locale copy allocation identity/extent\");}}for(address,bytes)in[(0x40b289u32,&{bytes:?}[..]),(0x40b380,&{tail:?}[..])]{{let q=rt.process_image_code(inputs.image,address,bytes.len()as u32)?;if rt.memory.read(q.address(),bytes.len()as u32).map_err(|_|\"locale copy code read\")?!=bytes{{return Err(\"locale copy code changed\");}}}}{body}}}"))
}

#[test]
fn repeated_copy_requires_dedicated_effect_and_exact_supported_encoding() {
    let bytes = [0xf3, 0xa5, 0xc3];
    let g = Graph::decode(&bytes, 0x1000).unwrap();
    assert!(matches!(
        g.nodes[&0x1000].op,
        Op::RepeatCopyString { width: 32 }
    ));
    assert_eq!(
        crate::crt_stream_emit::emit_body(&g, |_, _| Err("call".into()), &Default::default(), 8)
            .unwrap_err(),
        "CRT emit repeated copy effect unbound"
    );
    let byte = Graph::decode(&[0xf3, 0xa4, 0xc3], 0x1000).unwrap();
    assert!(matches!(
        byte.nodes[&0x1000].op,
        Op::RepeatCopyString { width: 8 }
    ));
    assert!(crate::crt_stream_emit::emit_body(
        &byte,
        |_, _| Err("call".into()),
        &Default::default(),
        8
    )
    .is_err());
    // An old catch-all thread hook cannot silently erase a new REP operation.
    assert_eq!(
        crate::crt_stream_emit::emit_body_with_hooks(
            &g,
            |_, _| Err("call".into()),
            &Default::default(),
            8,
            |_, _| Ok(String::new()),
            |_, _| Ok(String::new()),
            |_, _| Ok(None)
        )
        .unwrap_err(),
        "CRT emit repeated copy effect unbound"
    );
    for bytes in [
        &[0xf2, 0xa5, 0xc3][..],
        &[0xf3, 0x66, 0xa5, 0xc3],
        &[0x67, 0xf3, 0xa5, 0xc3],
        &[0x64, 0xf3, 0xa5, 0xc3],
        &[0xfd, 0xc3],
    ] {
        assert!(Graph::decode(bytes, 0x1000).is_err(), "{bytes:?}");
    }
}

#[test]
fn repeated_copy_preserves_overlap_knowledge_authority_and_partial_progress() {
    let g = Graph::decode_linear_fragment(&[0xf3, 0xa5], 0x1000).unwrap();
    let body = crate::crt_stream_emit::emit_body_with_repeat_copy(
        &g,
        |_, _| Err("call".into()),
        &Default::default(),
        8,
        |_, _| Err("thread".into()),
        |_, _| Ok(String::new()),
        |_, _| Err("RET".into()),
        Some(g.end),
        |_, _, _| Ok(None),
        |_, _| Err("indirect".into()),
        |_, width| {
            assert_eq!(width, 32);
            Ok("cpu.repeat_move_dwords(rt,256)?;".into())
        },
    )
    .unwrap();
    let extra = format!(
        r#"
fn rep(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}
fn base()->(CrtStreamRuntime,CrtCpu){{
 let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,1048576).unwrap();let s=rt.map_region(0xa000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(s,2048).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(99)).unwrap();let mut c=CrtCpu::new(sp,99).unwrap();c.r[0]=CrtValue::scalar(123);c.flags=CrtFlags{{cf:Some(true),zf:Some(false),sf:Some(true),of:Some(false)}};(rt,c)
}}
fn flags(c:&CrtCpu)->(Option<bool>,Option<bool>,Option<bool>,Option<bool>){{(c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of)}}
"#
    );
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
// Independent byte oracle models MOVSD forward iteration, including overlap.
for (from,to,words) in [(0usize,16usize,4usize),(0,4,4),(4,0,4),(0,0,4),(1,3,3),(3,1,3),(0,0,0)]{
 let(mut rt,mut c)=base();let data:Vec<u8>=(0..64).map(|i|i as u8).collect();let p=rt.map_region(0x20000,64,CrtRegionKind::Stack,Some(&data)).unwrap();let src=rt.offset(p,from as i64).unwrap();let dst=rt.offset(p,to as i64).unwrap();let mut expected=data;
 for i in 0..words{let word:Vec<u8>=expected[from+4*i..from+4*i+4].to_vec();expected[to+4*i..to+4*i+4].copy_from_slice(&word);}
 c.r[1]=CrtValue::scalar(words as u32);c.r[6]=CrtValue::Pointer(src);c.r[7]=CrtValue::Pointer(dst);let prior=c.r;let f=flags(&c);
 assert_eq!(rep(&mut rt,&mut c),Ok(CrtValue::scalar(123)));assert!(!c.returned);assert_eq!(rt.memory.read(p.address(),64).unwrap(),expected);assert_eq!(c.r[1],CrtValue::scalar(0));assert_eq!(CrtCpu::number(c.r[6]).unwrap(),src.address()+words as u32*4);assert_eq!(CrtCpu::number(c.r[7]).unwrap(),dst.address()+words as u32*4);assert_eq!(flags(&c),f);for r in [0,2,3,4,5]{assert_eq!(c.r[r],prior[r]);}
}
// Zero count must not read or validate numeric, stale or opaque cursors.
for mode in 0..3{
 let(mut rt,mut c)=base();let dead=rt.allocate(4,false,true).unwrap().unwrap();rt.free_allocation(dead).unwrap();c.r[1]=CrtValue::scalar(0);c.r[6]=match mode{0=>CrtValue::scalar(u32::MAX),1=>CrtValue::Pointer(dead),_=>CrtValue::OpaqueSaved(6)};c.r[7]=CrtValue::scalar(0);let prior=c.r;let f=flags(&c);assert!(rep(&mut rt,&mut c).is_ok());assert_eq!(c.r,prior);assert_eq!(flags(&c),f);
}
// Unknown data stays unknown even when replacing previously initialized data.
{
 let(mut rt,mut c)=base();let src=rt.allocate(8,false,true).unwrap().unwrap();let dst=rt.allocate(8,true,true).unwrap().unwrap();let partial=CrtValue::Scalar{bits:0xaa00cc00,known:0xff00ff00};rt.store(src,32,partial).unwrap();c.r[1]=CrtValue::scalar(2);c.r[6]=CrtValue::Pointer(src);c.r[7]=CrtValue::Pointer(dst);rep(&mut rt,&mut c).unwrap();assert_eq!(rt.load(dst,32).unwrap(),partial);assert_eq!(rt.load(rt.offset(dst,4).unwrap(),32).unwrap(),CrtValue::Scalar{bits:0,known:0});assert!(CrtCpu::pointer(rt.load(dst,32).unwrap()).is_err());assert_eq!(rt.memory.read(dst.address(),8),Err(guest_memory::Fault::Uninitialized));
}
// An ordinary data pointer preserves its exact alias; retirement expires both.
{
 let(mut rt,mut c)=base();let src=rt.allocate(8,true,true).unwrap().unwrap();let dst=rt.allocate(8,true,true).unwrap().unwrap();let target=rt.allocate(4,false,true).unwrap().unwrap();rt.store(src,32,CrtValue::scalar(77)).unwrap();rt.store(rt.offset(src,4).unwrap(),32,CrtValue::Pointer(target)).unwrap();c.r[1]=CrtValue::scalar(2);c.r[6]=CrtValue::Pointer(src);c.r[7]=CrtValue::Pointer(dst);rep(&mut rt,&mut c).unwrap();assert_eq!(rt.load(rt.offset(dst,4).unwrap(),32).unwrap(),CrtValue::Pointer(target));assert!(rt.load(target,32).unwrap().known_scalar().is_err());rt.free_allocation(target).unwrap();let a=CrtCpu::pointer(rt.load(rt.offset(src,4).unwrap(),32).unwrap()).unwrap();let b=CrtCpu::pointer(rt.load(rt.offset(dst,4).unwrap(),32).unwrap()).unwrap();assert_eq!(a,target);assert_eq!(b,target);assert!(rt.load(a,32).is_err());assert!(rt.load(b,32).is_err());let replacement=rt.allocate(4,false,true).unwrap().unwrap();assert_ne!(replacement.cap,target.cap);assert!(rt.load(a,32).is_err());assert!(rt.load(b,32).is_err());assert_eq!(rt.load(dst,32).unwrap(),CrtValue::scalar(77));
}
// Failures before or after one complete word retain exact memory/cursor/count.
for mode in 0..10{
 let(mut rt,mut c)=base();let src=rt.map_region(0x20000,if mode==0{4}else{8},CrtRegionKind::Stack,Some(if mode==0{&[1,0,0,0][..]}else{&[1,0,0,0,2,0,0,0][..]})).unwrap();let dst=if mode==4{rt.offset(CrtCpu::pointer(c.r[4]).unwrap(),-4).unwrap()}else{rt.map_region(0x30000,if mode==1{4}else{8},CrtRegionKind::Stack,None).unwrap()};
 c.r[1]=CrtValue::scalar(2);c.r[6]=CrtValue::Pointer(src);c.r[7]=CrtValue::Pointer(dst);
 if mode==2{rt.store(rt.offset(src,4).unwrap(),32,CrtValue::ProtectedReturn(777)).unwrap();}
 if mode==3{c.steps=u32::MAX-2;}
 if mode==5{rt.memory.release(src.cap,src.owner).unwrap();}
 if mode==6{rt.memory.release(dst.cap,dst.owner).unwrap();}
 if mode==7{c.r[6]=CrtValue::scalar(src.address());}
 if mode==8{c.r[1]=CrtValue::Scalar{bits:0,known:0};}
 if mode==9{c.r[1]=CrtValue::scalar(257);}
 let f=flags(&c);let result=rep(&mut rt,&mut c);let expected=match mode{0|1=>"CRT pointer complete range/identity",2=>"CRT repeated copy control authority",3=>"CRT instruction counter overflow",4=>"CRT protected saved/return overwrite",5|6=>"CRT pointer lifetime",7=>"CRT pointer provenance",8=>"CRT scalar knowledge/type",9=>"CRT repeated copy count bound",_=>unreachable!()};assert_eq!(result,Err(expected),"REP negative mode {mode}");assert_eq!(flags(&c),f);assert!(!c.returned);
 if mode<=4{assert_eq!(rt.load(dst,32).unwrap(),CrtValue::scalar(1));assert_eq!(c.r[1],CrtValue::scalar(1));assert_eq!(CrtCpu::number(c.r[6]).unwrap(),src.address()+4);assert_eq!(CrtCpu::number(c.r[7]).unwrap(),dst.address()+4);if mode==2{assert_eq!(rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(777)).count(),1);}if mode==4{assert_eq!(rt.load(CrtCpu::pointer(c.entry[4]).unwrap(),32).unwrap(),CrtValue::ProtectedReturn(99));}}
 else{if mode!=6{assert!(rt.load(dst,32).unwrap().known_scalar().is_err());}if mode!=8&&mode!=9{assert_eq!(c.r[1],CrtValue::scalar(2));}}
}
"#,
        "repeated-copy-effects",
    );
}

#[test]
fn repeated_copy_permission_boundary_retains_progress_without_replaying_completed_words() {
    crate::crt_stream_callees_tests::native(
        "",
        r#"
 let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,1048576).unwrap();
 let stack=rt.map_region(0xa000,4096,CrtRegionKind::Stack,None).unwrap();
 let sp=rt.offset(stack,2048).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(99)).unwrap();
 let mut c=CrtCpu::new(sp,99).unwrap();
 let src=rt.map_region(0x20000,8,CrtRegionKind::Stack,Some(&[1,0,0,0,2,0,0,0])).unwrap();
 let region=rt.map_region(0x30000,8192,CrtRegionKind::Module,Some(&[0;8192])).unwrap();
 let dst=rt.offset(region,4092).unwrap();let second=rt.offset(dst,4).unwrap();
 let output=rt.map_region(0x40000,4,CrtRegionKind::Stack,Some(&[0;4])).unwrap();
 rt.memory.protect_data_with_old((region.cap,region.owner,second.address(),4),2,(output.cap,output.owner,output.address())).unwrap();
 c.r[1]=CrtValue::scalar(2);c.r[6]=CrtValue::Pointer(src);c.r[7]=CrtValue::Pointer(dst);
 c.flags=CrtFlags{cf:Some(true),zf:Some(false),sf:Some(true),of:Some(false)};
 let old=c.r;assert_eq!(c.repeat_move_dwords(&mut rt,2),Err("CRT storage write"));
 assert_eq!(rt.load(dst,32).unwrap(),CrtValue::scalar(1));assert_eq!(rt.load(second,32).unwrap(),CrtValue::scalar(0));
 assert_eq!(c.r[1],CrtValue::scalar(1));assert_eq!(c.r[6],CrtValue::Pointer(rt.offset(src,4).unwrap()));assert_eq!(c.r[7],CrtValue::Pointer(second));
 for r in [0,2,3,4,5]{assert_eq!(c.r[r],old[r]);}assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(Some(true),Some(false),Some(true),Some(false)));assert!(!c.returned);
 // This is explicit component reentry after a checked guest permission repair,
 // not a claim that Windows exception capture/resumption has been implemented.
 rt.memory.protect_data_with_old((region.cap,region.owner,second.address(),4),4,(output.cap,output.owner,output.address())).unwrap();
 rt.store(src,32,CrtValue::scalar(77)).unwrap();c.repeat_move_dwords(&mut rt,2).unwrap();
 assert_eq!(rt.load(dst,32).unwrap(),CrtValue::scalar(1));assert_eq!(rt.load(second,32).unwrap(),CrtValue::scalar(2));assert_eq!(c.r[1],CrtValue::scalar(0));
 assert_eq!(c.r[6],CrtValue::Pointer(rt.offset(src,8).unwrap()));assert_eq!(c.r[7],CrtValue::Pointer(rt.offset(dst,8).unwrap()));
 "#,
        "repeated-copy-permission-progress",
    );
}
