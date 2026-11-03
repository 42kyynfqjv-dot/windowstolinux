//! Closed scalar/ERMS paths of the original CRT copy, with explicit rejection cuts.
use crate::crt_stream_ir::{Graph, Node, Op, Target};
use std::collections::BTreeMap;
pub(crate) const CODE:&str="57568b7424108b4c24148b7c240c8bc18bd103c63bfe76083bf80f829402000083f9200f82d204000081f98000000073130fba2558c04100010f828e040000e9e30100000fba25bccc4100017309f3a48b44240c5e5fc38bc733c6a90f000000750e0fba2558c04100010f82e00300000fba25bccc4100000f83a9010000f7c7030000000f859d010000f7c6030000000f85ac0100000fbae702730d8b0683e9048d760489078d7f040fbae7037311f30f7e0e83e9088d7608660fd60f8d7f08f7c60700000074650fbae6030f83b4000000660f6f4ef48d76f48bff660f6f5e1083e930660f6f4620660f6f6e308d763083f930660f6fd3660f3a0fd90c660f7f1f660f6fe0660f3a0fc20c660f7f4710660f6fcd660f3a0fec0c660f7f6f208d7f3073b78d760ce9af000000660f6f4ef88d76f88d4900660f6f5e1083e930660f6f4620660f6f6e308d763083f930660f6fd3660f3a0fd908660f7f1f660f6fe0660f3a0fc208660f7f4710660f6fcd660f3a0fec08660f7f6f208d7f3073b78d7608eb56660f6f4efc8d76fc8bff660f6f5e1083e930660f6f4620660f6f6e308d763083f930660f6fd3660f3a0fd904660f7f1f660f6fe0660f3a0fc204660f7f4710660f6fcd660f3a0fec04660f7f6f208d7f3073b78d760483f9107213f30f6f0e83e9108d7610660f7f0f8d7f10ebe80fbae102730d8b0683e9048d760489078d7f040fbae1037311f30f7e0e83e9088d7608660fd60f8d7f088b048da4324000ffe0f7c70300000074138a0688074983c60183c701f7c70300000075ed8bd183f9200f82ae020000c1e902f3a583e203ff2495a4324000ff248db432400090b4324000bc324000c8324000dc3240008b44240c5e5fc3908a0688078b44240c5e5fc3908a0688078a46018847018b44240c5e5fc38d49008a0688078a46018847018a46028847028b44240c5e5fc3908d340e8d3c0f83f9200f82510100000fba2558c04100010f8294000000f7c70300000074148bd783e2032bca8a46ff8847ff4e4f83ea0175f383f9200f821e0100008bd1c1e90283e20383ee0483ef04fdf3a5fcff249550334000906033400068334000783340008c3340008b44240c5e5fc3908a46038847038b44240c5e5fc38d49008a46038847038a46028847028b44240c5e5fc3908a46038847038a46028847028a46018847018b44240c5e5fc3f7c70f000000740f494e4f8a068807f7c70f00000075f181f980000000726881ee8000000081ef80000000f30f6f06f30f6f4e10f30f6f5620f30f6f5e30f30f6f6640f30f6f6e50f30f6f7660f30f6f7e70f30f7f07f30f7f4f10f30f7f5720f30f7f5f30f30f7f6740f30f7f6f50f30f7f7760f30f7f7f7081e980000000f7c180ffffff759083f920722383ee2083ef20f30f6f06f30f6f4e10f30f7f07f30f7f4f1083e920f7c1e0ffffff75ddf7c1fcffffff741583ef0483ee048b06890783e904f7c1fcffffff75eb85c9740f83ef0183ee018a06880783e90175f18b44240c5e5fc3eb03cccccc8bc683e00f85c00f85e30000008bd183e17fc1ea0774668da424000000008bff660f6f06660f6f4e10660f6f5620660f6f5e30660f7f07660f7f4f10660f7f5720660f7f5f30660f6f6640660f6f6e50660f6f7660660f6f7e70660f7f6740660f7f6f50660f7f7760660f7f7f708db6800000008dbf800000004a75a385c9745f8bd1c1ea0585d274218d9b00000000f30f6f06f30f6f4e10f30f7f07f30f7f4f108d76208d7f204a75e583e11f74308bc1c1e902740f8b16891783c70483c60483e90175f18bc883e10374138a06880746474975f78da424000000008d49008b44240c5e5fc38da424000000008bffba100000002bd0";
const CUTS: [u32; 3] = [0x4030be, 0x4032f4, 0x403580];
fn graph() -> Result<Graph, String> {
    let raw = crate::crt_ptd::raw(CODE);
    let mut nodes = BTreeMap::new();
    let table_at = (0x4032a4 - 0x403040) as usize;
    let table = &raw[table_at..table_at + 16];
    let targets: Vec<_> = table
        .as_chunks::<4>()
        .0
        .iter()
        .map(|w| u32::from_le_bytes(*w))
        .collect();
    if targets != [0x4032b4, 0x4032bc, 0x4032c8, 0x4032dc] {
        return Err("memcpy original tail table".into());
    }
    for (start, end) in [
        (0x403040u32, 0x4030be),
        (0x403267, 0x40329c),
        (0x4032b4, 0x4032f3),
        (0x403490, 0x403577),
    ] {
        let mut decoder = iced_x86::Decoder::with_ip(
            32,
            &raw[(start - 0x403040) as usize..(end - 0x403040) as usize],
            u64::from(start),
            iced_x86::DecoderOptions::NONE,
        );
        while decoder.can_decode() {
            let ins = decoder.decode();
            if ins.is_invalid() {
                return Err("memcpy invalid instruction".into());
            }
            let pc = ins.ip() as u32;
            let at = (pc - 0x403040) as usize;
            let bytes = &raw[at..at + ins.len()];
            let node = if pc == 0x403295 {
                if bytes != [0xff, 0x24, 0x95, 0xa4, 0x32, 0x40, 0]
                    || raw[(0x403292 - 0x403040) as usize..at] != [0x83, 0xe2, 3]
                {
                    return Err("memcpy tail table mask/binding".into());
                }
                Node {
                    length: 7,
                    op: Op::TableJump {
                        index: crate::graph::Reg {
                            index: 2,
                            width: 32,
                            shift: 0,
                        },
                        address: 0x4032a4,
                        targets: targets.clone(),
                    },
                    successors: targets.clone(),
                }
            } else {
                Graph::decode_instruction(bytes, pc)?
            };
            if nodes.insert(pc, node).is_some() {
                return Err("memcpy overlapping regions".into());
            }
        }
    }
    for pc in CUTS {
        let at = (pc - 0x403040) as usize;
        let d = iced_x86::Decoder::with_ip(
            32,
            &raw[at..],
            u64::from(pc),
            iced_x86::DecoderOptions::NONE,
        )
        .decode();
        let mut node = Graph::decode_instruction(&raw[at..at + d.len()], pc)?;
        node.op = Op::Reject("locale memcpy SSSE3/backward/unaligned path unbound");
        node.successors.clear();
        if nodes.insert(pc, node).is_some() {
            return Err("memcpy cut overlap".into());
        }
    }
    for (&pc, node) in &nodes {
        if CUTS.contains(&pc) {
            continue;
        }
        for target in &node.successors {
            if !nodes.contains_key(target) {
                return Err(format!(
                    "memcpy edge {pc:x}->{target:x} outside proved regions"
                ));
            }
            if *target == 0x403295 && pc != 0x403292 {
                return Err("memcpy table guard bypass".into());
            }
        }
    }
    Ok(Graph {
        origin: 0x403040,
        end: 0x403587,
        nodes,
    })
}
pub(crate) fn source() -> Result<String, String> {
    let bytes = crate::crt_ptd::raw(CODE);
    let g = graph()?;
    let body = crate::crt_stream_emit::emit_body_with_repeat_copy(
        &g,
        |_, _: Target| Err("memcpy unexpected call".into()),
        &BTreeMap::from([
            (0x41c058, "CrtRegionKind::Module".into()),
            (0x41ccbc, "CrtRegionKind::Module".into()),
            (0x4032a4, "CrtRegionKind::Module".into()),
        ]),
        32768,
        |_, _| Err("memcpy thread effect".into()),
        |pc, _| {
            Ok(if pc == 0x40304e {
                "if cpu.r[1].known_scalar()?!=0{for r in [6usize,7]{if matches!(cpu.r[r],CrtValue::Scalar{..}){cpu.r[r]=CrtValue::Pointer(rt.module_word_pointer(inputs.image,cpu.r[r])?);}}}".into()
            } else {
                String::new()
            })
        },
        |_, _| Ok(None),
        None,
        |_, _, _| Ok(None),
        |_, _| Err("memcpy indirect call".into()),
        |pc, width| {
            if !matches!((pc, width), (0x40308e, 8) | (0x403290, 32)) {
                return Err("memcpy REP location/width".into());
            }
            Ok(format!("cpu.repeat_move_units(rt,{width},4096)?;"))
        },
    )?;
    Ok(format!("fn locale_memcpy_bytes()->Vec<u8>{{vec!{bytes:?}}}fn locale_memcpy_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let p=rt.process_image_code(inputs.image,0x403040,{n})?;if rt.memory.read(p.address(),{n}).map_err(|_|\"locale memcpy code read\")?!=&{bytes:?}{{return Err(\"locale memcpy code changed\");}}{body}}}",n=bytes.len()))
}
#[test]
fn scalar_copy_graph_preserves_original_edges_tables_and_rejection_cuts() {
    let code = source().unwrap();
    for p in CUTS {
        assert!(code.contains(&format!("{p}=>")));
    }
    assert!(code.contains("SSSE3/backward/unaligned path unbound"));
    assert!(code.contains("original jump table changed"));
    assert!(code.contains("repeat_move_units(rt,8"));
    assert!(code.contains("repeat_move_units(rt,32"));
}

#[test]
fn bit_test_and_byte_repeat_keep_knowledge_flags_aliases_and_partial_progress() {
    let mut extra = String::new();
    for (name, bytes) in [
        ("reg_bit", &[0x0f, 0xba, 0xe0, 1][..]),
        ("mem_bit", &[0x0f, 0xba, 0x21, 1][..]),
    ] {
        let g = Graph::decode_linear_fragment(bytes, 0x1000).unwrap();
        let body = crate::crt_stream_emit::emit_linear_fragment(&g, &Default::default()).unwrap();
        extra.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}"));
    }
    for bytes in [
        &[0x0f, 0xba, 0xe0, 32][..],
        &[0x66, 0x0f, 0xba, 0xe0, 1],
        &[0x64, 0x0f, 0xba, 0x21, 1],
        &[0x0f, 0xa3, 0x01],
    ] {
        assert!(
            Graph::decode_linear_fragment(bytes, 0x1000).is_err(),
            "{bytes:x?}"
        );
    }
    crate::crt_stream_callees_tests::native_bounded_stack(
        &extra,
        r#"
#[inline(never)] fn registers(){for bits in [0u32,1,2,3,0x80000000,u32::MAX]{for known in [u32::MAX,!2]{for zf in [false,true]{
 let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0xa000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(77)).unwrap();let mut c=CrtCpu::new(sp,77).unwrap();c.r[0]=CrtValue::Scalar{bits:bits&known,known};c.flags=CrtFlags{cf:Some(false),zf:Some(zf),sf:Some(true),of:Some(true)};let before=c.r;reg_bit(&mut rt,&mut c).expect("BT must execute");assert_eq!(c.r,before);assert_eq!(c.flags.cf,if known&2!=0{Some(bits&2!=0)}else{None});assert_eq!(c.flags.zf,Some(zf));assert_eq!((c.flags.sf,c.flags.of),(None,None));if known&2==0{assert_eq!(c.condition(2),Err("CRT unknown CF"));}
}}}
}


#[inline(never)] fn memory(){for mode in 0..4{
 let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0xa000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(77)).unwrap();let mut c=CrtCpu::new(sp,77).unwrap();let p=rt.map_region(0xc000,4,CrtRegionKind::Stack,Some(&2u32.to_le_bytes())).unwrap();c.r[1]=CrtValue::Pointer(p);if mode==1{rt.memory.release(p.cap,p.owner).unwrap();}if mode==2{c.r[1]=CrtValue::Pointer(rt.offset(p,1).unwrap());}if mode==3{c.r[1]=CrtValue::scalar(p.address());}c.flags=CrtFlags{cf:Some(false),zf:Some(true),sf:Some(false),of:Some(true)};let old=c.r;let flags=c.flags;let result=mem_bit(&mut rt,&mut c);
 if mode==0{result.expect("memory BT must execute");assert_eq!(c.flags.cf,Some(true));assert_eq!(c.flags.zf,Some(true));}else{assert_eq!(result,Err(match mode{1=>"CRT pointer lifetime",2=>"CRT pointer complete range/identity",_=>"CRT scalar address lacks provenance"}));assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(flags.cf,flags.zf,flags.sf,flags.of));}assert_eq!(c.r,old);
}
}
#[inline(never)] fn bytes(){for mode in 0..6{
 let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0xa000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(77)).unwrap();let mut c=CrtCpu::new(sp,77).unwrap();let src=rt.map_region(0xc000,4,CrtRegionKind::Stack,Some(&[1,2,3,4])).unwrap();let dst=if mode==1{rt.offset(src,1).unwrap()}else{rt.map_region(0xd000,if mode==3{1}else{4},CrtRegionKind::Stack,None).unwrap()};c.r[6]=CrtValue::Pointer(src);c.r[7]=CrtValue::Pointer(dst);c.r[1]=CrtValue::scalar(3);c.flags=CrtFlags{cf:Some(true),zf:Some(false),sf:Some(true),of:Some(false)};let flags=c.flags;
 if mode==2{rt.store(src,8,CrtValue::Scalar{bits:5,known:0xf}).unwrap();}if mode==4{rt.memory.release(src.cap,src.owner).unwrap();c.r[1]=CrtValue::scalar(0);}if mode==5{rt.store(src,32,CrtValue::Pointer(stack)).unwrap();}
 let result=c.repeat_move_units(&mut rt,8,4);
 if mode==3{assert_eq!(result,Err("CRT pointer complete range/identity"));assert_eq!(rt.load(dst,8).unwrap(),CrtValue::scalar(1));assert_eq!(c.r[1],CrtValue::scalar(2));assert_eq!(c.r[6],CrtValue::Pointer(rt.offset(src,1).unwrap()));assert_eq!(c.r[7],CrtValue::Pointer(rt.offset(dst,1).unwrap()));}
 else if mode==5{assert_eq!(result,Err("CRT partial typed-word read"));assert_eq!(c.r[1],CrtValue::scalar(3));assert!(rt.load(dst,8).unwrap().known_scalar().is_err());}
 else{result.expect("REP byte case must execute");assert_eq!(c.r[1],CrtValue::scalar(0));if mode==0{assert_eq!(rt.memory.read(dst.address(),3).unwrap(),[1,2,3]);}if mode==1{assert_eq!(rt.memory.read(src.address(),4).unwrap(),[1,1,1,1]);}if mode==2{assert_eq!(rt.load(dst,8).unwrap(),CrtValue::Scalar{bits:5,known:0xffffff0f});}if mode==4{assert_eq!(c.r[6],CrtValue::Pointer(src));assert_eq!(c.r[7],CrtValue::Pointer(dst));}}
 assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(flags.cf,flags.zf,flags.sf,flags.of));
}
}
registers();memory();bytes();
"#,
        "bit-test-byte-rep",
    );
}

#[test]
fn vector_copy_alignment_and_byte_selection_preserve_unknowns_and_reject_controls() {
    for bytes in [
        &[0x66, 0x0f, 0x6f, 0x01][..],
        &[0xf3, 0x0f, 0x6f, 0x01],
        &[0x66, 0x0f, 0x7f, 0x01],
        &[0xf3, 0x0f, 0x7e, 0x01],
        &[0x66, 0x0f, 0xd6, 0x01],
        &[0x66, 0x0f, 0x6f, 0xc1],
    ] {
        Graph::decode_linear_fragment(bytes, 0x1000).unwrap();
    }
    for bytes in [
        &[0x64, 0x66, 0x0f, 0x6f, 0x01][..],
        &[0x66, 0x0f, 0x3a, 0x0f, 0x01, 8],
        &[0xf3, 0x0f, 0x7e, 0xc1],
        &[0x66, 0x0f, 0xd6, 0xc1],
    ] {
        assert!(
            Graph::decode_linear_fragment(bytes, 0x1000).is_err(),
            "{bytes:x?}"
        );
    }
    let copy = crate::crt_stream_emit::emit_linear_fragment(
        &Graph::decode_linear_fragment(&[0x66, 0x0f, 0x6f, 0xc8], 0x1000).unwrap(),
        &Default::default(),
    )
    .unwrap();
    let extra=format!("fn copy_register(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{copy}}}");
    crate::crt_stream_callees_tests::native_bounded_stack(
        &extra,
        r#"
#[inline(never)]fn memory(){for mode in 0..9{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0xa000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(77)).unwrap();let mut c=CrtCpu::new(sp,77).unwrap();let data:Vec<u8>=(0..if mode==2{32}else{16}).collect();let src=rt.map_region(0xc000,data.len()as u32,CrtRegionKind::Stack,Some(&data)).unwrap();let dst=rt.map_region(0xd000,if mode==4{8}else{32},CrtRegionKind::Stack,Some(&vec![77;if mode==4{8}else{32}])).unwrap();
 if mode==3{rt.memory.release(src.cap,src.owner).unwrap();}if mode==5{rt.store(rt.offset(dst,4).unwrap(),32,CrtValue::ProtectedReturn(99)).unwrap();}if mode==6{rt.store(src,32,CrtValue::Pointer(stack)).unwrap();}if mode==7{rt.store(rt.offset(src,5).unwrap(),8,CrtValue::Scalar{bits:5,known:0xf}).unwrap();}
 c.xmm[0]=[CrtValue::scalar(0xdeadbeef);4];let before=c.xmm;c.flags=CrtFlags{cf:Some(true),zf:Some(false),sf:Some(true),of:Some(false)};let flags=c.flags;let offset=if mode==1||mode==2{1}else{0};let result=c.vector_load(&rt,0,rt.offset(src,offset).unwrap_or(src),if mode==1{64}else{128},mode!=1);
 if matches!(mode,2|3|6){assert_eq!(result,Err(match mode{2=>"CRT vector alignment",3=>"CRT pointer lifetime",_=>"CRT vector typed data unbound"}));assert_eq!(c.xmm,before);}
 else{result.expect("vector load must execute");copy_register(&mut rt,&mut c).expect("vector register copy must execute");assert_eq!(c.xmm[0],c.xmm[1]);if mode==1{assert_eq!(c.xmm[0][2],CrtValue::scalar(0));assert_eq!(c.xmm[0][3],CrtValue::scalar(0));}
  let target=if mode==8{rt.bootstrap_main_image(init,0x400000,&[71;4096]).unwrap().root}else{rt.offset(dst,offset).unwrap()};let old=rt.memory.read(dst.address(),dst.size).unwrap().to_vec();let got=c.vector_store(&mut rt,1,target,if mode==1{64}else{128},mode!=1);
  if matches!(mode,4|5|8){assert_eq!(got,Err(match mode{4=>"CRT pointer complete range/identity",5=>"CRT vector typed destination unbound",_=>"CRT vector write permission"}));assert_eq!(rt.memory.read(dst.address(),dst.size).unwrap(),old);if mode==8{assert_eq!(rt.memory.read(target.address(),16).unwrap(),[71;16]);}}
  else{got.expect("vector store must execute");if mode==7{assert_eq!(rt.load(rt.offset(dst,5).unwrap(),8).unwrap(),CrtValue::Scalar{bits:5,known:0xffffff0f});}else if mode==1{assert_eq!(rt.memory.read(dst.address(),1).unwrap(),[77]);assert_eq!(rt.memory.read(dst.address()+1,8).unwrap(),&data[1..9]);assert_eq!(rt.memory.read(dst.address()+9,7).unwrap(),[77;7]);}else{assert_eq!(rt.memory.read(dst.address(),16).unwrap(),data);}}
 }assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(flags.cf,flags.zf,flags.sf,flags.of));
}}
memory();
"#,
        "vector-scalar-knowledge",
    );
}
