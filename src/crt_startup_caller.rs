//! Original post-initializer caller; live frame checks grant no exception/TEB effects.
use crate::crt_stream_ir::{Graph, Node, Op, Target};
use std::collections::BTreeMap;
pub(crate) const CALLER:&str="5984c00f845301000032db885de7c745fc00000000e8c70200008845dca17ccc410033c9413bc10f842f01000085c07549890d7ccc41006858514100683c514100e854560000595985c07411c745fcfeffffffb8ff000000e9ef00000068385141006830514100e8035600005959c7057ccc410002000000eb058ad9885de7ff75dce8e3030000";
pub(crate) const LOCK:&str="56e8a608000085c0742064a118000000be80cc41008b5004eb043bd0741033c08bcaf00fb10e85c075f032c05ec3b0015ec3";
pub(crate) const FLAG: &str = "33c03905f0d241000f95c0c3";
pub(crate) const SCOPE: &str = "feffffff00000000ccffffff00000000feffffff491740005d174000";
fn lock_graph() -> Result<Graph, String> {
    let bytes = crate::crt_ptd::raw(LOCK);
    let mut nodes = crate::crt_startup_table::graph(&bytes[..10], 0x401913)?.nodes;
    nodes.extend(Graph::decode(&bytes[42..46], 0x40193d)?.nodes);
    nodes.insert(
        0x40191d,
        Node {
            length: 6,
            op: Op::Reject("startup TEB/atomic ownership unbound at 0x40191d"),
            successors: vec![],
        },
    );
    if nodes
        .values()
        .flat_map(|n| &n.successors)
        .any(|t| !nodes.contains_key(t))
    {
        return Err("startup lock original closed-prefix edges".into());
    }
    Ok(Graph {
        origin: 0x401913,
        end: 0x401945,
        nodes,
    })
}
pub(crate) fn source() -> Result<String, String> {
    let array_source = crate::crt_c_initializers::source()?;
    let flag = crate::crt_ptd::raw(FLAG);
    let g = Graph::decode(&flag, 0x4021bf)?;
    let body = crate::crt_stream_emit::emit_body_with_hooks(
        &g,
        |_, _| Err("startup flag call".into()),
        &BTreeMap::from([(0x41d2f0, "CrtRegionKind::Module".into())]),
        32,
        |_, _| Err("startup flag thread effect".into()),
        |pc, _| {
            Ok(if pc == 0x4021c1 {
                "if !matches!(rt.load(rt.process_image_pointer(inputs.image,0x41d2f0,4)?,32)?,CrtValue::Scalar{..}){return Err(\"startup flag scalar field\");}".into()
            } else {
                String::new()
            })
        },
        |_, _| Ok(None),
    )?;
    let mut out=format!("fn startup_runtime_flag(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{} {body}}}",guard(0x4021bf,&flag));
    out.push_str(&array_source);
    let lock = crate::crt_ptd::raw(LOCK);
    let g = lock_graph()?;
    let body = crate::crt_stream_emit::emit_body(
        &g,
        |pc, t| {
            if t != Target::Direct(0x4021bf) {
                return Err("startup lock guard target".into());
            }
            Ok(format!(
                "cpu.call_activation(rt,{},0,|rt,c|startup_runtime_flag(rt,c,inputs))?;",
                pc + g.nodes[&pc].length
            ))
        },
        &Default::default(),
        64,
    )?;
    out.push_str(&format!("fn startup_runtime_lock(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{} {body}}}",guard(0x401913,&lock)));
    let bytes = crate::crt_ptd::raw(CALLER);
    let mut g = crate::crt_startup_table::graph(&bytes, 0x401632)?;
    for (pc, reason) in [
        (0x40178e, "startup failure branch unbound at 0x40178e"),
        (
            0x40177e,
            "startup C initializer failure continuation unbound at 0x40177e",
        ),
        (
            0x4016ac,
            "startup existing-state branch unbound at 0x4016ac",
        ),
    ] {
        g.nodes.insert(
            pc,
            Node {
                length: 2,
                op: Op::Reject(reason),
                successors: vec![],
            },
        );
    }
    g.nodes.insert(
        0x4016b4,
        Node {
            length: 5,
            op: Op::Reject("startup lock release unbound at 0x4016b4"),
            successors: vec![],
        },
    );
    let roles = BTreeMap::from([(0x41cc7c, "CrtRegionKind::Module".into())]);
    let scope = crate::crt_ptd::raw(SCOPE);
    let body = crate::crt_stream_emit::emit_body_with_store(
        &g,
        |pc, t| {
            Ok(match(pc,t){(0x401647,Target::Direct(0x401913))=>"startup_caller_frame(rt,cpu,epoch,binding)?;cpu.call_activation(rt,0x40164c,0,|rt,c|startup_runtime_lock(rt,c,inputs))?;startup_caller_frame(rt,cpu,epoch,binding)?;".into(),(0x401673,Target::Direct(0x406ccc))=>"startup_caller_frame(rt,cpu,epoch,binding)?;if binding.image(rt,cpu,epoch)?.try_level!=0||rt.load(rt.process_image_pointer(inputs.image,0x41cc7c,4)?,32)?!=CrtValue::scalar(1){return Err(\"C initializer caller phase\");}cpu.call_activation(rt,0x401678,0,|rt,c|startup_c_array_observed(rt,c,inputs,Some(epoch),platform,features))?;startup_caller_frame(rt,cpu,epoch,binding)?;".into(),(0x401699,Target::Direct(0x406ca1))=>"startup_caller_frame(rt,cpu,epoch,binding)?;cpu.call_activation(rt,0x40169e,0,|rt,c|startup_cpp_array_original(rt,c,inputs))?;startup_caller_frame(rt,cpu,epoch,binding)?;".into(),_=>return Err("startup caller call target".into())})
        },
        &roles,
        128,
        |_, _| Err("startup caller thread effect".into()),
        |pc, _| {
            Ok(if pc == 0x40164f {
                "if !matches!(rt.load(rt.process_image_pointer(inputs.image,0x41cc7c,4)?,32)?,CrtValue::Scalar{..}){return Err(\"startup state scalar field\");}".into()
            } else {
                String::new()
            })
        },
        |_, _| Err("startup caller unexpected return".into()),
        Some(0x4016b4),
        |pc, a, width| {
            let offset = match pc {
                0x40163d | 0x4016ae if width == 8 => Some(-25),
                0x401640 | 0x40167e if width == 32 => Some(-4),
                0x40164c if width == 8 => Some(-36),
                0x401663 | 0x4016a0 if width == 32 => None,
                _ => return Err("startup caller store shape".into()),
            };
            let target = crate::crt_stream_emit::address(a, &roles)?;
            let identity = if let Some(offset) = offset {
                format!("if p!=binding.at(rt,binding.layout.bp+({offset}))?{{return Err(\"startup caller local alias\");}}")
            } else {
                "if p!=rt.process_image_pointer(inputs.image,0x41cc7c,4)?{return Err(\"startup caller global alias\");}".into()
            };
            let transition = if pc == 0x401640 {
                format!("if rt.load(p,32)?!=CrtValue::scalar((-2i32)as u32)||v!=CrtValue::scalar(0){{return Err(\"startup caller scope transition\");}}let q=rt.process_image_pointer(inputs.image,binding.layout.scope,{})?;rt.memory.validate_immutable(q.cap,q.owner,q.address(),{}).map_err(|_|\"startup caller scope permission\")?;if binding.layout.scope!=0x41b238||rt.memory.read(q.address(),{}).map_err(|_|\"startup caller scope read\")?!=&{scope:?}{{return Err(\"startup caller scope bytes\");}}",scope.len(),scope.len(),scope.len())
            } else if pc == 0x4016a0 {
                "if rt.load(p,32)?!=CrtValue::scalar(1)||v!=CrtValue::scalar(2){return Err(\"startup initialization completion transition\");}".into()
            } else {
                String::new()
            };
            Ok(Some(format!("startup_caller_frame(rt,cpu,epoch,binding)?;let p={target};{identity}{transition}rt.store(p,{width},v)?;startup_caller_frame(rt,cpu,epoch,binding)?;")))
        },
    )?;
    out.push_str(r#"fn startup_caller_frame(rt:&CrtStreamRuntime,cpu:&CrtCpu,epoch:&NormalCallEpoch<'_>,binding:&CrtNormalBinding)->Result<(),&'static str>{binding.authority(rt,epoch)?;let image=binding.image(rt,cpu,epoch)?;epoch.validate_image(binding.id.ok_or("startup caller missing normal frame")?,&image)}"#);
    out.push_str(&format!("fn startup_post_initializer(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,epoch:&mut NormalCallEpoch<'_>,binding:&mut CrtNormalBinding)->Result<CrtValue,&'static str>{{startup_post_initializer_platform(rt,cpu,inputs,epoch,binding,None)}}fn startup_post_initializer_platform(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,epoch:&mut NormalCallEpoch<'_>,binding:&mut CrtNormalBinding,platform:Option<&CrtNativePlatform>)->Result<CrtValue,&'static str>{{startup_post_initializer_observed(rt,cpu,inputs,epoch,binding,platform,None)}}fn startup_post_initializer_observed(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,epoch:&mut NormalCallEpoch<'_>,binding:&mut CrtNormalBinding,platform:Option<&CrtNativePlatform>,features:Option<&CrtFeatureObservation>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;startup_caller_frame(rt,cpu,epoch,binding)?;let arg=binding.at(rt,binding.layout.low-4)?;if cpu.r[4]!=CrtValue::Pointer(arg)||rt.load(arg,32)?!=CrtValue::scalar(1){{return Err(\"startup caller argument/phase\");}}if binding.image(rt,cpu,epoch)?.try_level!= -2{{return Err(\"startup caller scope phase\");}}{}let _=(||->Result<CrtValue,&'static str>{{{body}}})()?;Err(\"startup lock release unbound at 0x4016b4\")}}",guard(0x401632,&bytes)));
    out.push_str(&format!("fn startup_caller_bytes()->Vec<u8>{{vec!{bytes:?}}}fn startup_runtime_lock_bytes()->Vec<u8>{{vec!{lock:?}}}fn startup_runtime_flag_bytes()->Vec<u8>{{vec!{flag:?}}}"));
    Ok(out)
}
fn guard(at: u32, bytes: &[u8]) -> String {
    format!("let p=rt.process_image_code(inputs.image,{at},{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"startup caller code read\")?!=&{bytes:?}{{return Err(\"startup caller code changed\");}}",bytes.len(),bytes.len())
}
#[test]
fn original_startup_guard_reads_flag_and_rejects_unproved_thread_branch() {
    let g = lock_graph().unwrap();
    assert!(matches!(g.nodes[&0x40191d].op, Op::Reject(_)));
    assert!(matches!(
        g.nodes[&0x401914].op,
        Op::Call(Target::Direct(0x4021bf))
    ));
    source().expect("bounded original caller and zero-flag path must lower");
}
#[cfg(test)]
pub(crate) fn declared_frame_source() -> Result<String, String> {
    let bytes = crate::crt_ptd::raw(crate::crt_startup_entry::REGIONS[1].2)[..14].to_vec();
    let g = crate::crt_startup_table::graph(&bytes, 0x40161f)?;
    let body = crate::crt_stream_emit::emit_body_with_store(
        &g,
        |_, t| {
            if t != Target::Direct(0x401e60) {
                return Err("declared startup prolog target".into());
            }
            Ok("let id=(rt.generation+1)|(1u64<<63);rt.generation+=1;cpu.push(rt,CrtValue::ProtectedReturn(id))?;startup_helper(rt,cpu,id,binding.token,|rt,c,record,head|binding.install(rt,c,epoch,record,head))?;".into())
        },
        &Default::default(),
        32,
        |_, _| Err("declared prolog FS".into()),
        |_, _| Ok(String::new()),
        |_, _| Err("declared prolog RET".into()),
        Some(0x40162d),
        |_, _, _| Ok(None),
    )?;
    Ok(format!("fn declared_startup_post_frame(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,epoch:&mut NormalCallEpoch<'_>,binding:&mut CrtNormalBinding)->Result<CrtValue,&'static str>{{{}let h=rt.process_image_code(inputs.image,0x401e60,startup_helper_code().len()as u32)?;if rt.memory.read(h.address(),startup_helper_code().len()as u32).map_err(|_|\"declared helper read\")?!=startup_helper_code(){{return Err(\"declared helper bytes\");}}{body}}}",guard(0x40161f,&bytes)))
}

#[test]
fn original_result_branch_preserves_pops_failed_scope_and_unknown_truth() {
    let all = crate::crt_ptd::raw(CALLER);
    let mut graph = crate::crt_startup_table::graph(&all[0x46..0x67], 0x401678).unwrap();
    graph.nodes.insert(
        0x40177e,
        Node {
            length: 1,
            op: Op::Reject("independent original failure continuation"),
            successors: vec![],
        },
    );
    let body = crate::crt_stream_emit::emit_body_with_store(
        &graph,
        |_, _| Err("unexpected result-prefix call".into()),
        &Default::default(),
        32,
        |_, _| Err("unexpected result-prefix thread effect".into()),
        |_, _| Ok(String::new()),
        |_, _| Err("unexpected result-prefix RET".into()),
        Some(0x401699),
        |_, _, _| Ok(None),
    )
    .unwrap();
    let extra=format!("fn original_result(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{cpu.validate_active(rt)?;{body}}}");
    crate::crt_stream_callees_tests::native_bounded_stack(
        &extra,
        r#"
for mode in 0..8{
 let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0x10000,2048,CrtRegionKind::Stack,None).unwrap();let entry=rt.offset(stack,1536).unwrap();rt.store(entry,32,CrtValue::ProtectedReturn(88)).unwrap();let mut c=CrtCpu::new(entry,88).unwrap();let sp=rt.offset(stack,512).unwrap();let bp=rt.offset(stack,if mode==6{1540}else{1024}).unwrap();c.r[4]=CrtValue::Pointer(sp);c.r[5]=CrtValue::Pointer(bp);let level=rt.offset(bp,-4).unwrap();if mode!=6{rt.store(level,32,CrtValue::scalar(0)).unwrap();}for(i,v)in[0x41513c,0x415158].into_iter().enumerate(){rt.store(rt.offset(sp,i as i64*4).unwrap(),32,CrtValue::scalar(v)).unwrap();}
 c.r[0]=match mode{0=>CrtValue::scalar(0),1|6=>CrtValue::scalar(9),2=>CrtValue::scalar(u32::MAX),3=>CrtValue::Scalar{bits:1,known:1},4=>CrtValue::Scalar{bits:0,known:0},5=>CrtValue::Scalar{bits:0,known:255},_=>rt.symbolic_bool(true).unwrap()};let before=c.r[0];let got=original_result(&mut rt,&mut c);assert!(!c.returned);assert_eq!(rt.load(entry,32),Ok(CrtValue::ProtectedReturn(88)));
 if mode==0{assert_eq!(got,Ok(CrtValue::scalar(0)));assert_eq!(c.r[4],CrtValue::Pointer(sp));assert_eq!(rt.load(sp,32),Ok(CrtValue::scalar(0x415130)));assert_eq!(rt.load(rt.offset(sp,4).unwrap(),32),Ok(CrtValue::scalar(0x415138)));assert_eq!(rt.load(level,32),Ok(CrtValue::scalar(0)));}
 else{assert_eq!(c.r[4],CrtValue::Pointer(rt.offset(sp,8).unwrap()));assert_eq!(rt.load(sp,32),Ok(CrtValue::Scalar{bits:0,known:0}));if matches!(mode,1..=3|7){assert_eq!(got,Err("independent original failure continuation"));assert_eq!(c.r[0],CrtValue::scalar(255));assert_eq!(rt.load(level,32),Ok(CrtValue::scalar(u32::MAX-1)));}else{assert_eq!(got,Err(if mode==6{"CRT protected saved/return overwrite"}else{"CRT unknown ZF"}));assert_eq!(c.r[0],before);if mode!=6{assert_eq!(rt.load(level,32),Ok(CrtValue::scalar(0)));}}}
}
"#,
        "original-caller-result",
    );
}
