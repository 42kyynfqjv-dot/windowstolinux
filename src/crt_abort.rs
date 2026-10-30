//! Original abort decisions and registered signal-query/exit prefixes.
use crate::crt_stream_ir::{Graph, Target};
pub(crate) const ENTRY: &str = "e8cb530000";
pub(crate) const QUERY: &str =
    "8bff558bec83ec0c6a03588945f88d4dff8945f48d45f8508d45ff508d45f450e809ffffffc9c3";
pub(crate) fn source(entry: &[u8], query: &[u8]) -> Result<String, String> {
    if entry != crate::crt_ptd::raw(ENTRY) || query != crate::crt_ptd::raw(QUERY) {
        return Err("abort entry/query code binding".into());
    }
    let graph = Graph::decode(query, 0x40cbcf)?;
    let body = crate::crt_stream_emit::emit_body(
        &graph,
        |pc, target| {
            if target != Target::Direct(0x40cafd) {
                return Err("abort query target".into());
            }
            let next = pc + graph.nodes[&pc].length;
            Ok(format!(
                "cpu.call_activation(rt,{next},12,|rt,child|query(rt,child))?;"
            ))
        },
        &Default::default(),
        128,
    )?;
    let graph = Graph {
        origin: 0x4077ff,
        end: 0x407804,
        nodes: std::collections::BTreeMap::from([(
            0x4077ff,
            Graph::decode_instruction(entry, 0x4077ff)?,
        )]),
    };
    let prefix = crate::crt_stream_emit::emit_body_with_exit(
        &graph,
        |_, target| {
            if target != Target::Direct(0x40cbcf) {
                return Err("abort entry target".into());
            }
            Ok("cpu.call_activation(rt,0x407804,0,|rt,child|abort_query_original(rt,child,&mut|_,_|Err(\"abort locked signal query 0x40cafd unbound\")))?;".into())
        },
        &Default::default(),
        16,
        |_, _| Err("abort unexpected FS".into()),
        |_, _| Ok(String::new()),
        |_, _| Err("abort entry cannot return".into()),
        Some(0x407804),
    )?;
    Ok(format!("fn abort_query_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,query:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{{body}}}fn abort_entry_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{cpu.validate_active(rt)?;let _=(||->Result<CrtValue,&'static str>{{{prefix}}})()?;Err(\"abort signal/report/exit effects unbound\")}}"))
}
#[test]
fn original_abort_query_caller_preserves_arguments_cleanup_and_prior_effects() {
    let extra = source(&crate::crt_ptd::raw(ENTRY), &crate::crt_ptd::raw(QUERY)).unwrap();
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
for mode in 0..8{
 let mut rt=CrtStreamRuntime::new(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0x9000,2048,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,1536).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();let saved=cpu.r;let mut visited=false;
 if mode==7{assert_eq!(abort_entry_original(&mut rt,&mut cpu),Err("abort locked signal query 0x40cafd unbound"));assert!(!cpu.returned);continue;}
 let result=abort_query_original(&mut rt,&mut cpu,&mut|rt,c|{
  visited=true;let s=CrtCpu::pointer(c.r[4])?;let bp=CrtCpu::pointer(c.r[5])?;
  let a=CrtCpu::pointer(rt.load(rt.offset(s,4)?,32)?)?;let b=CrtCpu::pointer(rt.load(rt.offset(s,8)?,32)?)?;let d=CrtCpu::pointer(rt.load(rt.offset(s,12)?,32)?)?;
  assert_eq!(a,rt.offset(bp,-12)?);assert_eq!(b,rt.offset(bp,-1)?);assert_eq!(d,rt.offset(bp,-8)?);assert_eq!(c.r[1],CrtValue::Pointer(b));
  assert_eq!(rt.load(a,32)?,CrtValue::scalar(3));assert_eq!(rt.load(d,32)?,CrtValue::scalar(3));assert!(rt.load(b,8)?.known_scalar().is_err());
  rt.store(b,8,CrtValue::scalar(0x5a))?;
  if mode==2{return Err("independent query failure after write");}
  if mode==3{rt.store(bp,32,CrtValue::scalar(99))?;}
  c.clobber(if mode==4{CrtValue::Scalar{bits:0,known:0}}else{CrtValue::scalar(if mode==1{0x12345678}else{0})});
  if mode==5{return c.finish(rt);}
  if mode==6{return Ok(c.r[0]);}c.finish_pop(rt,12)
 });assert!(visited);
 if matches!(mode,0|1|4){let v=result.expect("original query caller must return");assert_eq!(v,if mode==4{CrtValue::Scalar{bits:0,known:0}}else{CrtValue::scalar(if mode==1{0x12345678}else{0})});assert!(cpu.returned);for r in [3,5,6,7]{assert_eq!(cpu.r[r],saved[r]);}assert_eq!(cpu.r[4],CrtValue::Pointer(rt.offset(sp,4).unwrap()));}
 else{assert_eq!(result,Err(match mode{2=>"independent query failure after write",3=>"CRT protected saved/return overwrite",5=>"CRT unbound RET argument cleanup",6=>"CRT callee missing exact protected RET",_=>unreachable!()}));assert!(!cpu.returned);}
 assert_eq!(rt.load(rt.offset(sp,-5).unwrap(),8).unwrap(),CrtValue::scalar(0x5a));
}
"#,
        "abort-query",
    );
}
#[test]
fn original_abort_entry_and_query_mutations_reject() {
    let e = crate::crt_ptd::raw(ENTRY);
    let q = crate::crt_ptd::raw(QUERY);
    for i in 0..e.len() {
        let mut b = e.clone();
        b[i] ^= 1;
        assert!(source(&b, &q).is_err());
    }
    for i in 0..q.len() {
        let mut b = q.clone();
        b[i] ^= 1;
        assert!(source(&e, &b).is_err());
    }
}

#[test]
fn rotate_cl_preserves_x86_bits_flags_and_rejects_unknown_count() {
    let mut extra = String::new();
    for reg in [0u8, 2, 3, 5, 6, 7] {
        let g = Graph::decode(&[0xd3, 0xc8 + reg, 0xc3], 0x430000).unwrap();
        let body = crate::crt_stream_emit::emit_body(
            &g,
            |_, _| Err("no rotate calls".into()),
            &Default::default(),
            8,
        )
        .unwrap();
        extra.push_str(&format!("fn rotate_{reg}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}"));
    }
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
for bits in [0u32,1,0x80000000,0x12345678,u32::MAX]{for count in [0u32,1,2,31,32,33,255]{
 let mut rt=CrtStreamRuntime::new(7,9,0x8000,8192).unwrap();let s=rt.map_region(0x9000,512,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(s,400).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut c=CrtCpu::new(sp,1).unwrap();c.r[0]=CrtValue::scalar(bits);c.r[1]=CrtValue::scalar(count);c.flags=CrtFlags{cf:Some(true),of:Some(false),zf:Some(true),sf:Some(false)};
 let n=count&31;let mut expected=0;for i in 0..32{if bits&(1<<i)!=0{expected|=1<<((i+32-n)%32);}}
 rotate_0(&mut rt,&mut c).unwrap();assert_eq!(c.r[0],CrtValue::scalar(expected));assert_eq!(c.flags.zf,Some(true));assert_eq!(c.flags.sf,Some(false));assert_eq!(c.flags.cf,Some(if n==0{true}else{expected>>31!=0}));assert_eq!(c.flags.of,if n==0{Some(false)}else if n==1{Some(((expected>>31)^(expected>>30))&1!=0)}else{None});
}}
let mut rt=CrtStreamRuntime::new(7,9,0x8000,8192).unwrap();let p=rt.map_region(0x9000,512,CrtRegionKind::Stack,None).unwrap();let mut c=CrtCpu::new(p,1).unwrap();
c.flags=CrtFlags{cf:Some(true),of:Some(true),sf:Some(false),zf:Some(true)};
assert_eq!(c.rotate_right32(CrtValue::Scalar{bits:0x80000000,known:0x80000000},CrtValue::Scalar{bits:1,known:31}).unwrap(),CrtValue::Scalar{bits:0x40000000,known:0x40000000});assert_eq!(c.flags.cf,None);assert_eq!(c.flags.of,None);
let flags=c.flags;assert_eq!(c.rotate_right32(CrtValue::scalar(1),CrtValue::Scalar{bits:0,known:30}),Err("CRT unknown rotate count"));assert_eq!((c.flags.cf,c.flags.of,c.flags.sf,c.flags.zf),(flags.cf,flags.of,flags.sf,flags.zf));
"#,
        "rotate-cl",
    );
    assert!(Graph::decode_instruction(&[0xd3, 0xcc], 0x430000).is_err());
}
pub(crate) const LOCKED:&str="6a0c6840b74100e85753ffff8365e4008b4508ff30e8b8f2ffff598365fc008b0d00c0410083e11f8b35d8d24100333500c04100d3ce8975e4c745fcfeffffffe8170000008bc68b4df064890d00000000595f5e5bc9c20c00";
pub(crate) const UNLOCK: &str = "8b4d10ff31e8b4f2ffff59c3";
pub(crate) const SCOPE: &str = "feffffff00000000d4ffffff00000000feffffff0000000056cb4000";
pub(crate) fn locked_source(helper: &[u8]) -> Result<String, String> {
    use crate::crt_exception_wrapper::{EpilogProof, PrologProof, Region};
    let raw = crate::crt_ptd::raw;
    let code = raw(LOCKED);
    let scope = raw(SCOPE);
    let prolog = PrologProof::prove(
        Region {
            bytes: helper,
            origin: 0x401e60,
        },
        12,
        0x41b740,
        0x41c000,
        0x402210,
    )?;
    let epilog = EpilogProof::prove(
        Region {
            bytes: &code[71..],
            origin: 0x40cb44,
        },
        &prolog,
    )?;
    let p = prolog.emit("abort_locked_prolog")?;
    let e = epilog.emit("abort_locked_epilog")?;
    let prefix = crate::crt_stream_emit::emit_linear_fragment(
        &Graph::decode_linear_fragment(&code[..7], 0x40cafd)?,
        &Default::default(),
    )?;
    let mut nodes = std::collections::BTreeMap::new();
    let mut decoder =
        iced_x86::Decoder::with_ip(32, &code[12..71], 0x40cb09, iced_x86::DecoderOptions::NONE);
    while decoder.can_decode() {
        let i = decoder.decode();
        let at = (i.ip32() - 0x40cafd) as usize;
        nodes.insert(
            i.ip32(),
            Graph::decode_instruction(&code[at..at + i.len()], i.ip32())?,
        );
    }
    let graph = Graph {
        origin: 0x40cb09,
        end: 0x40cb44,
        nodes,
    };
    let roles = std::collections::BTreeMap::from([
        (0x41c000, "CrtRegionKind::Module".into()),
        (0x41d2d8, "CrtRegionKind::Module".into()),
    ]);
    let unlock = crate::crt_stream_emit::emit_body(
        &Graph::decode(&raw(UNLOCK), 0x40cb59)?,
        |_, target| {
            if target != Target::Direct(0x40be17) {
                return Err("abort finally unlock target".into());
            }
            Ok("cpu.call_activation(rt,0x40cb63,0,|rt,c|abort_global_leave(rt,c,|rt,index|{let lock=held.ok_or(\"abort unlock missing acquisition\")?;if index!=3{return Err(\"abort unlock index\");}cleanup(rt)?;rt.unlock_global(lock)?;*held=None;Ok(())}))?;".into())
        },
        &Default::default(),
        32,
    )?;
    let body = crate::crt_stream_emit::emit_body_with_exit(
        &graph,
        |pc, target| {
            Ok(match target{
  Target::Direct(0x40bdcf)=>"cpu.call_activation(rt,0x40cb17,0,|rt,c|abort_global_enter(rt,c,|rt,index|{if index!=3||held.is_some(){return Err(\"abort acquire index/replay\");}held=Some(rt.lock_global(rt.thread,index)?);Ok(())}))?;".into(),
  Target::Direct(0x40cb59)=>format!("cpu.call_activation(rt,{},0,|rt,c|abort_finally_original(rt,c,&mut held,cleanup))?;",pc+5),
  _=>return Err("abort locked unknown call".into())
 })
        },
        &roles,
        256,
        |_, _| Err("abort locked body FS".into()),
        |_, _| {
            Ok(format!(
                "binding.image(rt,cpu,epoch)?;CrtCxxRecord::bytes(rt,s,&{scope:?})?;"
            ))
        },
        |_, _| Err("abort body unexpected return".into()),
        Some(0x40cb44),
    )?;
    let enter = raw("8bff558bec6b4508180550d1410050ff154c5041005dc3");
    let leave = raw("8bff558bec6b4508180550d1410050ff15505041005dc3");
    let locks = format!(
        "{}{}",
        crate::crt_global_lock::Proof::prove(&enter, 0x40bdcf, 0x41d150, 0x41504c)?
            .emit("abort_global_enter")?,
        crate::crt_global_lock::Proof::prove(&leave, 0x40be17, 0x41d150, 0x415050)?
            .emit("abort_global_leave")?
    );
    Ok(format!(
        r#"{p}{e}{locks}
fn abort_finally_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,held:&mut Option<CrtGlobalLock>,cleanup:&mut impl FnMut(&mut CrtStreamRuntime)->RegistryResult<()>)->RegistryResult<CrtValue>{{{unlock}}}
fn abort_locked_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>,cleanup:&mut impl FnMut(&mut CrtStreamRuntime)->RegistryResult<()>)->RegistryResult<CrtValue>{{
 let result=(||{{let s=rt.resolve_absolute(0x41b740,CrtRegionKind::Module)?;CrtCxxRecord::bytes(rt,s,&{scope:?})?;
 let mut binding=CrtNormalBinding::bind(rt,cpu,epoch,abort_locked_epilog_layout())?;
 let _=(||->RegistryResult<CrtValue>{{{prefix}}})()?;
 let generation=rt.generation.checked_add(1).filter(|n|*n<1u64<<63).ok_or("abort helper generation")?;let id=generation|(1u64<<63);rt.generation=generation;cpu.push(rt,CrtValue::ProtectedReturn(id))?;
 abort_locked_prolog(rt,cpu,id,binding.token,|rt,c,p,t|binding.install(rt,c,epoch,p,t))?;
 let mut held=None;let _=(||->RegistryResult<CrtValue>{{{body}}})()?;
 if held.is_some(){{return Err("abort lock not released");}}abort_locked_epilog(rt,cpu,epoch,&mut binding)
 }})();match result{{Ok(v)=>Ok(v),Err(e)=>epoch.fail(e)}}
}}
"#
    ))
}

pub(crate) fn registered_entry_source() -> Result<String, String> {
    let mut s = source(&crate::crt_ptd::raw(ENTRY), &crate::crt_ptd::raw(QUERY))?;
    s = s[..s
        .find("fn abort_entry_original")
        .ok_or("abort source entry boundary")?]
        .into();
    s.push_str(&branch_source_for(
        &crate::crt_ptd::raw(ABORT),
        &crate::crt_ptd::raw(EXIT),
        true,
    )?);
    s.push_str("fn abort_entry_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>)->RegistryResult<CrtValue>{abort_branch_original(rt,cpu,epoch)}");
    Ok(s)
}

pub(crate) const ABORT:&str="e8cb53000085c074086a16e80554000059f60528c141000274226a17ff151c50410085c074056a0759cd296a0168150000406a03e81b01000083c40c6a03e8c2f7ffff";

pub(crate) const EXIT: &str = "8bff558bec6a006a02ff7508e854feffff83c40c5dc3";

pub(crate) fn branch_source(abort: &[u8], exit: &[u8]) -> Result<String, String> {
    branch_source_for(abort, exit, false)
}
fn branch_source_for(abort: &[u8], exit: &[u8], registered: bool) -> Result<String, String> {
    if abort != crate::crt_ptd::raw(ABORT) || exit != crate::crt_ptd::raw(EXIT) {
        return Err("abort branch/exit code binding".into());
    }
    let mut nodes = std::collections::BTreeMap::new();
    let mut todo = vec![0x4077ff];
    while let Some(pc) = todo.pop() {
        if nodes.contains_key(&pc) {
            continue;
        }
        let at = (pc - 0x4077ff) as usize;
        let mut decoder = iced_x86::Decoder::with_ip(
            32,
            &abort[at..],
            u64::from(pc),
            iced_x86::DecoderOptions::NONE,
        );
        let i = decoder.decode();
        let mut node = Graph::decode_instruction(&abort[at..at + i.len()], pc)?;
        if matches!(pc, 0x40780a | 0x40781b | 0x40783d) {
            node.successors.clear();
        }
        todo.extend_from_slice(&node.successors);
        nodes.insert(pc, node);
    }
    let graph = Graph {
        origin: 0x4077ff,
        end: 0x407842,
        nodes,
    };
    let body = crate::crt_stream_emit::emit_body_with_hooks(
        &graph,
        |pc, target| {
            Ok(match(pc,target){
  (0x4077ff,Target::Direct(0x40cbcf))=>if registered{"cpu.call_activation(rt,0x407804,0,|rt,c|abort_query_original(rt,c,&mut|rt,c|abort_locked_original(rt,c,epoch,&mut|_|Ok(()))))?;"}else{"cpu.call_activation(rt,0x407804,0,|rt,c|lookup(rt,c))?;"}.into(),
  (0x40780a,Target::Direct(0x40cc14))=>"if rt.load(CrtCpu::pointer(cpu.r[4])?,32)?!=CrtValue::scalar(22){return Err(\"abort signal argument\");}return Err(\"abort signal22 dispatch 0x40cc14 unbound\");".into(),
  (0x40781b,Target::Import(0x41501c))=>"if rt.load(CrtCpu::pointer(cpu.r[4])?,32)?!=CrtValue::scalar(23){return Err(\"abort feature argument\");}return Err(\"abort processor-feature/report/fast-fail effects unbound\");".into(),
  (0x40783d,Target::Direct(0x407004))=>format!("cpu.call_activation(rt,0x407842,0,|rt,c|abort_exit_original(rt,c{}))?;return Err(\"abort exit unexpectedly returned\");",if registered{",epoch"}else{""}),
  _=>return Err("abort branch call inventory".into())
 })
        },
        &std::collections::BTreeMap::from([(0x41c128, "CrtRegionKind::Module".into())]),
        128,
        |_, _| Err("abort direct FS".into()),
        |_, _| {
            Ok("if rt.closed||rt.anchor!=anchor||rt.thread!=thread||rt.owner!=owner{return Err(\"abort owner changed\");}cpu.validate_active(rt)?;".into())
        },
        |_, _| Err("abort cannot return normally".into()),
    )?;
    let exit_body = crate::crt_stream_emit::emit_body(
        &Graph::decode(exit, 0x407004)?,
        |pc, target| {
            if target != Target::Direct(0x406e69) {
                return Err("abort exit target".into());
            }
            let effect = if registered {
                format!("cpu.call_activation(rt,{},0,|rt,c|abort_shared_exit_original(rt,c,epoch))?;return Err(\"abort shared exit unexpectedly returned\");",pc+5)
            } else {
                "return Err(\"abort shared exit 0x406e69 status3 mode2 unbound\");".into()
            };
            Ok(format!("let sp=CrtCpu::pointer(cpu.r[4])?;for(i,value)in [3,2,0].into_iter().enumerate(){{if rt.load(rt.offset(sp,i as i64*4)?,32)?!=CrtValue::scalar(value){{return Err(\"abort shared exit argument domain\");}}}}{effect}"))
        },
        &Default::default(),
        32,
    )?;
    let exit_parameter = if registered {
        ",epoch:&mut NormalCallEpoch<'_>"
    } else {
        ""
    };
    let branch_parameter = if registered {
        "epoch:&mut NormalCallEpoch<'_>"
    } else {
        "lookup:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->RegistryResult<CrtValue>"
    };
    Ok(format!("fn abort_exit_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu{exit_parameter})->RegistryResult<CrtValue>{{cpu.validate_active(rt)?;{exit_body}}}fn abort_branch_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,{branch_parameter})->RegistryResult<CrtValue>{{cpu.validate_active(rt)?;let anchor=rt.anchor;let thread=rt.thread;let owner=rt.owner;{body}}}"))
}

#[test]
fn original_abort_branches_reject_unknown_stale_and_cross_thread_effects() {
    let extra = format!(
        "type RegistryResult<T>=Result<T,&'static str>;{}",
        branch_source(&crate::crt_ptd::raw(ABORT), &crate::crt_ptd::raw(EXIT)).unwrap()
    );
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
for mode in 0..13{
 let mut rt=CrtStreamRuntime::new(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0x9000,2048,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,1536).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();
 let flags=rt.map_region(0x41c128,1,CrtRegionKind::Module,None).unwrap();rt.store(flags,8,match mode{3=>CrtValue::scalar(2),4=>CrtValue::Scalar{bits:0,known:0},5=>CrtValue::Scalar{bits:0,known:2},6=>CrtValue::Scalar{bits:2,known:2},_=>CrtValue::scalar(0)}).unwrap();let marker=rt.map_region(0x7000,4,CrtRegionKind::ThreadData,Some(&[0;4])).unwrap();let mut visited=false;
 let result=abort_branch_original(&mut rt,&mut cpu,&mut|rt,c|{
  visited=true;rt.store(marker,32,CrtValue::scalar(77))?;
  if mode==11{rt.owner+=1;}if mode==12{rt.closed=true;}if mode==9{return Err("independent query failure after write");}if mode==7{rt.thread+=1;}if mode==8{rt.memory.release(flags.cap,flags.owner).map_err(|_|"independent flag storage retirement")?;}
  c.clobber(if mode==2{CrtValue::Scalar{bits:0,known:0}}else{CrtValue::scalar(u32::from(mode==1))});if mode==10{Ok(c.r[0])}else{c.finish(rt)}
 });assert!(visited);assert!(!cpu.returned);if mode==12{assert_eq!(rt.memory.read(marker.address(),4).unwrap(),&[77,0,0,0]);}else{assert_eq!(rt.load(marker,32).unwrap(),CrtValue::scalar(77));}
 let expected=match mode{0|5=>"abort shared exit 0x406e69 status3 mode2 unbound",1=>"abort signal22 dispatch 0x40cc14 unbound",2|4=>"CRT unknown ZF",3|6=>"abort processor-feature/report/fast-fail effects unbound",7|11=>"abort owner changed",12=>"CRT retired stream lifecycle",8=>"CRT pointer lifetime",9=>"independent query failure after write",10=>"CRT callee missing exact protected RET",_=>unreachable!()};assert_eq!(result,Err(expected),"branch case {mode}");
 if mode==0||mode==5{let s=CrtCpu::pointer(cpu.r[4]).unwrap();for(i,value)in [3,2,0].into_iter().enumerate(){assert_eq!(rt.load(rt.offset(s,i as i64*4).unwrap(),32).unwrap(),CrtValue::scalar(value));}}
 if mode==1{assert_eq!(rt.load(CrtCpu::pointer(cpu.r[4]).unwrap(),32).unwrap(),CrtValue::scalar(22));}
 if mode==3||mode==6{assert_eq!(rt.load(CrtCpu::pointer(cpu.r[4]).unwrap(),32).unwrap(),CrtValue::scalar(23));}
}
"#,
        "abort-branches",
    );
    let a = crate::crt_ptd::raw(ABORT);
    let e = crate::crt_ptd::raw(EXIT);
    for i in 0..a.len() {
        let mut b = a.clone();
        b[i] ^= 1;
        assert!(branch_source(&b, &e).is_err());
    }
    for i in 0..e.len() {
        let mut b = e.clone();
        b[i] ^= 1;
        assert!(branch_source(&a, &b).is_err());
    }
}
