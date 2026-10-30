//! Original abort entry and signal-query caller. The locked query is unbound.
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
