//! Bounded three-word C++ record adapter. No dispatcher or cleanup effect grant.
/// Validate independently supplied expected metadata before emitting a binding.
/// This subset has no catches/IP map/exception-specification; all actions still
/// require an execution/effect contract before any cleanup receipt can exist.
pub(crate) fn emit(
    metadata: &[u8],
    address: u32,
    map: &[u8],
    map_address: u32,
) -> Result<String, String> {
    if metadata.len() != 36
        || address == 0
        || address % 4 != 0
        || map_address == 0
        || map_address % 4 != 0
    {
        return Err("C++ metadata shape/alignment".into());
    }
    let words: Vec<u32> = metadata
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect();
    let n = words[1] as usize;
    if words[0] != 0x19930522
        || n == 0
        || n > 32
        || words[2] != map_address
        || words[3..8] != [0; 5]
        || words[8] != 1
        || map.len() != n * 8
    {
        return Err("C++ metadata unsupported fields/budget".into());
    }
    let end = address.checked_add(36).ok_or("C++ metadata overflow")?;
    let me = map_address
        .checked_add(map.len() as u32)
        .ok_or("C++ map overflow")?;
    if address < me && map_address < end {
        return Err("C++ metadata/map alias".into());
    }
    let rows: Vec<(i32, u32)> = map
        .chunks_exact(8)
        .map(|b| {
            (
                i32::from_le_bytes(b[..4].try_into().unwrap()),
                u32::from_le_bytes(b[4..].try_into().unwrap()),
            )
        })
        .collect();
    for (i, &(next, action)) in rows.iter().enumerate() {
        if next < -1
            || next >= i as i32
            || action == 0
            || (action >= address && action < end)
            || (action >= map_address && action < me)
        {
            return Err("C++ nondecreasing state/unknown action/alias".into());
        }
    }
    Ok(format!("{}\nfn cxx_bind(rt:&CrtStreamRuntime,cpu:&CrtCpu,frame:&CrtPtdFrame)->Result<CrtCxxRecord,&'static str>{{CrtCxxRecord::bind(rt,cpu,frame,{address},&{:?},{map_address},&{:?},&{:?})}}",TYPES,metadata,map,rows))
}
pub(crate) const HANDLER: &str = "90908b5424088d420c8b4af033c8e863cafeffb82cb44100e90fe5feff";
pub(crate) const METADATA: &str =
    "22059319020000001cb44100000000000000000000000000000000000000000001000000";
pub(crate) const UNWIND_MAP: &str = "fffffffffc264000fffffffffc264000";
pub(crate) const ACTION: &str = "e90b500000";

pub(crate) const COMMON: &str = "558bec83ec08535657fc8945fc33c0505050ff75fcff7514ff7510ff750cff7508e8500e000083c4208945f85f5e5b8b45f88be55dc3";
pub(crate) const DISPATCH_THUNK: &str = "558bec5de9f5feffff";
pub(crate) const DISPATCH_ENTRY: &str = "558bec535657ff7510";

pub(crate) const CONTEXT_CHECK:&str="558bec813d28514100f91b4000741f648b0d180000008b45088b80c40000003b410872053b410476056a0d59cd295dc3";
fn context_source(code: &[u8]) -> Result<String, String> {
    let proof = crate::handler_context::prove_context_check(code, 0x402877, 0x415128)?;
    let types = crate::handler_context::EMITTED_TYPES;
    let body = proof.body();
    Ok(format!(
        r#"{types}
impl ThreadContext{{fn original_check(&self,owner:u64,selector:u32)->Result<(),&'static str>{{{body}}}}}
struct CrtCxxContext{{anchor:guest_memory::Capability,thread:u64,outer:u64,bp:CrtPointer,context:CrtPointer,stack:CrtPointer,esp:CrtPointer,live:bool}}
impl CrtCxxContext{{
 fn bind(rt:&CrtStreamRuntime,owner:&CrtCpu,frame:&CrtPtdFrame,context:CrtPointer,stack:CrtPointer)->Result<Self,&'static str>{{
  let esp=CrtCpu::pointer(rt.load(rt.offset(context,0xc4)?,32)?)?;
  let token=Self{{anchor:rt.anchor,thread:rt.thread,outer:owner.return_id,bp:frame.bp,context,stack,esp,live:true}};token.check(rt,owner,frame)?;Ok(token)
 }}
 fn check(&self,rt:&CrtStreamRuntime,owner:&CrtCpu,frame:&CrtPtdFrame)->Result<(),&'static str>{{
  frame.live(rt,owner)?;
  if !self.live||self.anchor!=rt.anchor||self.thread!=rt.thread||self.outer!=owner.return_id||self.bp!=frame.bp{{return Err("C++ captured context owner/lifetime");}}
  if self.context.kind!=CrtRegionKind::Context||self.context.address()!=self.context.base||self.stack.kind!=CrtRegionKind::Stack||self.stack.address()!=self.stack.base||frame.bp.cap!=self.stack.cap||self.esp.cap!=self.stack.cap{{return Err("C++ captured context/stack role");}}
  if !rt.regions.iter().any(|r|r.pointer==self.stack)||!rt.regions.iter().any(|r|r.pointer==self.context){{return Err("C++ captured context/root extent");}}
  rt.valid(self.context,200)?;rt.valid(self.stack,self.stack.size)?;rt.valid(self.esp,0)?;
  if rt.load(rt.offset(self.context,0xc4)?,32)?!=CrtValue::Pointer(self.esp){{return Err("C++ captured ESP changed/unknown");}}
  let base=self.stack.address().checked_add(self.stack.size).ok_or("C++ stack bound overflow")?;
  let captured=ThreadContext::new(rt.thread,self.stack.address(),base,self.esp.address())?;
  let selector=rt.load(rt.resolve_absolute(0x415128,CrtRegionKind::Module)?,32)?.known_scalar()?;
  captured.original_check(rt.thread,selector)
 }}
 fn retire(&mut self){{self.live=false;}}
}}
"#
    ))
}

fn common_source(common: &[u8], thunk: &[u8], entry: &[u8]) -> Result<String, String> {
    if common != crate::crt_ptd::raw(COMMON)
        || thunk != crate::crt_ptd::raw(DISPATCH_THUNK)
        || entry != crate::crt_ptd::raw(DISPATCH_ENTRY)
    {
        return Err("C++ common dispatcher code binding".into());
    }
    let lift = |b: &[u8], pc| {
        crate::crt_stream_emit::emit_linear_fragment(
            &crate::crt_stream_ir::Graph::decode_linear_fragment(b, pc)?,
            &Default::default(),
        )
    };
    let a = lift(&common[..9], 0x403002)?;
    let b = lift(&common[10..33], 0x40300c)?;
    let t = lift(&thunk[..4], 0x403e78)?;
    let e = lift(entry, 0x403d76)?;
    Ok(format!(
        r#"
fn cxx_common(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,owner:&CrtCpu,frame:&CrtPtdFrame,context:&CrtCxxContext)->Result<CrtValue,&'static str>{{
 cpu.validate_active(rt)?;
 let _=(||->Result<CrtValue,&'static str>{{{a}}})()?;
 // Original CLD. This component constructor guarantees DF=0, and the
 // supported operations preserve it. Unknown thread flags are not admitted.
 if cpu.abi!=CrtAbi::Cdecl32Forward{{return Err("C++ CLD requires forward ABI domain");}}
 let _=(||->Result<CrtValue,&'static str>{{{b}}})()?;
 cpu.call_activation(rt,0x403028,0,|rt,cpu|{{
  let _=(||->Result<CrtValue,&'static str>{{{t}}})()?;
  let _=(||->Result<CrtValue,&'static str>{{{e}}})()?;
  context.check(rt,owner,frame)?;
  if rt.load(CrtCpu::pointer(cpu.r[4])?,32)?!=CrtValue::Pointer(context.context){{return Err("C++ validator context argument");}}
  cpu.call_activation(rt,0x403d84,0,|rt,child|{{context.check(rt,owner,frame)?;child.clobber(CrtValue::Scalar{{bits:0,known:0}});child.finish(rt)}})?;
  let argument=cpu.pop(rt)?;cpu.r[1]=argument;
  Err("C++ dispatcher PTD effect unbound")
 }})
}}
"#
    ))
}

/// Lift the original wrapper up to its external dispatcher. Guard mismatch and
/// the dispatcher itself remain rejecting boundaries, never a disposition.
fn handler_prefix(
    bytes: &[u8],
    origin: u32,
    metadata: u32,
    dispatcher: u32,
    guard: &crate::crt_stream_callees::SecurityProof,
) -> Result<String, String> {
    let end = origin.checked_add(29).ok_or("C++ handler overflow")?;
    let metadata_end = metadata
        .checked_add(36)
        .ok_or("C++ handler metadata overflow")?;
    let cookie_end = guard
        .cookie()
        .checked_add(4)
        .ok_or("C++ handler cookie overflow")?;
    let mut expected = crate::crt_ptd::raw(HANDLER);
    expected[15..19].copy_from_slice(&guard.target().wrapping_sub(origin + 19).to_le_bytes());
    expected[20..24].copy_from_slice(&metadata.to_le_bytes());
    expected[25..29].copy_from_slice(&dispatcher.wrapping_sub(end).to_le_bytes());
    if bytes != expected
        || origin == 0
        || metadata == 0
        || metadata % 4 != 0
        || dispatcher == 0
        || metadata < end && origin < metadata_end
        || guard.cookie() < end && origin < cookie_end
        || [metadata, dispatcher, guard.target(), guard.cookie()]
            .iter()
            .any(|p| (origin..end).contains(p))
    {
        return Err("C++ handler instruction/target identity".into());
    }
    let prefix = crate::crt_stream_ir::Graph::decode_linear_fragment(&bytes[..14], origin)?;
    let tail = crate::crt_stream_ir::Graph::decode_linear_fragment(&bytes[19..24], origin + 19)?;
    let prefix = crate::crt_stream_emit::emit_linear_fragment(&prefix, &Default::default())?;
    let tail = crate::crt_stream_emit::emit_linear_fragment(&tail, &Default::default())?;
    let cookie = guard.cookie();
    let next = origin + 19;
    let check = format!(
        r#"cpu.call_activation(rt,{next},0,|rt,child|{{
let expected=rt.load(rt.resolve_absolute({cookie},CrtRegionKind::Module)?,32)?.known_scalar()?;
let actual=CrtCpu::number(child.r[1])?;
child.binary(rt,7,CrtValue::scalar(actual),CrtValue::scalar(expected),32)?;
if actual!=expected{{return Err("C++ security failure effect unbound");}}
child.finish(rt)
}})?;"#
    );
    Ok(format!(
        r#"
fn cxx_handler_prefix(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord,context:&CrtCxxContext)->Result<CrtValue,&'static str>{{
 record.state(rt,owner,frame)?;cpu.validate_active(rt)?;
 if frame.handler!={origin}||frame.low!=rt.offset(frame.bp,-28)?||record.metadata.address()!={metadata}{{return Err("C++ handler/frame binding");}}
 let sp=CrtCpu::pointer(cpu.r[4])?;
 let call_low=rt.offset(sp,-4)?;rt.valid(call_low,16)?;
 if cpu.return_id==owner.return_id||u64::from(call_low.address())<u64::from(frame.bp.address())+4&&u64::from(frame.low.address())<u64::from(call_low.address())+16{{return Err("C++ handler call/frame overlap");}}
 if rt.load(rt.offset(sp,8)?,32)?!=CrtValue::Pointer(rt.offset(frame.bp,-12)?){{return Err("C++ establisher pointer identity");}}
 let _=(||->Result<CrtValue,&'static str>{{{prefix}}})()?;
 {check}
 let _=(||->Result<CrtValue,&'static str>{{{tail}}})()?;
 cxx_common(rt,cpu,owner,frame,context)
}}
"#
    ))
}
const TYPES: &str = r#"
struct CrtCxxRecord{anchor:guest_memory::Capability,thread:u64,outer:u64,bp:CrtPointer,metadata:CrtPointer,map:CrtPointer,metadata_bytes:Vec<u8>,map_bytes:Vec<u8>,rows:Vec<(i32,u32)>}
impl CrtCxxRecord{
 fn bytes(rt:&CrtStreamRuntime,p:CrtPointer,expected:&[u8])->Result<(),&'static str>{for(i,b)in expected.iter().enumerate(){if rt.load(rt.offset(p,i as i64)?,8)?.known_scalar()?!=u32::from(*b){return Err("C++ metadata mutated/unknown");}}Ok(())}
 fn bind(rt:&CrtStreamRuntime,cpu:&CrtCpu,frame:&CrtPtdFrame,address:u32,bytes:&[u8],map_address:u32,map_bytes:&[u8],rows:&[(i32,u32)])->Result<Self,&'static str>{
  frame.live(rt,cpu)?;let metadata=rt.subrange(rt.resolve_absolute(address,CrtRegionKind::Module)?,bytes.len()as u32)?;let map=rt.subrange(rt.resolve_absolute(map_address,CrtRegionKind::Module)?,map_bytes.len()as u32)?;
  let result=Self{anchor:rt.anchor,thread:rt.thread,outer:cpu.return_id,bp:frame.bp,metadata,map,metadata_bytes:bytes.to_vec(),map_bytes:map_bytes.to_vec(),rows:rows.to_vec()};result.state(rt,cpu,frame)?;Ok(result)
 }
 fn state(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu,frame:&CrtPtdFrame)->Result<i32,&'static str>{
  frame.live(rt,cpu)?;if rt.anchor!=self.anchor||rt.thread!=self.thread||cpu.return_id!=self.outer||frame.bp!=self.bp{return Err("C++ record owner/call identity");}
  Self::bytes(rt,self.metadata,&self.metadata_bytes)?;Self::bytes(rt,self.map,&self.map_bytes)?;
  let state=rt.load(rt.offset(self.bp,-4)?,32)?.known_scalar()? as i32;
  if state< -1||state>=self.rows.len() as i32{return Err("C++ unknown/out-of-range state");}Ok(state)
 }
 fn required_action(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu,frame:&CrtPtdFrame)->Result<Option<(i32,u32)>,&'static str>{let state=self.state(rt,cpu,frame)?;Ok(if state== -1{None}else{Some(self.rows[state as usize])})}
 // Deliberately no completion receipt, cursor update, dispatcher disposition
 // or registry registration: an action address does not prove its effects.
}
"#;
#[test]
fn owned_cxx_record_keeps_state_metadata_and_continuation_distinct() {
    let meta = crate::crt_ptd::raw(METADATA);
    let map = crate::crt_ptd::raw(UNWIND_MAP);
    assert_eq!(crate::crt_ptd::raw(ACTION), [0xe9, 0x0b, 0x50, 0, 0]);
    let security = crate::crt_stream_callees::prove_security(
        &crate::crt_ptd::raw("3b0d00c041007501c3e97c020000"),
        0x40154c,
    )
    .unwrap();
    let handler = handler_prefix(
        &crate::crt_ptd::raw(HANDLER),
        0x414ad6,
        0x41b42c,
        0x403002,
        &security,
    )
    .unwrap();
    let extra = format!(
        "{} {} {} {} {}",
        crate::crt_ptd::helper_source(
            &crate::crt_ptd::raw(crate::crt_ptd::PROLOG),
            0x414268,
            &crate::crt_ptd::raw(crate::crt_ptd::EPILOG),
            0x414254,
            0x41c000
        )
        .unwrap(),
        emit(&meta, 0x41b42c, &map, 0x41b41c).unwrap(),
        handler,
        common_source(
            &crate::crt_ptd::raw(COMMON),
            &crate::crt_ptd::raw(DISPATCH_THUNK),
            &crate::crt_ptd::raw(DISPATCH_ENTRY)
        )
        .unwrap(),
        context_source(&crate::crt_ptd::raw(CONTEXT_CHECK)).unwrap()
    );
    let body = format!(
        r#"
let mut rt=CrtStreamRuntime::new(7,9,0x8000,65536).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&123u32.to_le_bytes())).unwrap();let meta=rt.map_region(0x41b42c,36,CrtRegionKind::Module,Some(&{meta:?})).unwrap();rt.map_region(0x41b41c,16,CrtRegionKind::Module,Some(&{map:?})).unwrap();let stack=rt.map_region(0x9000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,768).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();cpu.push(&mut rt,CrtValue::scalar(0)).unwrap();cpu.r[0]=CrtValue::scalar(0x414ad6);let previous=rt.thread_head(4,5,[1,2,3]).unwrap();let mut frame=CrtPtdFrame::new(&rt,&cpu,previous,0x414ad6,0x41c000).unwrap();ptd_prolog(&mut rt,&mut cpu,&mut frame,0x40a33e).unwrap();let binding=cxx_bind(&rt,&cpu,&frame).unwrap();assert_eq!(binding.required_action(&rt,&cpu,&frame).unwrap(),None);let state=rt.offset(frame.bp,-4).unwrap();
let foreign=CrtStreamRuntime::new(7,9,0x8000,65536).unwrap();assert!(binding.state(&foreign,&cpu,&frame).is_err());
let context_pointer=rt.map_region(0xb000,200,CrtRegionKind::Context,None).unwrap();rt.store(rt.offset(context_pointer,0xc4).unwrap(),32,CrtValue::Pointer(frame.low)).unwrap();let selector=rt.map_region(0x415128,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes())).unwrap();let mut context=CrtCxxContext::bind(&rt,&cpu,&frame,context_pointer,stack).unwrap();
let scratch=rt.map_region(0xa000,1024,CrtRegionKind::Stack,None).unwrap();
for fault in 0..8{{let hs=rt.offset(scratch,if fault==6{{24}}else{{256+fault*96}}).unwrap();rt.store(hs,32,CrtValue::ProtectedReturn(123)).unwrap();rt.store(rt.offset(hs,8).unwrap(),32,if fault==1{{CrtValue::scalar(frame.bp.address()-12)}}else{{CrtValue::Pointer(rt.offset(frame.bp,if fault==2{{-8}}else{{-12}}).unwrap())}}).unwrap();for (i,value) in [(1,0xe06d7363),(3,0x1234),(4,0x5678)]{{rt.store(rt.offset(hs,i*4).unwrap(),32,CrtValue::scalar(value)).unwrap();}}rt.store(rt.offset(hs,12).unwrap(),32,CrtValue::Pointer(if fault==7{{rt.offset(context_pointer,4).unwrap()}}else{{context_pointer}})).unwrap();let mut child=CrtCpu::new(hs,123).unwrap();if fault==5{{child.r[4]=CrtValue::Pointer(frame.low);}}let guard=rt.load(frame.low,32).unwrap();if fault==3{{rt.store(frame.low,32,CrtValue::scalar(0)).unwrap();}}if fault==4{{rt.store(frame.low,32,CrtValue::Scalar{{bits:0,known:0}}).unwrap();}}
let result=cxx_handler_prefix(&mut rt,&mut child,&cpu,&frame,&binding,&context);assert!(result.is_err());assert!(!child.returned);if fault==0{{assert_eq!(result.unwrap_err(),"C++ dispatcher PTD effect unbound");let bp=CrtCpu::pointer(child.r[5]).unwrap();for(i,v)in [(8,0xe06d7363),(20,0x5678),(24,0x41b42c),(28,0),(32,0),(36,0)]{{assert_eq!(rt.load(rt.offset(bp,i).unwrap(),32).unwrap(),CrtValue::scalar(v));}}assert_eq!(rt.load(rt.offset(bp,12).unwrap(),32).unwrap(),CrtValue::Pointer(rt.offset(frame.bp,-12).unwrap()));assert_eq!(child.r[1],CrtValue::Pointer(context_pointer));}}if fault==6{{assert_eq!(rt.load(rt.offset(hs,-8).unwrap(),32).unwrap(),CrtValue::scalar(0x41b42c));assert!(frame.live(&rt,&cpu).is_ok());}}rt.store(frame.low,32,guard).unwrap();rt.consume_stack(hs,CrtValue::ProtectedReturn(123)).unwrap();}}
rt.store(rt.offset(stack,196).unwrap(),32,CrtValue::Pointer(frame.low)).unwrap();assert!(CrtCxxContext::bind(&rt,&cpu,&frame,stack,stack).is_err());assert!(CrtCxxContext::bind(&foreign,&cpu,&frame,context_pointer,stack).is_err());assert!(CrtCxxContext::bind(&rt,&cpu,&frame,context_pointer,scratch).is_err());assert!(CrtCxxContext::bind(&rt,&cpu,&frame,context_pointer,rt.subrange(stack,512).unwrap()).is_err());
for esp in [stack,rt.offset(stack,1024).unwrap()]{{rt.store(rt.offset(context_pointer,0xc4).unwrap(),32,CrtValue::Pointer(esp)).unwrap();let t=CrtCxxContext::bind(&rt,&cpu,&frame,context_pointer,stack).unwrap();t.check(&rt,&cpu,&frame).unwrap();}}
rt.store(rt.offset(context_pointer,0xc4).unwrap(),32,CrtValue::Pointer(frame.low)).unwrap();
for bad in [CrtValue::scalar(frame.low.address()),CrtValue::Pointer(scratch),CrtValue::Scalar{{bits:0,known:0}}]{{rt.store(rt.offset(context_pointer,0xc4).unwrap(),32,bad).unwrap();assert!(context.check(&rt,&cpu,&frame).is_err());}}
rt.store(rt.offset(context_pointer,0xc4).unwrap(),32,CrtValue::Pointer(frame.low)).unwrap();rt.store(selector,32,CrtValue::Scalar{{bits:0,known:0}}).unwrap();assert!(context.check(&rt,&cpu,&frame).is_err());rt.store(selector,32,CrtValue::scalar(0x401bf9)).unwrap();context.check(&rt,&cpu,&frame).unwrap();let mut cloned=CrtCxxContext::bind(&rt,&cpu,&frame,context_pointer,stack).unwrap();cloned.context=rt.map_region(0xc000,200,CrtRegionKind::Context,None).unwrap();assert!(cloned.check(&rt,&cpu,&frame).is_err());context.retire();assert!(context.check(&rt,&cpu,&frame).is_err());
for n in [0,1]{{rt.store(state,32,CrtValue::scalar(n)).unwrap();assert_eq!(binding.required_action(&rt,&cpu,&frame).unwrap(),Some((-1,0x4026fc)));assert_eq!(rt.load(state,32).unwrap(),CrtValue::scalar(n));}}
rt.store(state,32,CrtValue::Scalar{{bits:0,known:0}}).unwrap();assert!(binding.state(&rt,&cpu,&frame).is_err());rt.store(state,32,CrtValue::scalar(2)).unwrap();assert!(binding.state(&rt,&cpu,&frame).is_err());rt.store(state,32,CrtValue::scalar(1)).unwrap();let old=cpu.return_id;cpu.return_id+=1;assert!(binding.state(&rt,&cpu,&frame).is_err());cpu.return_id=old;rt.store(meta,32,CrtValue::scalar(0)).unwrap();assert!(binding.state(&rt,&cpu,&frame).is_err());rt.store(meta,32,CrtValue::scalar(0x19930522)).unwrap();let live_capture=CrtCxxContext::bind(&rt,&cpu,&frame,context_pointer,stack).unwrap();ptd_epilog(&mut rt,&mut cpu,&mut frame,0x40a3b8).unwrap();assert!(live_capture.check(&rt,&cpu,&frame).is_err());assert!(binding.state(&rt,&cpu,&frame).is_err());cpu.finish(&mut rt).unwrap();
"#
    );
    crate::crt_stream_callees_tests::native(&extra, &body, "cxx-record");
    for i in [0, 4, 8, 12, 16, 20, 24, 28, 32] {
        let mut bad = meta.clone();
        bad[i] ^= 1;
        assert!(emit(&bad, 0x41b42c, &map, 0x41b41c).is_err());
    }
    for (which, bytes) in [COMMON, DISPATCH_THUNK, DISPATCH_ENTRY].iter().enumerate() {
        for i in 0..bytes.len() / 2 {
            let mut inputs = [
                crate::crt_ptd::raw(COMMON),
                crate::crt_ptd::raw(DISPATCH_THUNK),
                crate::crt_ptd::raw(DISPATCH_ENTRY),
            ];
            inputs[which][i] ^= 1;
            assert!(common_source(&inputs[0], &inputs[1], &inputs[2]).is_err());
        }
    }
    for i in [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
    ] {
        let mut code = crate::crt_ptd::raw(CONTEXT_CHECK);
        code[i] ^= 1;
        assert!(context_source(&code).is_err(), "context mutation {}", i);
    }
    for i in 0..29 {
        let mut code = crate::crt_ptd::raw(HANDLER);
        code[i] ^= 1;
        assert!(handler_prefix(&code, 0x414ad6, 0x41b42c, 0x403002, &security).is_err());
    }
    assert!(emit(&meta, 0xfffffff0, &map, 0x41b41c).is_err());
    let mut aliased = meta.clone();
    aliased[8..12].copy_from_slice(&0x41b430u32.to_le_bytes());
    assert!(emit(&aliased, 0x41b42c, &map, 0x41b430).is_err());
    let mut cycle = map.clone();
    cycle[..4].copy_from_slice(&0i32.to_le_bytes());
    assert!(emit(&meta, 0x41b42c, &cycle, 0x41b41c).is_err());
}
