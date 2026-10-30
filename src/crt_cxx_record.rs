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
    let projection = proof.projection_body();
    Ok(format!(
        r#"{types}
impl ThreadContext{{fn original_check(&self,owner:u64,selector:u32)->Result<(),&'static str>{{{body}}}}}
struct CrtCxxContext{{anchor:guest_memory::Capability,thread:u64,outer:u64,bp:CrtPointer,context:CrtPointer,stack:CrtPointer,esp:Option<CrtPointer>,esp_value:CrtValue,unobserved:Option<CrtUnobservedContext>,live:bool}}
impl CapturedStackView{{fn cxx_original_check(&self,owner:u64,selector:u32)->Result<(),&'static str>{{{projection}}}}}
impl CrtCxxContext{{
 fn bind(rt:&CrtStreamRuntime,owner:&CrtCpu,frame:&CrtPtdFrame,context:CrtPointer,stack:CrtPointer)->Result<Self,&'static str>{{
  let esp=CrtCpu::pointer(rt.load(rt.offset(context,0xc4)?,32)?)?;
  let token=Self{{anchor:rt.anchor,thread:rt.thread,outer:owner.return_id,bp:frame.bp,context,stack,esp:Some(esp),esp_value:CrtValue::Pointer(esp),unobserved:None,live:true}};token.check(rt,owner,frame)?;Ok(token)
 }}
 fn check(&self,rt:&CrtStreamRuntime,owner:&CrtCpu,frame:&CrtPtdFrame)->Result<(),&'static str>{{
  frame.live(rt,owner)?;
  if !self.live||self.anchor!=rt.anchor||self.thread!=rt.thread||self.outer!=owner.return_id||self.bp!=frame.bp{{return Err("C++ captured context owner/lifetime");}}
  if self.context.kind!=CrtRegionKind::Context||self.context.address()!=self.context.base||self.stack.kind!=CrtRegionKind::Stack||self.stack.address()!=self.stack.base||frame.bp.cap!=self.stack.cap||self.esp.is_some_and(|p|p.cap!=self.stack.cap){{return Err("C++ captured context/stack role");}}
  if !rt.regions.iter().any(|r|r.pointer==self.stack)||!rt.regions.iter().any(|r|r.pointer==self.context){{return Err("C++ captured context/root extent");}}
  rt.valid(self.context,200)?;rt.valid(self.stack,self.stack.size)?;
  if let Some(esp)=self.esp{{rt.valid(esp,0)?;if self.esp_value!=CrtValue::Pointer(esp)&&self.esp_value!=CrtValue::scalar(esp.address()){{return Err("C++ captured numeric view mismatch");}}}}
  if let Some(lease)=&self.unobserved{{
   if lease.context!=self.context||self.esp.is_some()||self.esp_value!=(CrtValue::Scalar{{bits:0,known:0}}){{return Err("C++ unobserved context representation");}}
   return lease.require_helper(rt,0x402877,0x415128,{bypass},&{code:?});
  }}
  if rt.load(rt.offset(self.context,0xc4)?,32)?!=self.esp_value{{return Err("C++ captured ESP changed/unknown");}}
  let base=self.stack.address().checked_add(self.stack.size).ok_or("C++ stack bound overflow")?;
  let(bits,known)=match self.esp_value{{CrtValue::Pointer(p)if self.esp==Some(p)=>(p.address(),u32::MAX),CrtValue::Scalar{{bits,known}}=>(bits,known),_=>return Err("C++ captured representation mismatch")}};
  let captured=CapturedStackView::from_bits(rt.thread,self.stack.address(),base,bits,known)?;
  if captured.captured_below_limit(rt.thread)?||!captured.captured_at_most_base(rt.thread)?{{return Err("invalid captured same-thread stack boundary");}}
  let selector=rt.load(rt.resolve_absolute(0x415128,CrtRegionKind::Module)?,32)?.known_scalar()?;
  captured.cxx_original_check(rt.thread,selector)
 }}
 fn numeric_esp(&self)->Result<CrtPointer,&'static str>{{self.esp.ok_or("C++ unwind requires numeric captured ESP")}}
 fn retire(&mut self){{self.live=false;}}
}}
"#,
        bypass = proof.bypass_selector()
    ))
}

pub(crate) const DISPATCH_PTD_USE: &str = "8b4d1833f68b5508bbffffff1fbf22059319397020";
pub(crate) const DISPATCH_TAIL:&str="7522813a63736de0741a813a2600008074128b0123c33bc7720af64120010f85ad000000f642046674263971040f849e00000039751c0f859500000051ff7514ff750ce8bd03000083c40ce98100000039710c751e8b0123c33d21059319720539711c750e3bc772688b4120c1e802a801745e813a63736de0753a837a10037234397a14762f8b421c8b700885f674250fb6452450ff7520ff751c51ff75148bceff7510ff750c52ff1528514100ffd683c420eb1fff7520ff751cff752451ff7514ff7510ff750c52e8a2f9ffff83c42033c0405f5e5b5dc3";
fn common_source(
    common: &[u8],
    thunk: &[u8],
    entry: &[u8],
    tail_bytes: &[u8],
) -> Result<String, String> {
    common_source_bound(common, thunk, entry, tail_bytes, false)
}
fn common_source_bound(
    common: &[u8],
    thunk: &[u8],
    entry: &[u8],
    tail_bytes: &[u8],
    cached: bool,
) -> Result<String, String> {
    common_source_mode(common, thunk, entry, tail_bytes, cached, false)
}
/// Original common dispatcher with the unwind call bound to a live delivery
/// child epoch. Acquisition and nested exception effects remain separate gates.
pub(crate) fn delivered_common_source() -> Result<String, String> {
    let context = context_source(&crate::crt_ptd::raw(CONTEXT_CHECK))?;
    let context = &context[context
        .find("struct CrtCxxContext")
        .ok_or("C++ shared context types")?..];
    Ok(format!(
        "{}\n{}",
        context,
        common_source_mode(
            &crate::crt_ptd::raw(COMMON),
            &crate::crt_ptd::raw(DISPATCH_THUNK),
            &crate::crt_ptd::raw(DISPATCH_ENTRY),
            &crate::crt_ptd::raw(DISPATCH_TAIL),
            true,
            true
        )?
    ))
}
fn common_source_mode(
    common: &[u8],
    thunk: &[u8],
    entry: &[u8],
    tail_bytes: &[u8],
    cached: bool,
    delivery: bool,
) -> Result<String, String> {
    common_source_provider(common, thunk, entry, tail_bytes, cached, delivery, false)
}
/// Execute the same original dispatcher with an owned, checked whole-PTD
/// producer. The caller must bind its actual allocator/API effects separately.
fn common_source_provider(
    common: &[u8],
    thunk: &[u8],
    entry: &[u8],
    tail_bytes: &[u8],
    cached: bool,
    delivery: bool,
    whole_ptd: bool,
) -> Result<String, String> {
    if whole_ptd && cached {
        return Err("C++ conflicting PTD provider modes".into());
    }
    let ptd_call = if whole_ptd {
        "let value=lookup(rt,child)?;if !child.returned||child.r[0]!=value{return Err(\"C++ PTD provider return authority\");}rt.dispatcher_ptd(CrtCpu::pointer(value)?)?;Ok(value)".to_string()
    } else if cached {
        "cxx_ptd_required(rt,child,CrtResolverAccess::Cached,fiber,slot,&mut |_,_,_|Err(\"C++ cached handler cannot load\"))".into()
    } else {
        "cxx_ptd_required(rt,child,lookup)".into()
    };
    let epoch_parameter = if delivery {
        "epoch:&mut NormalCallEpoch<'_>,"
    } else {
        ""
    };
    let preflight = if delivery {
        r#"
 epoch.state()?;if epoch.delivery.is_none(){return Err("C++ dispatcher requires delivery child authority");}
 context.check(rt,owner,frame)?;record.state(rt,owner,frame)?;
 let entry=CrtCpu::pointer(cpu.entry[4])?;
 if rt.load(rt.offset(entry,8)?,32)?!=CrtValue::Pointer(rt.offset(frame.bp,-12)?)||rt.load(rt.offset(entry,12)?,32)?!=CrtValue::Pointer(context.context){return Err("C++ dispatcher original owner/context arguments");}
 "#
    } else {
        ""
    };
    let parameters = if cached {
        "fiber:CrtFiber,slot:CrtFlsSlot"
    } else {
        "lookup:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>"
    };
    if common != crate::crt_ptd::raw(COMMON)
        || thunk != crate::crt_ptd::raw(DISPATCH_THUNK)
        || entry != crate::crt_ptd::raw(DISPATCH_ENTRY)
        || tail_bytes != crate::crt_ptd::raw(DISPATCH_TAIL)
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
    let use_ptd = lift(&crate::crt_ptd::raw(DISPATCH_PTD_USE), 0x403d8a)?;
    let bytes = tail_bytes.to_vec();
    let mut nodes = std::collections::BTreeMap::new();
    let mut decoder =
        iced_x86::Decoder::with_ip(32, &bytes, 0x403d9f, iced_x86::DecoderOptions::NONE);
    while decoder.can_decode() {
        let i = decoder.decode();
        let a = (i.ip32() - 0x403d9f) as usize;
        nodes.insert(
            i.ip32(),
            crate::crt_stream_ir::Graph::decode_instruction(&bytes[a..a + i.len()], i.ip32())?,
        );
    }
    let graph = crate::crt_stream_ir::Graph {
        origin: 0x403d9f,
        end: 0x403e78,
        nodes,
    };
    if graph
        .nodes
        .values()
        .flat_map(|n| &n.successors)
        .any(|p| !graph.nodes.contains_key(p))
    {
        return Err("C++ dispatcher tail CFG".into());
    }
    let tail = crate::crt_stream_emit::emit_body_with_indirect(
        &graph,
        |pc, target| {
            if delivery
                && pc == 0x403de2
                && matches!(target, crate::crt_stream_ir::Target::Direct(0x4041a4))
            {
                Ok("cpu.call_activation(rt,0x403de7,0,|rt,child|cxx_unwind_cached(rt,child,epoch,owner,frame,record,fiber,slot))?;".into())
            } else {
                Ok("return Err(\"C++ dispatcher unwind/search call effects unbound\");".into())
            }
        },
        &Default::default(),
        4096,
        |_, _| Err("C++ tail thread effect".into()),
        |_, _| Ok(String::new()),
        |_, _| Ok(None),
        None,
        |_, _, _| Ok(None),
        |_, _| Ok("return Err(\"C++ indirect search backend unbound\");".into()),
    )?;
    let epilog = crate::crt_stream_emit::emit_body(
        &crate::crt_stream_ir::Graph::decode(&common[38..], 0x403028)?,
        |_, _| Err("C++ common epilog calls".into()),
        &Default::default(),
        4096,
    )?;
    Ok(format!(
        r#"
fn cxx_common(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,owner:&CrtCpu,frame:&CrtPtdFrame,context:&CrtCxxContext,record:&CrtCxxRecord,{epoch_parameter}{parameters})->Result<CrtValue,&'static str>{{
 cpu.validate_active(rt)?;{preflight}
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
  cpu.call_activation(rt,0x403d8a,0,|rt,child|{{{ptd_call}}})?;
  let _=(||->Result<CrtValue,&'static str>{{{use_ptd}}})()?;
  record.state(rt,owner,frame)?;context.check(rt,owner,frame)?;
  if CrtCpu::number(cpu.r[1])?!=record.metadata.address(){{return Err("C++ dispatcher metadata identity");}}cpu.r[1]=CrtValue::Pointer(record.metadata);
  let exception=CrtCpu::pointer(cpu.r[2])?;if exception.kind!=CrtRegionKind::Context{{return Err("C++ exception object role");}}rt.valid(exception,80)?;
  {tail}
 }})?;
 {epilog}
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
    handler_prefix_bound(bytes, origin, metadata, dispatcher, guard, false)
}
fn handler_prefix_bound(
    bytes: &[u8],
    origin: u32,
    metadata: u32,
    dispatcher: u32,
    guard: &crate::crt_stream_callees::SecurityProof,
    cached: bool,
) -> Result<String, String> {
    handler_prefix_mode(bytes, origin, metadata, dispatcher, guard, cached, false)
}
pub(crate) fn delivered_prefix_source() -> Result<String, String> {
    let guard = crate::crt_stream_callees::prove_security(
        &crate::crt_ptd::raw("3b0d00c041007501c3e97c020000"),
        0x40154c,
    )?;
    handler_prefix_mode(
        &crate::crt_ptd::raw(HANDLER),
        0x414ad6,
        0x41b42c,
        0x403002,
        &guard,
        true,
        true,
    )
}
fn handler_prefix_mode(
    bytes: &[u8],
    origin: u32,
    metadata: u32,
    dispatcher: u32,
    guard: &crate::crt_stream_callees::SecurityProof,
    cached: bool,
    delivery: bool,
) -> Result<String, String> {
    let epoch_parameter = if delivery {
        "epoch:&mut NormalCallEpoch<'_>,"
    } else {
        ""
    };
    let epoch_argument = if delivery { "epoch," } else { "" };
    let preflight = if delivery {
        "epoch.state()?;if epoch.delivery.is_none(){return Err(\"C++ prefix requires delivery child authority\");}let entry=CrtCpu::pointer(cpu.entry[4])?;epoch.delivery_range(rt.offset(entry,-4)?.address(),u64::from(entry.address())+4)?;epoch.delivery_arguments(entry.address(),20)?;"
    } else {
        ""
    };
    let parameters = if cached {
        "fiber:CrtFiber,slot:CrtFlsSlot"
    } else {
        "lookup:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>"
    };
    let arguments = if cached { "fiber,slot" } else { "lookup" };
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
fn cxx_handler_identity()->[u32;3]{{[{origin},{metadata},{dispatcher}]}}
fn cxx_handler_prefix(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord,context:&CrtCxxContext,{epoch_parameter}{parameters})->Result<CrtValue,&'static str>{{
 {preflight}record.state(rt,owner,frame)?;cpu.validate_active(rt)?;
 if frame.handler!={origin}||frame.low!=rt.offset(frame.bp,-28)?||record.metadata.address()!={metadata}{{return Err("C++ handler/frame binding");}}
 let sp=CrtCpu::pointer(cpu.r[4])?;
 let call_low=rt.offset(sp,-4)?;rt.valid(call_low,16)?;
 if cpu.return_id==owner.return_id||u64::from(call_low.address())<u64::from(frame.bp.address())+4&&u64::from(frame.low.address())<u64::from(call_low.address())+16{{return Err("C++ handler call/frame overlap");}}
 if rt.load(rt.offset(sp,8)?,32)?!=CrtValue::Pointer(rt.offset(frame.bp,-12)?){{return Err("C++ establisher pointer identity");}}
 let _=(||->Result<CrtValue,&'static str>{{{prefix}}})()?;
 {check}
 let _=(||->Result<CrtValue,&'static str>{{{tail}}})()?;
 cxx_common(rt,cpu,owner,frame,context,record,{epoch_argument}{arguments})
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
        "{} {} {} {} {} {}",
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
            &crate::crt_ptd::raw(DISPATCH_ENTRY),
            &crate::crt_ptd::raw(DISPATCH_TAIL)
        )
        .unwrap(),
        context_source(&crate::crt_ptd::raw(CONTEXT_CHECK)).unwrap(),
        crate::crt_cxx_ptd::source(
            &crate::crt_ptd::raw(crate::crt_cxx_ptd::GETTER),
            &crate::crt_ptd::raw(crate::crt_cxx_ptd::REQUIRED)
        )
        .unwrap()
    );
    let body = format!(
        r#"
let mut rt=CrtStreamRuntime::new(7,9,0x8000,65536).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&123u32.to_le_bytes())).unwrap();let meta=rt.map_region(0x41b42c,36,CrtRegionKind::Module,Some(&{meta:?})).unwrap();rt.map_region(0x41b41c,16,CrtRegionKind::Module,Some(&{map:?})).unwrap();let stack=rt.map_region(0x9000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,768).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();cpu.push(&mut rt,CrtValue::scalar(0)).unwrap();cpu.r[0]=CrtValue::scalar(0x414ad6);let previous=rt.thread_head(4,5,[1,2,3]).unwrap();let mut frame=CrtPtdFrame::new(&rt,&cpu,previous,0x414ad6,0x41c000).unwrap();ptd_prolog(&mut rt,&mut cpu,&mut frame,0x40a33e).unwrap();let binding=cxx_bind(&rt,&cpu,&frame).unwrap();assert_eq!(binding.required_action(&rt,&cpu,&frame).unwrap(),None);let state=rt.offset(frame.bp,-4).unwrap();
let foreign=CrtStreamRuntime::new(7,9,0x8000,65536).unwrap();assert!(binding.state(&foreign,&cpu,&frame).is_err());
let context_pointer=rt.map_region(0xb000,200,CrtRegionKind::Context,None).unwrap();rt.store(rt.offset(context_pointer,0xc4).unwrap(),32,CrtValue::Pointer(frame.low)).unwrap();let selector=rt.map_region(0x415128,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes())).unwrap();let mut context=CrtCxxContext::bind(&rt,&cpu,&frame,context_pointer,stack).unwrap();
let mut cache=[0u8;12];cache[8..12].copy_from_slice(&u32::MAX.to_le_bytes());rt.map_region(0x41cd14,12,CrtRegionKind::Module,Some(&cache)).unwrap();let ptd=rt.map_region(0xd000,40,CrtRegionKind::ThreadData,None).unwrap();rt.store(rt.offset(ptd,32).unwrap(),32,CrtValue::scalar(0)).unwrap();rt.map_region(0x41c060,4,CrtRegionKind::Module,Some(&3u32.to_le_bytes())).unwrap();
let exception=rt.map_region(0xe000,80,CrtRegionKind::Context,Some(&[0;80])).unwrap();rt.store(exception,32,CrtValue::scalar(0xe06d7363)).unwrap();
let scratch=rt.map_region(0xa000,4096,CrtRegionKind::Stack,None).unwrap();
for fault in 0..14{{let hs=rt.offset(scratch,if fault==6{{24}}else{{512+fault*192}}).unwrap();rt.store(hs,32,CrtValue::ProtectedReturn(123)).unwrap();rt.store(rt.offset(hs,8).unwrap(),32,if fault==1{{CrtValue::scalar(frame.bp.address()-12)}}else{{CrtValue::Pointer(rt.offset(frame.bp,if fault==2{{-8}}else{{-12}}).unwrap())}}).unwrap();for (i,value) in [(1,0xe06d7363),(3,0x1234),(4,0x5678)]{{rt.store(rt.offset(hs,i*4).unwrap(),32,CrtValue::scalar(value)).unwrap();}}rt.store(rt.offset(hs,4).unwrap(),32,CrtValue::Pointer(exception)).unwrap();rt.store(exception,32,CrtValue::scalar(if fault==9{{0xe0420042}}else{{0xe06d7363}})).unwrap();rt.store(rt.offset(exception,4).unwrap(),32,CrtValue::scalar(if fault==10{{2}}else{{0}})).unwrap();rt.store(rt.offset(hs,12).unwrap(),32,CrtValue::Pointer(if fault==7{{rt.offset(context_pointer,4).unwrap()}}else{{context_pointer}})).unwrap();let mut child=CrtCpu::new(hs,123).unwrap();if fault==5{{child.r[4]=CrtValue::Pointer(frame.low);}}let guard=rt.load(frame.low,32).unwrap();if fault==3{{rt.store(frame.low,32,CrtValue::scalar(0)).unwrap();}}if fault==4{{rt.store(frame.low,32,CrtValue::Scalar{{bits:0,known:0}}).unwrap();}}
rt.store(rt.offset(ptd,32).unwrap(),32,CrtValue::scalar(0)).unwrap();if fault==8{{rt.store(rt.offset(ptd,32).unwrap(),32,CrtValue::Scalar{{bits:0,known:0}}).unwrap();}}let result=cxx_handler_prefix(&mut rt,&mut child,&cpu,&frame,&binding,&context,&mut |rt,child|{{let sp=CrtCpu::pointer(child.r[4])?;assert_eq!(rt.load(rt.offset(sp,4)?,32)?,CrtValue::scalar(3));let dispatcher_bp=CrtCpu::pointer(rt.load(CrtCpu::pointer(child.r[5])?,32)?)?;for(i,value)in [CrtValue::Pointer(exception),CrtValue::Pointer(rt.offset(frame.bp,-12)?),CrtValue::Pointer(context_pointer),CrtValue::scalar(0x5678),CrtValue::scalar(0x41b42c),CrtValue::scalar(0),CrtValue::scalar(0),CrtValue::scalar(0)].into_iter().enumerate(){{assert_eq!(rt.load(rt.offset(dispatcher_bp,8+i as i64*4)?,32)?,value);}}if fault==11{{rt.store(rt.offset(context_pointer,196)?,32,CrtValue::scalar(0))?;}}if fault==12{{rt.store(rt.offset(context_pointer,196)?,32,CrtValue::Pointer(scratch))?;}}if fault==13{{rt.retire_region(context_pointer)?;}}child.clobber(CrtValue::Pointer(ptd));rt.last_os_error=None;child.finish_pop(rt,4)}});if fault==0||fault==9{{assert_eq!(result.unwrap(),CrtValue::scalar(1));assert!(child.returned);assert_eq!(child.r[4],CrtValue::Pointer(rt.offset(hs,4).unwrap()));assert_eq!(cpu.r[5],CrtValue::Pointer(frame.bp));}}else{{assert!(result.is_err());assert!(!child.returned);}}if fault==6{{assert_eq!(rt.load(rt.offset(hs,-8).unwrap(),32).unwrap(),CrtValue::scalar(0x41b42c));assert!(frame.live(&rt,&cpu).is_ok());}}if fault==11||fault==12{{assert_eq!(rt.load(rt.offset(context_pointer,196).unwrap(),32).unwrap(),if fault==11{{CrtValue::scalar(0)}}else{{CrtValue::Pointer(scratch)}});rt.store(rt.offset(context_pointer,196).unwrap(),32,CrtValue::Pointer(frame.low)).unwrap();}}rt.store(frame.low,32,guard).unwrap();if !child.returned{{rt.consume_stack(hs,CrtValue::ProtectedReturn(123)).unwrap();}}}}
let context_pointer=rt.map_region(0xb000,200,CrtRegionKind::Context,None).unwrap();rt.store(rt.offset(context_pointer,196).unwrap(),32,CrtValue::Pointer(frame.low)).unwrap();let mut context=CrtCxxContext::bind(&rt,&cpu,&frame,context_pointer,stack).unwrap();
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
    for (which, bytes) in [COMMON, DISPATCH_THUNK, DISPATCH_ENTRY, DISPATCH_TAIL]
        .iter()
        .enumerate()
    {
        for i in 0..bytes.len() / 2 {
            let mut inputs = [
                crate::crt_ptd::raw(COMMON),
                crate::crt_ptd::raw(DISPATCH_THUNK),
                crate::crt_ptd::raw(DISPATCH_ENTRY),
                crate::crt_ptd::raw(DISPATCH_TAIL),
            ];
            inputs[which][i] ^= 1;
            assert!(common_source(&inputs[0], &inputs[1], &inputs[2], &inputs[3]).is_err());
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

#[test]
fn common_handler_executes_cached_getter_with_owned_context_and_no_loader_authority() {
    common_handler_fixture(false);
}
#[test]
fn common_handler_acquires_heap_ptd_through_original_lazy_producer() {
    common_handler_fixture(true);
}
fn common_handler_fixture(lazy: bool) {
    let security = crate::crt_stream_callees::prove_security(
        &crate::crt_ptd::raw("3b0d00c041007501c3e97c020000"),
        0x40154c,
    )
    .unwrap();
    let extra = format!(
        "{} {} {} {} {} {}",
        crate::crt_ptd::helper_source(
            &crate::crt_ptd::raw(crate::crt_ptd::PROLOG),
            0x414268,
            &crate::crt_ptd::raw(crate::crt_ptd::EPILOG),
            0x414254,
            0x41c000
        )
        .unwrap(),
        emit(
            &crate::crt_ptd::raw(METADATA),
            0x41b42c,
            &crate::crt_ptd::raw(UNWIND_MAP),
            0x41b41c
        )
        .unwrap(),
        handler_prefix_bound(
            &crate::crt_ptd::raw(HANDLER),
            0x414ad6,
            0x41b42c,
            0x403002,
            &security,
            !lazy
        )
        .unwrap(),
        common_source_provider(
            &crate::crt_ptd::raw(COMMON),
            &crate::crt_ptd::raw(DISPATCH_THUNK),
            &crate::crt_ptd::raw(DISPATCH_ENTRY),
            &crate::crt_ptd::raw(DISPATCH_TAIL),
            !lazy,
            false,
            lazy
        )
        .unwrap(),
        context_source(&crate::crt_ptd::raw(CONTEXT_CHECK)).unwrap(),
        if lazy {
            crate::crt_cxx_ptd::lazy_source(
                &crate::crt_ptd::raw(crate::crt_cxx_ptd::GETTER),
                &crate::crt_ptd::raw(crate::crt_cxx_ptd::REQUIRED),
                &crate::crt_ptd::raw(crate::crt_cxx_lookup::SETTER),
            )
        } else {
            crate::crt_cxx_ptd::dynamic_source(
                &crate::crt_ptd::raw(crate::crt_cxx_ptd::GETTER),
                &crate::crt_ptd::raw(crate::crt_cxx_ptd::REQUIRED),
            )
        }
        .unwrap()
    );
    if let Some(out) = std::env::var_os("W2L_EH4_EVIDENCE") {
        std::fs::write(
            std::path::Path::new(&out).join(if lazy {
                "lazy-common-handler.rs"
            } else {
                "cached-common-handler.rs"
            }),
            format!(
                "{}\n{}\n{}",
                crate::crt_stream_runtime::EMITTED_TYPES,
                crate::crt_stream_cpu::EMITTED_TYPES,
                extra
            ),
        )
        .unwrap();
    }
    let meta = crate::crt_ptd::raw(METADATA);
    let map = crate::crt_ptd::raw(UNWIND_MAP);
    let invoke = if lazy {
        r#"cxx_handler_prefix(&mut rt,&mut child,&owner,&frame,&record,&context,&mut |rt,c|{if mode==22{return Ok(CrtValue::Pointer(ptd));}let value=cxx_ptd_required(rt,c,CrtResolverAccess::Cached,if mode==7{foreign}else{fiber},slot,&mut|_,_,_|Err("lazy handler cannot load"),&mut|rt,_,value|{
       if let CrtValue::Pointer(p)=value{if mode==12{rt.free_allocation(p)?;}else if mode==2{rt.store(rt.offset(p,32)?,32,CrtValue::Scalar{bits:0,known:0})?;}else if mode==18{rt.store(rt.offset(p,32)?,32,CrtValue::scalar(1))?;}}
       Ok((u32::from(mode!=19||!matches!(value,CrtValue::Pointer(_))),None))
      },&mut|rt,c,target|{let sp=CrtCpu::pointer(c.r[4])?;let v=if target==0x407cf0{assert_eq!(rt.load(rt.offset(sp,4)?,32)?,CrtValue::scalar(1));assert_eq!(rt.load(rt.offset(sp,8)?,32)?,CrtValue::scalar(40));CrtValue::Pointer(rt.allocate(40,true,true)?.ok_or("allocation unavailable")?)}else{assert_eq!(target,0x407d50);let value=rt.load(rt.offset(sp,4)?,32)?;if let CrtValue::Pointer(p)=value{rt.free_allocation(p)?;}else{assert_eq!(value,CrtValue::scalar(0));}CrtValue::Scalar{bits:0,known:0}};c.clobber(v);c.finish(rt)})?;if mode==20{return Ok(CrtValue::scalar(0));}if mode==21{c.r[0]=CrtValue::scalar(0);}if mode==23{rt.free_allocation(CrtCpu::pointer(value)?)?;}Ok(value)})"#
    } else {
        "cxx_handler_prefix(&mut rt,&mut child,&owner,&frame,&record,&context,if mode==7{foreign}else{fiber},slot)"
    };
    let lazy_setup = if lazy {
        r#"let setter=rt.module_export_result(init,m,"FlsSetValue",0x722000).unwrap();rt.store(rt.offset(cache_root,12).unwrap(),32,CrtValue::Function(setter)).unwrap();rt.map_region(0x415d60,8,CrtRegionKind::Input,Some(&[0,0,0,0,2,0,0,0])).unwrap();rt.map_region(0x415d68,12,CrtRegionKind::Input,Some(b"FlsSetValue\0")).unwrap();"#
    } else {
        ""
    };
    let replay = if lazy {
        "cxx_handler_prefix(&mut rt,&mut child,&owner,&frame,&record,&context,&mut|_,_|panic!(\"replayed producer\"))"
    } else {
        "cxx_handler_prefix(&mut rt,&mut child,&owner,&frame,&record,&context,fiber,slot)"
    };
    let cache_size = if lazy { 16 } else { 12 };
    let null_slot = lazy;
    let count = if lazy { 24 } else { 20 };
    let body = format!(
        r#"
for mode in 0..{count}{{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let(m,reference)=rt.module_acquire_result(init,"independent handler dependency",0x720000).unwrap();let function=rt.module_export_result(init,m,"FlsGetValue",0x721000).unwrap();
 let cache_root=rt.map_region(0x41cd14,{cache_size},CrtRegionKind::Module,None).unwrap();let cache=rt.offset(cache_root,8).unwrap();rt.store(cache,32,if mode==14{{CrtValue::scalar(0)}}else{{CrtValue::Function(function)}}).unwrap();
 rt.map_region(0x415128,4,CrtRegionKind::Module,Some(&(if mode==13{{0x401bfau32}}else{{0x401bf9u32}}).to_le_bytes())).unwrap();
 rt.map_region(0x415d4c,8,CrtRegionKind::Input,Some(&[0,0,0,0,2,0,0,0])).unwrap();rt.map_region(0x415d54,12,CrtRegionKind::Input,Some(b"FlsGetValue\0")).unwrap();rt.map_region(0x41c060,4,CrtRegionKind::Module,Some(&3u32.to_le_bytes())).unwrap();
 {lazy_setup}
 let ptd=rt.map_region(0xd000,40,CrtRegionKind::ThreadData,None).unwrap();if mode!=2{{rt.store(rt.offset(ptd,32).unwrap(),32,CrtValue::scalar(if mode==18{{1}}else{{0}})).unwrap();}}
 let fiber=rt.bind_fiber(9).unwrap();let slot=rt.bind_fls(fiber,3,if {null_slot}||mode==19{{CrtValue::scalar(0)}}else{{CrtValue::Pointer(ptd)}}).unwrap();
 if mode==8||mode==9{{rt.retire_fls(fiber,slot).unwrap();if mode==9{{rt.bind_fls(fiber,3,CrtValue::Pointer(ptd)).unwrap();}}}}if mode==10||mode==11{{rt.module_release_result(init,reference,true).unwrap();if mode==11{{rt.module_acquire_result(init,"independent handler dependency",0x720000).unwrap();}}}}if mode==12{{rt.retire_region(ptd).unwrap();}}rt.end_initialization(init).unwrap();
 rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&123u32.to_le_bytes())).unwrap();rt.map_region(0x41b42c,36,CrtRegionKind::Module,Some(&{meta:?})).unwrap();rt.map_region(0x41b41c,16,CrtRegionKind::Module,Some(&{map:?})).unwrap();
 let stack=rt.map_region(0x9000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,768).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut owner=CrtCpu::new(sp,1).unwrap();owner.push(&mut rt,CrtValue::scalar(0)).unwrap();owner.r[0]=CrtValue::scalar(0x414ad6);let previous=rt.thread_head(4,5,[1,2,3]).unwrap();let mut frame=CrtPtdFrame::new(&rt,&owner,previous,0x414ad6,0x41c000).unwrap();ptd_prolog(&mut rt,&mut owner,&mut frame,0x40a33e).unwrap();let record=cxx_bind(&rt,&owner,&frame).unwrap();
 let context_pointer=rt.map_region(0xb000,200,CrtRegionKind::Context,None).unwrap();rt.store(rt.offset(context_pointer,196).unwrap(),32,CrtValue::Pointer(frame.low)).unwrap();let mut context=CrtCxxContext::bind(&rt,&owner,&frame,context_pointer,stack).unwrap();
 let exception=rt.map_region(0xe000,80,CrtRegionKind::Context,Some(&[0;80])).unwrap();rt.store(exception,32,CrtValue::scalar(if mode==1{{0xe0420042}}else{{0xe06d7363}})).unwrap();rt.store(rt.offset(exception,4).unwrap(),32,CrtValue::scalar(if mode==15{{2}}else{{0}})).unwrap();
 let scratch=rt.map_region(0xa000,4096,CrtRegionKind::Stack,None).unwrap();let hs=rt.offset(scratch,3072).unwrap();rt.store(hs,32,CrtValue::ProtectedReturn(123)).unwrap();rt.store(rt.offset(hs,4).unwrap(),32,CrtValue::Pointer(exception)).unwrap();rt.store(rt.offset(hs,8).unwrap(),32,CrtValue::Pointer(rt.offset(frame.bp,-12).unwrap())).unwrap();rt.store(rt.offset(hs,12).unwrap(),32,CrtValue::Pointer(if mode==17{{rt.offset(context_pointer,4).unwrap()}}else{{context_pointer}})).unwrap();rt.store(rt.offset(hs,16).unwrap(),32,CrtValue::scalar(0x5678)).unwrap();let mut child=CrtCpu::new(hs,123).unwrap();
 match mode{{3=>{{rt.store(rt.offset(context_pointer,196).unwrap(),32,CrtValue::scalar(frame.low.address())).unwrap();}},4=>{{rt.store(rt.offset(context_pointer,196).unwrap(),32,CrtValue::Pointer(scratch)).unwrap();}},5=>context.retire(),6=>rt.retire_region(context_pointer).unwrap(),16=>owner.return_id+=1,_=>{{}}}}
 let(mut other,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let foreign=other.bind_fiber(9).unwrap();rt.last_os_error=Some(77);let cache_bytes=rt.memory.read(cache.address(),4).unwrap().to_vec();let refs=rt.module_references.len();
 let result={invoke};let result_error=result.as_ref().err().copied();
 if mode==0||mode==1||mode==18{{assert_eq!(result.unwrap(),CrtValue::scalar(1));assert!(child.returned);assert_eq!(child.r[4],CrtValue::Pointer(rt.offset(hs,4).unwrap()));assert_eq!(owner.r[5],CrtValue::Pointer(frame.bp));assert!({replay}.is_err());}}else{{assert!(result.is_err(),"mode {{mode}}");assert!(!child.returned);}}
 if {null_slot}&&matches!(mode,0|1|18){{let CrtValue::Pointer(actual)=rt.fls.get(&3).unwrap().1 else{{panic!("PTD not actually published")}};assert_eq!(actual.kind,CrtRegionKind::Buffer);assert_ne!(actual.cap,ptd.cap);rt.dispatcher_ptd(actual).unwrap();assert_eq!(rt.load(rt.offset(actual,32).unwrap(),32).unwrap(),CrtValue::scalar(if mode==18{{1}}else{{0}}));}}
 if {null_slot}{{match mode{{2=>assert_eq!(result_error,Some("CRT unknown scalar bits observed")),12|23=>assert_eq!(result_error,Some("CRT stale/foreign pointer")),19=>assert_eq!(result_error,Some("C++ required PTD termination effect unbound")),20..=22=>assert_eq!(result_error,Some("C++ PTD provider return authority")),_=>{{}}}}}}
 assert_eq!(rt.initialization,None);assert_eq!(rt.module_references.len(),refs);assert_eq!(rt.memory.read(cache.address(),4).unwrap(),cache_bytes);assert_eq!(rt.last_os_error,if mode==19&&!{null_slot}||mode==12&&{null_slot}{{None}}else{{Some(77)}},"mode {{mode}}");
}}
"#
    );
    crate::crt_stream_callees_tests::native(
        &extra,
        &body,
        if lazy {
            "lazy-common-handler"
        } else {
            "cached-common-handler"
        },
    );
    for (which, bytes) in [COMMON, DISPATCH_THUNK, DISPATCH_ENTRY, DISPATCH_TAIL]
        .into_iter()
        .enumerate()
    {
        for i in 0..bytes.len() / 2 {
            let mut inputs = [
                crate::crt_ptd::raw(COMMON),
                crate::crt_ptd::raw(DISPATCH_THUNK),
                crate::crt_ptd::raw(DISPATCH_ENTRY),
                crate::crt_ptd::raw(DISPATCH_TAIL),
            ];
            inputs[which][i] ^= 1;
            assert!(
                common_source_bound(&inputs[0], &inputs[1], &inputs[2], &inputs[3], true).is_err()
            );
            assert!(
                common_source_mode(&inputs[0], &inputs[1], &inputs[2], &inputs[3], true, true)
                    .is_err()
            );
        }
    }
    let handler = crate::crt_ptd::raw(HANDLER);
    for i in 0..handler.len() {
        let mut changed = handler.clone();
        changed[i] ^= 1;
        assert!(
            handler_prefix_bound(&changed, 0x414ad6, 0x41b42c, 0x403002, &security, true).is_err()
        );
        assert!(
            handler_prefix_mode(&changed, 0x414ad6, 0x41b42c, 0x403002, &security, true, true)
                .is_err()
        );
    }
}

pub(crate) const UNWIND_STATE_GET: &str =
    "558bec8b45108b4d08817804800000007f060fbe41085dc38b41085dc3";
pub(crate) const UNWIND_STATE_SET: &str = "558bec8b45088b4d108948085dc3";
pub(crate) fn unwind_state_source(get: &[u8], set: &[u8]) -> Result<String, String> {
    if get != crate::crt_ptd::raw(UNWIND_STATE_GET) || set != crate::crt_ptd::raw(UNWIND_STATE_SET)
    {
        return Err("C++ original unwind state helpers".into());
    }
    let mut result = String::new();
    for (bytes, origin, name) in [
        (get, 0x4043e9, "cxx_unwind_state_read_raw"),
        (set, 0x404406, "cxx_unwind_state_write_raw"),
    ] {
        let graph = crate::crt_stream_ir::Graph::decode(bytes, origin)?;
        let body = crate::crt_stream_emit::emit_body(
            &graph,
            |_, _| Err("unwind state helper call".into()),
            &Default::default(),
            64,
        )?;
        result.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}"));
    }
    result.push_str(r#"
fn cxx_unwind_state_read_owned(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord)->Result<CrtValue,&'static str>{
 let expected=record.state(rt,owner,frame)?;cpu.validate_active(rt)?;let sp=CrtCpu::pointer(cpu.r[4])?;
 if rt.load(rt.offset(sp,4)?,32)?!=CrtValue::Pointer(rt.offset(frame.bp,-12)?)||rt.load(rt.offset(sp,12)?,32)?!=CrtValue::Pointer(record.metadata){return Err("C++ unwind read object/metadata authority");}
 let result=cxx_unwind_state_read_raw(rt,cpu)?;if result.known_scalar()?!=expected as u32{return Err("C++ unwind read state disagreement");}Ok(result)
}
// The original loop writes the next state before invoking its action. This
// adapter certifies only that write; no cleanup completion receipt is created.
fn cxx_unwind_state_step(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord)->Result<CrtValue,&'static str>{
 let state=record.state(rt,owner,frame)?;cpu.validate_active(rt)?;
 let sp=CrtCpu::pointer(cpu.r[4])?;let object=rt.offset(frame.bp,-12)?;
 if rt.load(rt.offset(sp,4)?,32)?!=CrtValue::Pointer(object)||rt.load(rt.offset(sp,8)?,32)?!=CrtValue::Pointer(record.metadata){return Err("C++ unwind state object/metadata authority");}
 let Some((next,_))=record.required_action(rt,owner,frame)? else{return Err("C++ no pending unwind state transition");};
 if state<0||rt.load(rt.offset(sp,12)?,32)?.known_scalar()?!=next as u32{return Err("C++ unwind map next state");}
 cxx_unwind_state_write_raw(rt,cpu)
}
"#);
    Ok(result)
}

#[test]
fn unwind_state_helpers_read_and_write_the_same_owned_record_without_cleanup_receipt() {
    let mut extra = unwind_state_source(
        &crate::crt_ptd::raw(UNWIND_STATE_GET),
        &crate::crt_ptd::raw(UNWIND_STATE_SET),
    )
    .unwrap();
    extra.push_str(
        &crate::crt_ptd::helper_source(
            &crate::crt_ptd::raw(crate::crt_ptd::PROLOG),
            0x414268,
            &crate::crt_ptd::raw(crate::crt_ptd::EPILOG),
            0x414254,
            0x41c000,
        )
        .unwrap(),
    );
    extra.push_str(
        &emit(
            &crate::crt_ptd::raw(METADATA),
            0x41b42c,
            &crate::crt_ptd::raw(UNWIND_MAP),
            0x41b41c,
        )
        .unwrap(),
    );
    if let Some(out) = std::env::var_os("W2L_EH4_EVIDENCE") {
        std::fs::write(
            std::path::Path::new(&out).join("unwind-state-live.rs"),
            format!(
                "{}\n{}\n{}",
                crate::crt_stream_runtime::EMITTED_TYPES,
                crate::crt_stream_cpu::EMITTED_TYPES,
                extra
            ),
        )
        .unwrap();
    }
    let meta = crate::crt_ptd::raw(METADATA);
    let map = crate::crt_ptd::raw(UNWIND_MAP);
    let body = format!(
        r#"
for mode in 0..8{{
 let mut rt=CrtStreamRuntime::new(7,9,0x8000,65536).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&123u32.to_le_bytes())).unwrap();let metadata=rt.map_region(0x41b42c,36,CrtRegionKind::Module,Some(&{meta:?})).unwrap();rt.map_region(0x41b41c,16,CrtRegionKind::Module,Some(&{map:?})).unwrap();
 let stack=rt.map_region(0x9000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,768).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut owner=CrtCpu::new(sp,1).unwrap();owner.push(&mut rt,CrtValue::scalar(0)).unwrap();owner.r[0]=CrtValue::scalar(0x414ad6);let previous=rt.thread_head(4,5,[1,2,3]).unwrap();let mut frame=CrtPtdFrame::new(&rt,&owner,previous,0x414ad6,0x41c000).unwrap();ptd_prolog(&mut rt,&mut owner,&mut frame,0x40a33e).unwrap();let record=cxx_bind(&rt,&owner,&frame).unwrap();let state=rt.offset(frame.bp,-4).unwrap();rt.store(state,32,CrtValue::scalar(if mode==1{{1}}else{{0}})).unwrap();
 let scratch=rt.map_region(0xa000,1024,CrtRegionKind::Stack,None).unwrap();let hs=rt.offset(scratch,768).unwrap();rt.store(hs,32,CrtValue::ProtectedReturn(10)).unwrap();let mut child=CrtCpu::new(hs,10).unwrap();let record_pointer=rt.offset(frame.bp,-12).unwrap();child.push(&mut rt,CrtValue::Pointer(metadata)).unwrap();child.push(&mut rt,CrtValue::scalar(0)).unwrap();child.push(&mut rt,CrtValue::Pointer(record_pointer)).unwrap();let read=child.call_activation(&mut rt,0x3333,0,|rt,c|cxx_unwind_state_read_owned(rt,c,&owner,&frame,&record)).unwrap();assert_eq!(read,CrtValue::scalar(if mode==1{{1}}else{{0}}));child.discard(&mut rt,12).unwrap();child.push(&mut rt,CrtValue::scalar(if mode==2{{0}}else{{u32::MAX}})).unwrap();let meta_arg=if mode==3{{rt.offset(metadata,4).unwrap()}}else{{metadata}};child.push(&mut rt,CrtValue::Pointer(meta_arg)).unwrap();let object=rt.offset(frame.bp,if mode==4{{-8}}else{{-12}}).unwrap();child.push(&mut rt,CrtValue::Pointer(object)).unwrap();
 if mode==5{{owner.return_id+=1;}}if mode==6{{rt.store(state,32,CrtValue::Scalar{{bits:0,known:0}}).unwrap();}}if mode==7{{rt.store(metadata,32,CrtValue::scalar(0)).unwrap();}}let before=rt.load(state,32).unwrap();
 let result=child.call_activation(&mut rt,0x4444,0,|rt,c|cxx_unwind_state_step(rt,c,&owner,&frame,&record));
 if mode<=1{{assert_eq!(result.unwrap(),CrtValue::Pointer(rt.offset(frame.bp,-12).unwrap()));assert_eq!(rt.load(state,32).unwrap(),CrtValue::scalar(u32::MAX));assert_eq!(record.required_action(&rt,&owner,&frame).unwrap(),None);child.discard(&mut rt,12).unwrap();child.finish(&mut rt).unwrap();}}else{{assert!(result.is_err());assert_eq!(rt.load(state,32).unwrap(),before);}}
}}
// Independent read-width boundary: <=128 reads a signed byte, >128 a full word.
for(count,value,expected)in [(128u32,255u32,u32::MAX),(129,255,255),(2,128,0xffffff80),(129,0x80000000,0x80000000)]{{
 let mut rt=CrtStreamRuntime::new(23,45,0x8000,16384).unwrap();let object=rt.map_region(0x6000,12,CrtRegionKind::Context,None).unwrap();rt.store(rt.offset(object,8).unwrap(),32,CrtValue::scalar(value)).unwrap();let info=rt.map_region(0x7000,8,CrtRegionKind::Module,None).unwrap();rt.store(rt.offset(info,4).unwrap(),32,CrtValue::scalar(count)).unwrap();let stack=rt.map_region(0x9000,256,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,192).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(5)).unwrap();let mut c=CrtCpu::new(sp,5).unwrap();c.push(&mut rt,CrtValue::Pointer(info)).unwrap();c.push(&mut rt,CrtValue::scalar(0)).unwrap();c.push(&mut rt,CrtValue::Pointer(object)).unwrap();let result=c.call_activation(&mut rt,0x5555,0,|rt,c|cxx_unwind_state_read_raw(rt,c)).unwrap();assert_eq!(result,CrtValue::scalar(expected));c.discard(&mut rt,12).unwrap();c.finish(&mut rt).unwrap();
}}
"#
    );
    crate::crt_stream_callees_tests::native(&extra, &body, "owned-unwind-state");
    for (which, bytes) in [UNWIND_STATE_GET, UNWIND_STATE_SET].into_iter().enumerate() {
        for i in 0..bytes.len() / 2 {
            let mut inputs = [
                crate::crt_ptd::raw(UNWIND_STATE_GET),
                crate::crt_ptd::raw(UNWIND_STATE_SET),
            ];
            inputs[which][i] ^= 1;
            assert!(unwind_state_source(&inputs[0], &inputs[1]).is_err());
        }
    }
}
/// Supplied unwind-delivery input, bound to one suspended event. This does not
/// acquire a Windows CONTEXT or produce RtlUnwind's delivery flags.
pub(crate) fn invocation_source() -> &'static str {
    INVOCATION
}
const INVOCATION: &str = r#"
impl CrtCxxContext{ /// Preserve the checked event's exact scalar knowledge.
 /// A partial value grants predicate observations only, never a stack pointer.
 /// This performs no guest CONTEXT store or capture acquisition.
 fn bind_normal(rt:&CrtStreamRuntime,owner:&CrtCpu,frame:&CrtPtdFrame,objects:&CrtNormalObjects,stack:CrtPointer)->Result<Self,&'static str>{
  let esp=match objects.captured_esp{CrtValue::Scalar{bits,known:u32::MAX}=>Some(rt.offset(stack,i64::from(bits)-i64::from(stack.address()))?),CrtValue::Scalar{..}=>None,_=>return Err("normal captured ESP requires scalar knowledge")};
  let token=Self{anchor:rt.anchor,thread:rt.thread,outer:owner.return_id,bp:frame.bp,context:objects.context,stack,esp,esp_value:objects.captured_esp,unobserved:objects.unobserved.clone(),live:true};
  token.check(rt,owner,frame)?;Ok(token)
 }
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum CxxInvocationPhase{Pending,Active,Consumed,ResultTaken,Failed}
struct CxxInvocationReturn{handler:CrtNormalHandlerReturn,lease:u64,executed:[u32;3],owner:u64,bp:CrtPointer}
struct CrtCxxInvocation{
 anchor:guest_memory::Capability,identity:RegistryIdentity,epoch:u64,event:u64,parent:NormalFrameId,
 owner:u64,bp:CrtPointer,metadata:CrtPointer,exception:CrtPointer,context:CrtPointer,esp:CrtPointer,
 flags:u32,phase:CxxInvocationPhase,lease:Option<u64>,target:[u32;3],
}
impl CrtCxxInvocation{
 fn bind_unwind(event:&CrtNormalException,rt:&CrtStreamRuntime,epoch:&NormalCallEpoch<'_>,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord,context:&CrtCxxContext,exception:CrtPointer)->RegistryResult<Self>{
  event.validate_pending(rt,epoch)?;
  if event.delivery!=CrtNormalDelivery::Pending||epoch.delivery.is_some(){return Err("C++ invocation nested/active delivery unbound");}
  let value=Self{anchor:rt.anchor,identity:event.identity,epoch:event.epoch,event:event.generation,parent:event.frame,
   owner:owner.return_id,bp:frame.bp,metadata:record.metadata,exception,context:context.context,esp:context.numeric_esp()?,
   flags:2|u32::from(event.noncontinuable),phase:CxxInvocationPhase::Pending,lease:None,target:cxx_handler_identity()};
  value.objects(event.code,rt,owner,frame,record,context)?;Ok(value)
 }
 fn objects(&self,code:u32,rt:&CrtStreamRuntime,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord,context:&CrtCxxContext)->RegistryResult<()>{
  context.check(rt,owner,frame)?;record.state(rt,owner,frame)?;
  if self.target!=cxx_handler_identity()||frame.handler!=self.target[0]||record.metadata.address()!=self.target[1]{return Err("C++ invocation executed handler identity");}
  if rt.anchor!=self.anchor||rt.owner!=self.identity.owner||rt.thread!=self.identity.instance||owner.return_id!=self.owner
   ||frame.bp!=self.bp||record.metadata!=self.metadata||context.context!=self.context||context.esp!=Some(self.esp)
   ||self.exception.kind!=CrtRegionKind::Context||self.exception.address()%4!=0
   ||u64::from(self.exception.address())<u64::from(self.context.address())+716&&u64::from(self.context.address())<u64::from(self.exception.address())+80{
   return Err("C++ invocation foreign owner/context or alias");
  }
  rt.valid(self.exception,80)?;rt.valid(self.context,716)?;
  for(offset,value)in [(0,code),(4,self.flags),(8,0),(16,0)]{
   if rt.load(rt.offset(self.exception,offset)?,32)?.known_scalar()?!=value{return Err("C++ invocation event record mismatch");}
  }Ok(())
 }
 fn pending(&self,event:&CrtNormalException,rt:&CrtStreamRuntime,epoch:&NormalCallEpoch<'_>,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord,context:&CrtCxxContext)->RegistryResult<()>{
  event.validate_pending(rt,epoch)?;
  if self.phase!=CxxInvocationPhase::Pending||event.delivery!=CrtNormalDelivery::Pending
   ||event.identity!=self.identity||event.epoch!=self.epoch||event.generation!=self.event||event.frame!=self.parent
   ||self.flags!=2|u32::from(event.noncontinuable){return Err("C++ invocation stale event/phase");}
  self.objects(event.code,rt,owner,frame,record,context)
 }
}
struct CrtSelectedCxxReturn{receipt:CrtNormalHandlerReturn,serial:u64,registration:RegistrationId,handler:[u32;3],owner:u64,context:CrtCxxContext}
/// Execute exactly the selected live C++ registration. A rejected search backend
/// yields no result/advance/restoration receipt. Earlier original effects remain.
fn cxx_invoke_selected_search(search:&mut CrtOrderedSearch,event:&mut CrtNormalException,objects:&CrtNormalObjects,rt:&mut CrtStreamRuntime,interrupted:&CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&CrtNormalBinding,dispatcher:&mut CrtCpu,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord,stack:CrtPointer,fiber:CrtFiber,slot:CrtFlsSlot,continuation:u32)->RegistryResult<CrtSelectedCxxReturn>{
 let ready=(||{
  if search.phase!=2{return Err("selected C++ repeated execution");}
  search.validate_stage(event,objects,rt,interrupted,epoch,binding,true)?;
  let RegistryHead::Cxx(id)=search.current else{return Err("selected search requires C++ registration");};
  let f=epoch.registry.cxx.iter().find(|f|f.id==id&&f.linked).ok_or("selected C++ registration expired")?;
  frame.live(rt,owner)?;record.state(rt,owner,frame)?;
  if f.epoch!=event.epoch||f.owner!=owner.return_id||f.record!=rt.offset(frame.bp,-12)?.address()||f.handler!=cxx_handler_identity()[0]
   ||frame.handler!=f.handler||f.high!=u64::from(CrtCpu::pointer(owner.entry[4])?.address())+4||f.low!=rt.offset(frame.low,-4)?.address(){return Err("selected C++ owner/record/handler mismatch");}
  if event.noncontinuable{return Err("selected C++ noncontinuable search contract unbound");}
  objects.validate(event,rt,epoch)?;
  let context=CrtCxxContext::bind_normal(rt,owner,frame,objects,stack)?;
  let sp=CrtCpu::pointer(dispatcher.r[4])?;
  for(i,v)in [CrtValue::Pointer(objects.record),CrtValue::Pointer(rt.offset(frame.bp,-12)?),CrtValue::Pointer(objects.context)].into_iter().enumerate(){if rt.load(rt.offset(sp,i as i64*4)?,32)?!=v{return Err("selected C++ original arguments");}}
  Ok(context)
 })();
 let context=match ready{Ok(c)=>c,Err(e)=>{search.phase=3;if let Some(lease)=&event.unobserved{lease.revoke();}return Err(e);}};
 search.phase=4;event.delivery=CrtNormalDelivery::Pending;
 let result=event.execute_child_handler(rt,interrupted,epoch,binding,dispatcher,continuation,|rt,cpu,child|{
  cxx_handler_prefix(rt,cpu,owner,frame,record,&context,child,fiber,slot)
 });
 match result{Err(e)=>{search.phase=3;Err(e)},Ok(receipt)=>{
  search.validate_stage(event,objects,rt,interrupted,epoch,binding,true)?;context.check(rt,owner,frame)?;
  let RegistryHead::Cxx(registration)=search.current else{unreachable!()};
  Ok(CrtSelectedCxxReturn{receipt,serial:search.serial,registration,handler:cxx_handler_identity(),owner:owner.return_id,context})
 }}
}
fn cxx_take_selected_search(search:&mut CrtOrderedSearch,event:&mut CrtNormalException,objects:&CrtNormalObjects,returned:CrtSelectedCxxReturn,rt:&CrtStreamRuntime,interrupted:&CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&CrtNormalBinding,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord)->RegistryResult<u32>{
 let result=(||{
  search.validate_stage(event,objects,rt,interrupted,epoch,binding,true)?;
  if search.phase!=4||returned.serial!=search.serial||search.current!=RegistryHead::Cxx(returned.registration)||returned.handler!=cxx_handler_identity()||returned.owner!=owner.return_id{return Err("selected C++ foreign/replayed executed receipt");}
  returned.context.check(rt,owner,frame)?;record.state(rt,owner,frame)?;
  let f=epoch.registry.cxx.iter().find(|f|f.id==returned.registration&&f.linked).ok_or("selected C++ expired return registration")?;
  if f.owner!=returned.owner||f.handler!=returned.handler[0]||f.record!=rt.offset(frame.bp,-12)?.address(){return Err("selected C++ return owner mismatch");}
  let next=f.previous;
  if returned.receipt.value!=CrtValue::scalar(1){return Err("selected C++ unsupported search disposition");}
  let value=event.take_handler_result(returned.receipt,rt,interrupted,epoch,binding)?;
  search.phase=5;search.current=next;if let Some(lease)=&event.unobserved{lease.revoke();}Ok(value)
 })();if result.is_err(){search.phase=3;if let Some(lease)=&event.unobserved{lease.revoke();}}result
}

fn cxx_invoke_unwind(event:&mut CrtNormalException,invocation:&mut CrtCxxInvocation,rt:&mut CrtStreamRuntime,interrupted:&CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&CrtNormalBinding,dispatcher:&mut CrtCpu,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord,context:&CrtCxxContext,fiber:CrtFiber,slot:CrtFlsSlot,continuation:u32)->RegistryResult<CxxInvocationReturn>{
 let start=(||{
  invocation.pending(event,rt,epoch,owner,frame,record,context)?;
  let sp=CrtCpu::pointer(dispatcher.r[4])?;
  for(i,value)in [CrtValue::Pointer(invocation.exception),CrtValue::Pointer(rt.offset(frame.bp,-12)?),CrtValue::Pointer(invocation.context)].into_iter().enumerate(){
   if rt.load(rt.offset(sp,i as i64*4)?,32)?!=value{return Err("C++ invocation dispatcher argument mismatch");}
  }Ok(())
 })();
 if let Err(error)=start{invocation.phase=CxxInvocationPhase::Failed;return Err(error);}
 invocation.phase=CxxInvocationPhase::Active;let code=event.code;
 let result=event.execute_child_handler(rt,interrupted,epoch,binding,dispatcher,continuation,|rt,cpu,child|{
  let grant=child.delivery.ok_or("C++ invocation missing delivery grant")?;
  if invocation.phase!=CxxInvocationPhase::Active||grant.event!=invocation.event||grant.parent!=invocation.parent||child.generation!=invocation.epoch||child.registry.identity!=invocation.identity{return Err("C++ invocation foreign child grant");}
  if invocation.lease.is_some(){return Err("C++ invocation repeated child lease");}invocation.lease=Some(grant.lease);
  invocation.objects(code,rt,owner,frame,record,context)?;
  let value=cxx_handler_prefix(rt,cpu,owner,frame,record,context,child,fiber,slot)?;
  invocation.objects(code,rt,owner,frame,record,context)?;Ok(value)
 });
 match result{
  Ok(receipt)=>{invocation.phase=CxxInvocationPhase::Consumed;Ok(CxxInvocationReturn{handler:receipt,lease:invocation.lease.ok_or("C++ invocation missing return lease")?,executed:cxx_handler_identity(),owner:owner.return_id,bp:frame.bp})},
  Err(error)=>{invocation.phase=CxxInvocationPhase::Failed;Err(error)}
 }
}
fn cxx_take_invocation_result(event:&mut CrtNormalException,invocation:&mut CrtCxxInvocation,receipt:CxxInvocationReturn,rt:&CrtStreamRuntime,interrupted:&CrtCpu,epoch:&mut NormalCallEpoch<'_>,binding:&CrtNormalBinding,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord,context:&CrtCxxContext)->RegistryResult<u32>{
 let result=(||{
  if receipt.executed!=invocation.target||receipt.executed!=cxx_handler_identity()||receipt.owner!=invocation.owner||receipt.bp!=invocation.bp{return Err("C++ receipt executed target/owner mismatch");}
  if invocation.phase!=CxxInvocationPhase::Consumed||invocation.lease!=Some(receipt.lease)
   ||event.identity!=invocation.identity||event.epoch!=invocation.epoch||event.generation!=invocation.event||event.frame!=invocation.parent{return Err("C++ invocation foreign/stale return authority");}
  invocation.objects(event.code,rt,owner,frame,record,context)?;
  event.take_handler_result(receipt.handler,rt,interrupted,epoch,binding)
 })();
 match result{Ok(value)=>{invocation.phase=CxxInvocationPhase::ResultTaken;Ok(value)},Err(error)=>{invocation.phase=CxxInvocationPhase::Failed;event.fail_capture();epoch.fail(error)}}
}

"#;
