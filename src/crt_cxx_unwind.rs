//! Original C++ unwind body on a registered EH4 child frame.
//! PTD acquisition is an explicit checked provider; action/termination effects
//! are rejecting boundaries, never successful cleanup or resumption receipts.
use crate::crt_exception_wrapper::{EpilogProof, PrologProof, Region};
use crate::crt_stream_ir::{Graph, Target};

pub(crate) const WRAPPER: &str = "558bec6affff7510ff750cff7508e80500000083c4105dc3";
pub(crate) const BODY: &str = "6a106898b24100e898dcffffff7510ff750cff7508e81302000083c40c8bf08975e4e8e0e6ffffff4018c745fc000000003b7514746b83feff0f8ea90000008b7d103b77040f8d9d0000008b47088b0cf0894de0c745fc01000000837cf0040074305157ff7508e8de01000083c40c6803010000ff75088b4708ff74f004e841010000eb0dff75ece84be4ffff59c38b65e8c745fc000000008b75e08975e4eb90c745fcfeffffffe8270000003b7514753656ff7510ff7508e88c01000083c40c8b4df064890d00000000595f5e5bc9c38b75e4e82ee6ffff837818007e08e823e6ffffff4818c3e856350000cc";
pub(crate) const SCOPE: &str =
    "feffffff00000000d0ffffff00000000feffffff000000008d42400000000000414240004b424000";

pub(crate) fn source(
    wrapper: &[u8],
    body: &[u8],
    helper: &[u8],
    scope: &[u8],
) -> Result<String, String> {
    if wrapper != crate::crt_ptd::raw(WRAPPER)
        || body != crate::crt_ptd::raw(BODY)
        || scope != crate::crt_ptd::raw(SCOPE)
    {
        return Err("C++ unwind original code/scope binding".into());
    }
    let prolog = PrologProof::prove(
        Region {
            bytes: helper,
            origin: 0x401e60,
        },
        16,
        0x41b298,
        0x41c000,
        0x402210,
    )?;
    let epilog = EpilogProof::prove(
        Region {
            bytes: &body[0x40427d - 0x4041bc..0x40428d - 0x4041bc],
            origin: 0x40427d,
        },
        &prolog,
    )?;
    let p = prolog.emit("cxx_unwind_prolog")?;
    let e = epilog.emit("cxx_unwind_epilog")?;
    let prefix = crate::crt_stream_emit::emit_linear_fragment(
        &Graph::decode_linear_fragment(&body[..7], 0x4041bc)?,
        &Default::default(),
    )?;
    let decrement = crate::crt_stream_emit::emit_body_with_hooks(
        &Graph::decode(&body[0x404290 - 0x4041bc..0x4042a4 - 0x4041bc], 0x404290)?,
        |pc, target| {
            if target == Target::Direct(0x4028c3) {
                Ok(format!("cpu.call_activation(rt,{},0,|rt,child|cxx_unwind_ptd(rt,child,flow,provider))?;",pc+5))
            } else {
                Err("C++ decrement call".into())
            }
        },
        &Default::default(),
        64,
        |_, _| Err("C++ decrement FS".into()),
        |pc, _| {
            Ok(if pc == 0x4042a0 {
                "flow.check_counter(rt)?;".into()
            } else if pc == 0x4042a3 {
                "flow.after_decrement(rt)?;".into()
            } else {
                String::new()
            })
        },
        |_, _| Ok(None),
    )?;
    // Decode instruction boundaries before selecting the reachable normal body.
    // The two exceptional funclets are separate entry points and remain unbound.
    let mut all = std::collections::BTreeMap::new();
    let mut decoder = iced_x86::Decoder::with_ip(
        32,
        &body[12..0x40427d - 0x4041bc],
        0x4041c8,
        iced_x86::DecoderOptions::NONE,
    );
    while decoder.can_decode() {
        let i = decoder.decode();
        let at = (i.ip32() - 0x4041bc) as usize;
        all.insert(
            i.ip32(),
            Graph::decode_instruction(&body[at..at + i.len()], i.ip32())?,
        );
    }
    // Abort has no admitted return/effect contract; its original CALL always
    // rejects. Clearing the successor does not create a successful exit.
    let mut abort =
        Graph::decode_instruction(&body[0x4042a4 - 0x4041bc..0x4042a9 - 0x4041bc], 0x4042a4)?;
    abort.successors.clear();
    all.insert(0x4042a4, abort);
    let mut nodes = std::collections::BTreeMap::new();
    let mut todo = vec![0x4041c8];
    while let Some(pc) = todo.pop() {
        if pc == 0x40427d || nodes.contains_key(&pc) {
            continue;
        }
        let node = all
            .get(&pc)
            .ok_or("C++ unwind edge outside original boundaries")?
            .clone();
        todo.extend_from_slice(&node.successors);
        nodes.insert(pc, node);
    }
    let graph = Graph {
        origin: 0x4041c8,
        end: 0x40427d,
        nodes,
    };
    let body_code = crate::crt_stream_emit::emit_body_with_exit(
        &graph,
        |pc, target| {
            match(pc,target){
            (0x4041d1,Target::Direct(0x4043e9))=>Ok("cpu.call_activation(rt,0x4041d6,0,|rt,child|cxx_unwind_state_read_owned(rt,child,owner,frame,record))?;".into()),
            (0x4041de,Target::Direct(0x4028c3))=>Ok("cpu.call_activation(rt,0x4041e3,0,|rt,child|cxx_unwind_ptd(rt,child,&mut flow,provider))?;".into()),
            (0x404223,Target::Direct(0x404406))=>Ok("flow.before_step(rt,owner,frame,record)?;cpu.call_activation(rt,0x404228,0,|rt,child|cxx_unwind_state_step(rt,child,owner,frame,record))?;flow.after_step(rt,owner,frame,record)?;".into()),
            (0x40423a,Target::Direct(0x404380))=>Ok("flow.action_arguments(rt,cpu,owner,frame,record)?;cpu.call_activation(rt,0x40423f,12,|rt,child|cxx_unwind_action(rt,child,owner,frame,record,&flow))?;".into()),
            (0x404264,Target::Direct(0x404290))=>Ok("if flow.pending.is_some(){return Err(\"C++ unfinished action at counter cleanup\");}cpu.call_activation(rt,0x404269,0,|rt,child|cxx_unwind_decrement(rt,child,&mut flow,provider))?;".into()),
            (0x404275,Target::Direct(0x404406))=>Ok("flow.final_store(rt,cpu,owner,frame,record)?;cpu.call_activation(rt,0x40427a,0,|rt,child|cxx_unwind_state_write_raw(rt,child))?;".into()),
            (0x4042a4,Target::Direct(0x4077ff))=>Ok("return Err(\"C++ unwind abort effects unbound\");".into()),
            _=>Err(format!("C++ unwind call at {pc:x}")),
        }
        },
        &Default::default(),
        4096,
        |_, _| Err("C++ unwind unbound thread effect".into()),
        |pc, _| {
            let mut s=format!("binding.image(rt,cpu,epoch)?;record.state(rt,owner,frame)?;CrtCxxRecord::bytes(rt,scope,&{scope:?})?;");
            s.push_str(match pc {
                0x4041e3 => "flow.before_increment(rt)?;",
                0x4041e6 => "flow.after_increment(rt)?;",
                0x40420a => "flow.begin(rt,cpu,owner,frame,record)?;",
                0x404236 => "flow.map_pointer(rt,cpu,record)?;",
                0x40424e => "return Err(\"C++ loop advance lacks executed action receipt\");",
                _ => "",
            });
            Ok(s)
        },
        |_, _| Ok(None),
        Some(0x40427d),
    )?;
    let wrapper_code = crate::crt_stream_emit::emit_body(
        &Graph::decode(wrapper, 0x4041a4)?,
        |pc, target| {
            if pc != 0x4041b2 || target != Target::Direct(0x4041bc) {
                return Err("C++ unwind wrapper call".into());
            }
            Ok("cpu.call_activation(rt,0x4041b7,0,|rt,child|cxx_unwind_body(rt,child,epoch,owner,frame,record,provider))?;".into())
        },
        &Default::default(),
        64,
    )?;
    Ok(format!(
        r#"
{p}
{e}
{TYPES}
fn cxx_unwind_decrement(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,flow:&mut CxxUnwindFlow,provider:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->RegistryResult<CrtValue>)->RegistryResult<CrtValue>{{{decrement}}}
fn cxx_unwind_body(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord,provider:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->RegistryResult<CrtValue>)->RegistryResult<CrtValue>{{
 let result=(||{{
  record.state(rt,owner,frame)?;cpu.validate_active(rt)?;
  let scope=rt.resolve_absolute(0x41b298,CrtRegionKind::Module)?;CrtCxxRecord::bytes(rt,scope,&{scope:?})?;
  let entry=CrtCpu::pointer(cpu.r[4])?;
  if rt.load(rt.offset(entry,4)?,32)?!=CrtValue::Pointer(rt.offset(frame.bp,-12)?)||rt.load(rt.offset(entry,12)?,32)?!=CrtValue::Pointer(record.metadata)||rt.load(rt.offset(entry,16)?,32)?.known_scalar()?!=u32::MAX{{return Err("C++ unwind input record/metadata/target");}}
  let mut binding=CrtNormalBinding::bind(rt,cpu,epoch,cxx_unwind_epilog_layout())?;
  let _=(||->RegistryResult<CrtValue>{{{prefix}}})()?;
  let generation=rt.generation.checked_add(1).filter(|n|*n<1u64<<63).ok_or("C++ EH4 helper generation")?;let helper=generation|(1u64<<63);rt.generation=generation;
  cpu.push(rt,CrtValue::ProtectedReturn(helper))?;
  cxx_unwind_prolog(rt,cpu,helper,binding.token,|rt,cpu,p,t|binding.install(rt,cpu,epoch,p,t))?;
  let mut flow=CxxUnwindFlow::new(rt,cpu);
  let _=(||->RegistryResult<CrtValue>{{{body_code}}})()?;
  flow.finish(rt,cpu,owner,frame,record)?;cxx_unwind_epilog(rt,cpu,epoch,&mut binding)
 }})();match result{{Ok(v)=>Ok(v),Err(error)=>epoch.fail(error)}}
}}
fn cxx_unwind_wrapper(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord,provider:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->RegistryResult<CrtValue>)->RegistryResult<CrtValue>{{{wrapper_code}}}
"#
    ))
}

const TYPES: &str = r#"
struct CxxPendingAction{old:i32,next:i32,target:u32,written:bool}
struct CxxUnwindFlow{anchor:guest_memory::Capability,thread:u64,activation:u64,ptd:Option<CrtPointer>,counter:u32,incremented:bool,decremented:bool,pending:Option<CxxPendingAction>}
impl CxxUnwindFlow{
 fn new(rt:&CrtStreamRuntime,cpu:&CrtCpu)->Self{Self{anchor:rt.anchor,thread:rt.thread,activation:cpu.return_id,ptd:None,counter:0,incremented:false,decremented:false,pending:None}}
 fn check_counter(&self,rt:&CrtStreamRuntime)->RegistryResult<()>{
  if rt.anchor!=self.anchor||rt.thread!=self.thread{return Err("C++ unwind runtime/thread changed");}
  let p=self.ptd.ok_or("C++ unwind missing PTD")?;
  rt.valid(p,40)?;
  if rt.load(rt.offset(p,24)?,32)?.known_scalar()?!=self.counter{return Err("C++ unwind counter changed/unknown");}Ok(())
 }
 fn before_increment(&self,rt:&CrtStreamRuntime)->RegistryResult<()>{self.check_counter(rt)?;if self.incremented||self.counter>=i32::MAX as u32{return Err("C++ unwind counter domain/replay");}Ok(())}
 fn after_increment(&mut self,rt:&CrtStreamRuntime)->RegistryResult<()>{self.counter+=1;self.incremented=true;self.check_counter(rt)}
 fn after_decrement(&mut self,rt:&CrtStreamRuntime)->RegistryResult<()>{if !self.incremented||self.decremented||self.counter==0{return Err("C++ unwind counter cleanup phase");}self.counter-=1;self.decremented=true;self.check_counter(rt)}
 fn map_pointer(&self,rt:&CrtStreamRuntime,cpu:&mut CrtCpu,record:&CrtCxxRecord)->RegistryResult<()>{
  if cpu.r[7]!=CrtValue::Pointer(record.metadata)||cpu.r[0].known_scalar()?!=record.map.address(){return Err("C++ unwind map provenance");}
  CrtCxxRecord::bytes(rt,record.map,&record.map_bytes)?;cpu.r[0]=CrtValue::Pointer(record.map);Ok(())
 }
 fn begin(&mut self,rt:&CrtStreamRuntime,cpu:&mut CrtCpu,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord)->RegistryResult<()>{
  self.check_counter(rt)?;let old=record.state(rt,owner,frame)?;
  if cpu.return_id!=self.activation||self.pending.is_some()||old<0||cpu.r[6].known_scalar()?!=old as u32{return Err("C++ unwind pending action ownership");}
  let(next,target)=record.required_action(rt,owner,frame)?.ok_or("C++ unwind no action")?;
  self.map_pointer(rt,cpu,record)?;self.pending=Some(CxxPendingAction{old,next,target,written:false});Ok(())
 }
 fn before_step(&self,rt:&CrtStreamRuntime,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord)->RegistryResult<()>{self.check_counter(rt)?;let p=self.pending.as_ref().ok_or("C++ unwind missing pending action")?;if p.written||record.state(rt,owner,frame)?!=p.old{return Err("C++ unwind stale state transition");}Ok(())}
 fn after_step(&mut self,rt:&CrtStreamRuntime,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord)->RegistryResult<()>{let p=self.pending.as_mut().ok_or("C++ unwind missing transition")?;if p.written||record.state(rt,owner,frame)?!=p.next{return Err("C++ unwind state write disagreement");}p.written=true;Ok(())}
 fn action_arguments(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord)->RegistryResult<()>{
  self.check_counter(rt)?;let p=self.pending.as_ref().ok_or("C++ unwind lost action")?;let sp=CrtCpu::pointer(cpu.r[4])?;
  if cpu.return_id!=self.activation||!p.written||record.state(rt,owner,frame)?!=p.next||rt.load(sp,32)?.known_scalar()?!=p.target||rt.load(rt.offset(sp,4)?,32)?!=CrtValue::Pointer(rt.offset(frame.bp,-12)?)||rt.load(rt.offset(sp,8)?,32)?.known_scalar()?!=0x103{return Err("C++ unwind pending action arguments");}Ok(())
 }
 fn final_store(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord)->RegistryResult<()>{
  self.finish(rt,cpu,owner,frame,record)?;let sp=CrtCpu::pointer(cpu.r[4])?;
  if rt.load(sp,32)?!=CrtValue::Pointer(rt.offset(frame.bp,-12)?)||rt.load(rt.offset(sp,4)?,32)?!=CrtValue::Pointer(record.metadata)||rt.load(rt.offset(sp,8)?,32)?.known_scalar()?!=u32::MAX{return Err("C++ unwind final state arguments");}Ok(())
 }
 fn finish(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord)->RegistryResult<()>{self.check_counter(rt)?;if cpu.return_id!=self.activation||!self.decremented||self.pending.is_some()||record.state(rt,owner,frame)?!= -1{return Err("C++ unwind incomplete action/counter");}Ok(())}
}
fn cxx_unwind_ptd(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,flow:&mut CxxUnwindFlow,provider:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->RegistryResult<CrtValue>)->RegistryResult<CrtValue>{
 if flow.ptd.is_some(){flow.check_counter(rt)?;}
 let value=provider(rt,cpu)?;let p=CrtCpu::pointer(value)?;
 if p.kind!=CrtRegionKind::ThreadData||p.address()!=p.base||!rt.regions.iter().any(|r|r.pointer==p){return Err("C++ unwind PTD root/role");}rt.valid(p,40)?;
 if let Some(old)=flow.ptd{if old!=p{return Err("C++ unwind PTD changed across calls");}flow.check_counter(rt)?;}else{flow.counter=rt.load(rt.offset(p,24)?,32)?.known_scalar()?;flow.ptd=Some(p);}
 Ok(value)
}
"#;

pub(crate) const BRIDGE: &str = "558bec83ec0453518b450c83c00c8945fc8b450855ff75108b4d108b6dfce87de6ffff5657ffd05f5e8bdd5d8b4d10558beb81f9000100007505b90200000051e85be6ffff5d595bc9c20c00";
pub(crate) const NOTICE_PREFIX: &str = "5351bb70c04100e90f000000";
pub(crate) const NOTICE_TAIL: &str = "894b08894304896b0c55515058595d595bc20400";

pub(crate) fn action_source(input: [&[u8]; 4]) -> Result<String, String> {
    for (actual, expected) in input.into_iter().zip([
        BRIDGE,
        NOTICE_PREFIX,
        NOTICE_TAIL,
        crate::crt_cxx_record::ACTION,
    ]) {
        if actual != crate::crt_ptd::raw(expected) {
            return Err("C++ unwind action/notification code binding".into());
        }
    }
    let mut graph = Graph::decode_with_exits(input[1], 0x402a20, &[0x402a3b])
        .map_err(|e| format!("notice prefix: {e}"))?;
    graph.nodes.extend(
        Graph::decode(input[2], 0x402a3b)
            .map_err(|e| format!("notice tail: {e}"))?
            .nodes,
    );
    graph.end = 0x402a4f;
    let notice = crate::crt_stream_emit::emit_body_with_hooks(
        &graph,
        |_, _| Err("C++ notification call".into()),
        &Default::default(),
        64,
        |_, _| Err("C++ notification FS".into()),
        |pc, _| {
            Ok(if pc == 0x402a3b {
                "if cpu.r[3].known_scalar()?!=0x41c070{return Err(\"C++ notification module base\");}cpu.r[3]=CrtValue::Pointer(rt.resolve_absolute(0x41c070,CrtRegionKind::Module)?);".into()
            } else {
                String::new()
            })
        },
        |_, _| Ok(None),
    )?;
    // Indirect calls require this enclosing exact target/owner proof. The
    // ordinary graph admission continues to reject unbound indirect calls.
    let mut nodes = std::collections::BTreeMap::new();
    let mut decoder =
        iced_x86::Decoder::with_ip(32, input[0], 0x404380, iced_x86::DecoderOptions::NONE);
    while decoder.can_decode() {
        let i = decoder.decode();
        let at = (i.ip32() - 0x404380) as usize;
        nodes.insert(
            i.ip32(),
            Graph::decode_instruction(&input[0][at..at + i.len()], i.ip32())?,
        );
    }
    if nodes
        .values()
        .flat_map(|n| &n.successors)
        .any(|p| !nodes.contains_key(p))
    {
        return Err("C++ action bridge edge boundary".into());
    }
    let bridge_graph = Graph {
        origin: 0x404380,
        end: 0x4043cc,
        nodes,
    };
    let bridge = crate::crt_stream_emit::emit_body_with_indirect(
        &bridge_graph,
        |pc, target| {
            if target == Target::Direct(0x402a20) {
                Ok(format!("cpu.call_activation(rt,{},4,|rt,child|cxx_unwind_notice(rt,child,owner,frame,record,flow))?;",pc+5))
            } else {
                Err("C++ unwind bridge call".into())
            }
        },
        &Default::default(),
        256,
        |_, _| Err("C++ bridge FS".into()),
        |_, _| Ok("record.state(rt,owner,frame)?;flow.check_counter(rt)?;".into()),
        |_, _| Ok(None),
        None,
        |_, _, _| Ok(None),
        |pc, _| {
            if pc != 0x4043a5 {
                return Err("C++ unwind indirect call site".into());
            }
            Ok("let p=flow.pending.as_ref().ok_or(\"C++ action lost pending owner\")?;if target.known_scalar()?!=p.target||p.target!=0x4026fc||cpu.r[5]!=CrtValue::Pointer(frame.bp){return Err(\"C++ action target/frame changed\");}cpu.call_activation(rt,0x4043a7,0,|rt,child|{child.validate_active(rt)?;record.state(rt,owner,frame)?;return Err(\"C++ original action jumps to unbound terminate40770c\");})?;".into())
        },
    )?;
    Ok(format!(
        r#"
fn cxx_unwind_notice(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord,flow:&CxxUnwindFlow)->RegistryResult<CrtValue>{{
 cpu.validate_active(rt)?;record.state(rt,owner,frame)?;flow.check_counter(rt)?;
 let p=flow.pending.as_ref().ok_or("C++ notification missing action")?;
 if !p.written||cpu.r[0].known_scalar()?!=p.target||cpu.r[1].known_scalar()?!=0x103||cpu.r[5]!=CrtValue::Pointer(frame.bp)||rt.load(rt.offset(CrtCpu::pointer(cpu.r[4])?,4)?,32)?.known_scalar()?!=0x103{{return Err("C++ notification pending action/frame/reason");}}
 {notice}
}}
fn cxx_unwind_action(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord,flow:&CxxUnwindFlow)->RegistryResult<CrtValue>{{
 cpu.validate_active(rt)?;
 {bridge}
}}
"#
    ))
}

#[test]
fn original_unwind_binding_rejects_changed_control_scope_and_actions() {
    let helper=crate::crt_ptd::raw("681022400064ff35000000008b442410896c24108d6c24102be0535657a100c041003145fc33c5508965e8ff75f88b45fcc745fcfeffffff8945f88d45f064a300000000c3");
    let originals = [
        crate::crt_ptd::raw(WRAPPER),
        crate::crt_ptd::raw(BODY),
        crate::crt_ptd::raw(SCOPE),
    ];
    for which in 0..originals.len() {
        for i in 0..originals[which].len() {
            let mut changed = originals.clone();
            changed[which][i] ^= 1;
            assert!(source(&changed[0], &changed[1], &helper, &changed[2]).is_err());
        }
    }
    let actions = [
        crate::crt_ptd::raw(BRIDGE),
        crate::crt_ptd::raw(NOTICE_PREFIX),
        crate::crt_ptd::raw(NOTICE_TAIL),
        crate::crt_ptd::raw(crate::crt_cxx_record::ACTION),
    ];
    for which in 0..actions.len() {
        for i in 0..actions[which].len() {
            let mut changed = actions.clone();
            changed[which][i] ^= 1;
            assert!(action_source([&changed[0], &changed[1], &changed[2], &changed[3]]).is_err());
        }
    }
}

/// Connect the original required getter with cached-only resolver authority.
/// No caller-provided lookup or loader callback can produce an unwind PTD here.
pub(crate) fn cached_source() -> Result<String, String> {
    let getter = crate::crt_cxx_ptd::dynamic_source(
        &crate::crt_ptd::raw(crate::crt_cxx_ptd::GETTER),
        &crate::crt_ptd::raw(crate::crt_cxx_ptd::REQUIRED),
    )?;
    Ok(format!(
        r#"{getter}
fn cxx_unwind_cached(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>,owner:&CrtCpu,frame:&CrtPtdFrame,record:&CrtCxxRecord,fiber:CrtFiber,slot:CrtFlsSlot)->RegistryResult<CrtValue>{{
 epoch.state()?;cpu.validate_active(rt)?;
 cxx_unwind_wrapper(rt,cpu,epoch,owner,frame,record,&mut |rt,child|cxx_ptd_required(rt,child,CrtResolverAccess::Cached,fiber,slot,&mut |_,_,_|Err("C++ cached unwind cannot load")))
}}
"#
    ))
}
