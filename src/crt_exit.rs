//! Inline shared-exit registration. Only the common record prefix is shared
//! with C++ chain nodes; handler 0x414af3 has no execution contract here.
use crate::crt_stream_ir::{Graph, Op, Target};
use std::collections::BTreeMap;
pub(crate) const PREFIX: &str =
    "8bff558bec6aff68f34a410064a1000000005083ec18a100c0410033c5508d45f464a300000000";
pub(crate) const FRONT:&str="837d10007512e8b6aeffff84c07409ff7508e8ae000000598d450cc645f3008945dc8d45108945e08d45f38945e48365fc008d4df26a02588945ec8945e88d45ec508d45dc508d45e850e81bfeffff";
pub(crate) const RETURN: &str = "8b4df464890d0000000059c9c3";
fn decode_one(bytes: &[u8], pc: u32) -> Result<crate::crt_stream_ir::Node, String> {
    let mut d =
        iced_x86::Decoder::with_ip(32, bytes, u64::from(pc), iced_x86::DecoderOptions::NONE);
    let i = d.decode();
    Graph::decode_instruction(bytes.get(..i.len()).ok_or("exit instruction length")?, pc)
}
pub(crate) fn source(prefix: &[u8], front: &[u8], tail: &[u8]) -> Result<String, String> {
    if prefix != crate::crt_ptd::raw(PREFIX)
        || front != crate::crt_ptd::raw(FRONT)
        || tail != crate::crt_ptd::raw(RETURN)
    {
        return Err("shared exit code binding".into());
    }
    let mut nodes = BTreeMap::new();
    let mut pc = 0x406e69;
    while pc < 0x406e90 {
        let node = decode_one(&prefix[(pc - 0x406e69) as usize..], pc)?;
        let next = pc + node.length;
        if node.successors != vec![next] {
            return Err("exit prolog non-linear instruction".into());
        }
        nodes.insert(pc, node);
        pc = next;
    }
    if pc != 0x406e90 {
        return Err("exit prolog extent".into());
    }
    let prolog = Graph {
        origin: 0x406e69,
        end: 0x406e90,
        nodes,
    };
    let p = crate::crt_stream_emit::emit_body_with_exit(
        &prolog,
        |_, _| Err("exit prolog call".into()),
        &BTreeMap::from([(0x41c000, "CrtRegionKind::Module".into())]),
        64,
        |_, op| match op {
            Op::FsRead(r) => Ok(format!(
                "cpu.r[{}]=CrtValue::ThreadHead(frame.token);",
                r.index
            )),
            Op::FsWrite(r) => Ok(format!("frame.install(rt,cpu,epoch,cpu.r[{}])?;", r.index)),
            _ => Err("exit prolog FS".into()),
        },
        |_, _| Ok("frame.identity(rt,cpu,epoch)?;".into()),
        |_, _| Err("exit prolog return".into()),
        Some(0x406e90),
    )?;
    // Calls are terminal rejection boundaries, never successful opaque callbacks.
    let mut nodes = BTreeMap::new();
    let mut todo = vec![0x406e90];
    while let Some(pc) = todo.pop() {
        if nodes.contains_key(&pc) {
            continue;
        }
        let at = (pc - 0x406e90) as usize;
        let mut n = decode_one(front.get(at..).ok_or("exit front range")?, pc)?;
        if matches!(n.op, Op::Call(_)) {
            n.successors.clear();
        } else {
            todo.extend(n.successors.iter().copied());
        }
        nodes.insert(pc, n);
    }
    let g = Graph {
        origin: 0x406e90,
        end: 0x406edf,
        nodes,
    };
    let b = crate::crt_stream_emit::emit_body_with_hooks(
        &g,
        |pc, target| {
            Ok(match (pc, target) {
                (0x406e96, Target::Direct(0x401d51)) => {
                    "return Err(\"shared exit managed-runtime query 0x401d51 unbound\");"
                }
                (0x406eda, Target::Direct(0x406cfa)) => {
                    "return Err(\"shared exit lock/cleanup manager 0x406cfa unbound\");"
                }
                _ => return Err("exit front call inventory".into()),
            }
            .into())
        },
        &BTreeMap::new(),
        64,
        |_, _| Err("exit front FS".into()),
        |_, _| Ok("frame.live(rt,cpu,epoch)?;".into()),
        |_, _| Err("exit front return".into()),
    )?;
    let t = crate::crt_stream_emit::emit_body_with_hooks(
        &Graph::decode(tail, 0x406f09)?,
        |_, _| Err("exit epilog call".into()),
        &BTreeMap::new(),
        32,
        |_, op| match op {
            Op::FsWrite(r) => Ok(format!("frame.unlink(rt,cpu,epoch,cpu.r[{}])?;", r.index)),
            _ => Err("exit epilog FS".into()),
        },
        |pc, _| {
            Ok(if pc == 0x406f09 {
                "frame.return_ready(rt,cpu,epoch)?;"
            } else {
                "frame.identity(rt,cpu,epoch)?;"
            }
            .into())
        },
        |_, n| {
            if n != 0 {
                return Err("exit epilog cleanup".into());
            }
            Ok(Some(
                "let value=cpu.finish(rt)?;frame.retire(rt,cpu,epoch)?;return Ok(value);".into(),
            ))
        },
    )?;
    Ok(format!("{TYPES}\nfn shared_exit_prolog(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>,frame:&mut CrtInlineExit)->RegistryResult<CrtValue>{{{p}}}\nfn shared_exit_front(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>,frame:&mut CrtInlineExit)->RegistryResult<CrtValue>{{{b}}}\nfn shared_exit_return(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>,frame:&mut CrtInlineExit)->RegistryResult<CrtValue>{{{t}}}\nfn abort_shared_exit_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>)->RegistryResult<CrtValue>{{let result=(||{{let mut frame=CrtInlineExit::new(rt,cpu,epoch)?;shared_exit_prolog(rt,cpu,epoch,&mut frame)?;shared_exit_front(rt,cpu,epoch,&mut frame)}})();match result{{Ok(v)=>Ok(v),Err(e)=>epoch.fail(e)}}}}"))
}
const TYPES: &str = r#"
struct CrtInlineExit{anchor:guest_memory::Capability,identity:RegistryIdentity,fiber:Option<CrtFiber>,epoch:u64,lease:Option<DeliveryChildAuthority>,entry:[CrtValue;8],owner:u64,bp:CrtPointer,low:CrtPointer,previous:RegistryHead,token:CrtThreadHead,id:Option<RegistrationId>,phase:u8}
impl CrtInlineExit{
 fn new(rt:&CrtStreamRuntime,cpu:&CrtCpu,e:&NormalCallEpoch<'_>)->RegistryResult<Self>{
  let s=e.state()?;cpu.validate_active(rt)?;CrtNormalBinding::validate_cxx_head(rt,e)?;
  if rt.closed||rt.owner!=e.registry.identity.owner||rt.thread!=e.registry.identity.instance||cpu.r[4]!=cpu.entry[4]||cpu.return_pop!=0{return Err("inline exit entry identity/ABI");}
  let bp=rt.offset(CrtCpu::pointer(cpu.entry[4])?,-4)?;let low=rt.offset(bp,-40)?;let high=u64::from(bp.address())+8;
  rt.valid(low,48)?;e.registry.range(low.address(),high)?;e.delivery_range(low.address(),high)?;
  if rt.overlapping_tags(low.address(),44).iter().any(|(_,v)|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::OpaqueSaved(_)|CrtValue::ThreadHead(_))){return Err("inline exit protected frame overlap");}
  let previous=e.head()?;let parent=match previous{RegistryHead::Cxx(id)=>e.registry.cxx.iter().find(|f|f.id==id&&f.linked).ok_or("inline exit stale parent")?.low,RegistryHead::Normal(id)=>s.frames.iter().find(|f|f.id==id&&f.installed&&!f.unlinked).ok_or("inline exit stale parent")?.low,RegistryHead::Owned(id)=>e.registry.frames[e.registry.frame_index(id)?].low,_=>return Err("inline exit borrowed parent uncontained")};
  if high>u64::from(parent)||e.registry.cxx.iter().any(|f|u64::from(low.address())<f.high&&u64::from(f.low)<high)||e.registry.frames.iter().any(|f|f.live&&u64::from(low.address())<f.high&&u64::from(f.low)<high)||s.frames.iter().any(|f|u64::from(low.address())<f.high&&u64::from(f.low)<high){return Err("inline exit frame/parent overlap");}
  let token=rt.thread_head(e.registry.identity.instance,s.generation,CrtNormalBinding::head_bits(previous))?;
  Ok(Self{anchor:rt.anchor,identity:e.registry.identity,fiber:rt.fiber,epoch:s.generation,lease:e.delivery,entry:cpu.entry,owner:cpu.return_id,bp,low,previous,token,id:None,phase:0})
 }
 fn identity(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu,e:&NormalCallEpoch<'_>)->RegistryResult<()>{
  e.state()?;cpu.validate_active(rt)?;rt.valid(self.low,48)?;
  if self.phase>2||rt.closed||rt.anchor!=self.anchor||rt.owner!=self.identity.owner||rt.thread!=self.identity.instance||rt.fiber!=self.fiber||e.registry.identity!=self.identity||e.generation!=self.epoch||e.delivery!=self.lease||cpu.entry!=self.entry||cpu.return_id!=self.owner{return Err("inline exit stale owner/event/fiber");}Ok(())
 }
 fn install(&mut self,rt:&CrtStreamRuntime,cpu:&CrtCpu,e:&mut NormalCallEpoch<'_>,value:CrtValue)->RegistryResult<()>{
  self.identity(rt,cpu,e)?;CrtNormalBinding::validate_cxx_from(rt,e,self.previous)?;let record=rt.offset(self.bp,-12)?;
  if self.phase!=0||self.id.is_some()||e.head()?!=self.previous||value!=CrtValue::Pointer(record)||cpu.r[5]!=CrtValue::Pointer(self.bp)||cpu.r[4]!=CrtValue::Pointer(self.low)||rt.load(record,32)?!=CrtValue::ThreadHead(self.token)||rt.load(rt.offset(record,4)?,32)?!=CrtValue::scalar(0x414af3)||rt.load(rt.offset(record,8)?,32)?!=CrtValue::scalar(u32::MAX){return Err("inline exit original installation/replay");}
  if !e.registry.module_contains_address(0x414af3)||e.registry.cxx.len()>=32||e.state()?.issued>=4096{return Err("inline exit handler/budget");}
  let id=e.registry.next_id()?;e.registry.cxx.push(RegistryCxxFrame{id,epoch:self.epoch,lease:self.lease,previous:self.previous,low:self.low.address(),high:u64::from(self.bp.address())+8,record:record.address(),handler:0x414af3,owner:self.owner,linked:true});e.registry.normal_epoch.as_mut().unwrap().issued+=1;e.registry.head=RegistryHead::Cxx(id);self.id=Some(id);self.phase=1;Ok(())
 }
 fn live(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu,e:&NormalCallEpoch<'_>)->RegistryResult<()>{
  self.identity(rt,cpu,e)?;let id=self.id.ok_or("inline exit missing registration")?;CrtNormalBinding::validate_cxx_head(rt,e)?;
  if self.phase!=1||e.head()?!=RegistryHead::Cxx(id)||cpu.r[5]!=CrtValue::Pointer(self.bp)||e.registry.cxx.iter().find(|f|f.id==id).is_none_or(|f|!f.linked||f.owner!=self.owner||f.lease!=self.lease||f.handler!=0x414af3||f.low!=self.low.address()||f.record!=self.bp.address()-12){return Err("inline exit live/LIFO record");}Ok(())
 }
 fn return_ready(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu,e:&NormalCallEpoch<'_>)->RegistryResult<()>{
  self.live(rt,cpu,e)?;if cpu.r[4]!=CrtValue::Pointer(self.low)||rt.load(self.bp,32)?!=self.entry[5]{return Err("inline exit return stack/saved frame");}Ok(())
 }
 fn unlink(&mut self,rt:&CrtStreamRuntime,cpu:&CrtCpu,e:&mut NormalCallEpoch<'_>,value:CrtValue)->RegistryResult<()>{
  self.live(rt,cpu,e)?;if value!=CrtValue::ThreadHead(self.token){return Err("inline exit predecessor changed");}let id=self.id.unwrap();e.registry.cxx.iter_mut().find(|f|f.id==id).unwrap().linked=false;e.registry.head=self.previous;self.phase=2;Ok(())
 }
 fn retire(&mut self,rt:&mut CrtStreamRuntime,cpu:&CrtCpu,e:&mut NormalCallEpoch<'_>)->RegistryResult<()>{
  // Only the emitted original RET may reach this transition. Nonreturning or
  // rejected external calls retain their record and cannot issue completion.
  e.state()?;if self.phase!=2||!cpu.returned||rt.anchor!=self.anchor||rt.owner!=self.identity.owner||rt.thread!=self.identity.instance||rt.fiber!=self.fiber||e.registry.identity!=self.identity||e.generation!=self.epoch||e.delivery!=self.lease||cpu.entry!=self.entry||cpu.return_id!=self.owner||cpu.r[4]!=CrtValue::Pointer(rt.offset(CrtCpu::pointer(self.entry[4])?,4)?)||[3,5,6,7].iter().any(|&i|cpu.r[i]!=self.entry[i])||rt.tags.values().any(|&v|v==CrtValue::ProtectedReturn(self.owner))||e.head()?!=self.previous{return Err("inline exit incomplete return");}
  let id=self.id.ok_or("inline exit missing retired id")?;let index=e.registry.cxx.iter().position(|f|f.id==id&&!f.linked).ok_or("inline exit missing unlink")?;
  for off in [-12,-8,-4]{let p=rt.offset(self.bp,off)?;let v=rt.load(p,32)?;rt.consume_stack(p,v)?;}
  e.registry.cxx.remove(index);self.phase=3;Ok(())
 }
}
"#;
#[test]
fn shared_exit_rejects_changed_instruction_regions() {
    let p = crate::crt_ptd::raw(PREFIX);
    let b = crate::crt_ptd::raw(FRONT);
    let t = crate::crt_ptd::raw(RETURN);
    source(&p, &b, &t).expect("unchanged exit regions must lower");
    for region in 0..3 {
        let mut all = [p.clone(), b.clone(), t.clone()];
        for i in 0..all[region].len() {
            all[region][i] ^= 1;
            assert!(source(&all[0], &all[1], &all[2]).is_err());
            all[region][i] ^= 1;
        }
    }
}
