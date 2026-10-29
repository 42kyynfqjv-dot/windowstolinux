//! Normal-path PTD acquisition components. These emit original instructions;
//! neither the incoming chain nor exceptional delivery is an admission proof.
use crate::crt_stream_emit;
use crate::crt_stream_ir::{Graph, Op, Target};
use std::collections::BTreeMap;

pub(crate) fn raw(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
pub(crate) const PROLOG:&str="5064ff35000000008d44240c2b64240c53565789288be8a100c0410033c550ff75fcc745fcffffffff8d45f464a300000000c3";
pub(crate) const EPILOG: &str = "8b4df464890d00000000595f5f5e5b8be55d51c3";
pub(crate) const GETTER:&str="6a00b8d64a4100e82a9f0000803d30d1410000742d8365fc00a170c1410083f8ff741650e8f9dcffff8bf885ff740a33c083ffff0f44f8eb46e87efeffff8bf8eb3dff15445041008bf0a170c14100c745fc0100000083f8ff741650e8cedcffff8bf885ff740a33c083ffff0f44f8eb07e846feffff8bf856ff15485041008bc7e89c9e0000c3";

/// This helper protocol intentionally differs from the EH4 manager protocol.
/// Addresses are parameters; neither application names nor binary hashes bind it.
pub(crate) fn helper_source(
    prolog: &[u8],
    po: u32,
    epilog: &[u8],
    eo: u32,
    cookie: u32,
) -> Result<String, String> {
    let mut expected = raw(PROLOG);
    expected[24..28].copy_from_slice(&cookie.to_le_bytes());
    if prolog != expected
        || epilog != raw(EPILOG)
        || po == 0
        || eo == 0
        || cookie == 0
        || cookie % 4 != 0
    {
        return Err("PTD continuation helper protocol".into());
    }
    let pe = po.checked_add(51).ok_or("PTD code overflow")?;
    let ee = eo.checked_add(20).ok_or("PTD code overflow")?;
    let ce = cookie.checked_add(4).ok_or("PTD cookie overflow")?;
    if po < ee && eo < pe || po < ce && cookie < pe || eo < ce && cookie < ee {
        return Err("PTD helper/code/data alias".into());
    }
    let roles = BTreeMap::from([(cookie, "CrtRegionKind::Module".into())]);
    let mut source = String::from(TYPES);
    for (name, bytes, origin, enter) in [
        ("ptd_prolog", prolog, po, true),
        ("ptd_epilog", epilog, eo, false),
    ] {
        let graph = Graph::decode(bytes, origin)?;
        let body = crt_stream_emit::emit_body_with_hooks(
            &graph,
            |_, _| Err("PTD helper cannot call".into()),
            &roles,
            4096,
            |_, op| {
                match op {
                Op::FsPush if enter => Ok("cpu.push(rt,frame.previous)?;".into()),
                Op::FsWrite(r) => Ok(format!("frame.check_fs(rt,cpu.r[{}],{})?;fs(rt,frame,cpu.r[{}],{})?;frame.write_fs(rt,cpu.r[{}],{})?;", r.index, enter, r.index, enter, r.index, enter)),
                _ => Err("PTD helper thread instruction".into()),
            }
            },
            |pc, _| {
                Ok(if enter && pc == po + 34 {
                    "frame.move_continuation_source(rt,cpu,identity)?;".into()
                } else {
                    String::new()
                })
            },
            |_, pop| {
                if pop != 0 {
                    return Err("PTD helper RET cleanup".into());
                }
                Ok(Some("let p=CrtCpu::pointer(cpu.r[4])?;if rt.load(p,32)?!=CrtValue::ProtectedReturn(identity)||rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(identity)).count()!=1{return Err(\"PTD helper continuation uniqueness\");}cpu.pop(rt)?;return Ok(());".into()))
            },
        )?;
        source.push_str(&format!("fn {name}_with_fs(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,frame:&mut CrtPtdFrame,continuation:u32,mut fs:impl FnMut(&CrtStreamRuntime,&CrtPtdFrame,CrtValue,bool)->Result<(),&'static str>)->Result<(),&'static str>{{frame.helper(rt,cpu,{enter},continuation,|rt,cpu,frame,identity|{{{body}}})}}\nfn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,frame:&mut CrtPtdFrame,continuation:u32)->Result<(),&'static str>{{{name}_with_fs(rt,cpu,frame,continuation,|_,_,_,_|Ok(()))}}\n"));
    }
    Ok(source)
}

pub(crate) const FLS_THUNK: &str = "8bff558bec5dff25a0504100";
fn fls_thunk_source(bytes: &[u8], origin: u32, iat: u32) -> Result<String, String> {
    let mut expected = raw(FLS_THUNK);
    expected[8..12].copy_from_slice(&iat.to_le_bytes());
    let end = origin.checked_add(12).ok_or("FLS thunk overflow")?;
    let ie = iat.checked_add(4).ok_or("FLS IAT overflow")?;
    if bytes != expected || origin == 0 || iat == 0 || iat % 4 != 0 || origin < ie && iat < end {
        return Err("FLS original thunk/IAT protocol".into());
    }
    let graph = Graph::decode_linear_fragment(&bytes[..6], origin)?;
    let body = crt_stream_emit::emit_linear_fragment(&graph, &Default::default())?;
    Ok(format!("fn ptd_fls_thunk(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,fiber:CrtFiber,slot:CrtFlsSlot)->Result<CrtValue,&'static str>{{let _=(||->Result<CrtValue,&'static str>{{{body}}})()?;let sp=CrtCpu::pointer(cpu.r[4])?;let index=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;let value=rt.fls_get(fiber,slot,index)?;cpu.clobber(value);cpu.finish_pop(rt,4)}}"))
}

pub(crate) fn source() -> String {
    let mut source =
        helper_source(&raw(PROLOG), 0x414268, &raw(EPILOG), 0x414254, 0x41c000).unwrap();
    source.push_str(&fls_thunk_source(&raw(FLS_THUNK), 0x408061, 0x4150a0).unwrap());
    let graph = Graph::decode(&raw(GETTER), 0x40a332).unwrap();
    let roles = BTreeMap::from([
        (0x41d130, "CrtRegionKind::Module".into()),
        (0x41c170, "CrtRegionKind::Module".into()),
    ]);
    let body=crt_stream_emit::emit_body_with_hooks(&graph,|pc,target|{
  let next=pc+graph.nodes[&pc].length;
  Ok(match target{
   Target::Direct(0x414268)=>"frame=Some(CrtPtdFrame::new(rt,cpu,previous,0x414ad6,0x41c000)?);ptd_prolog(rt,cpu,frame.as_mut().unwrap(),0x40a33e)?;".into(),
   Target::Direct(0x414254)=>"ptd_epilog(rt,cpu,frame.as_mut().ok_or(\"PTD missing frame\")?,0x40a3b8)?;".into(),
   Target::Import(0x415044)=>format!("cpu.call_activation(rt,{next},0,|rt,child|{{let value=rt.last_os_error.map(CrtValue::scalar).unwrap_or(CrtValue::Scalar{{bits:0,known:0}});child.clobber(value);child.finish(rt)}})?;"),
   Target::Import(0x415048)=>format!("cpu.call_activation(rt,{next},4,|rt,child|{{let sp=CrtCpu::pointer(child.r[4])?;let value=rt.load(rt.offset(sp,4)?,32)?;if !matches!(value,CrtValue::Scalar{{..}}){{return Err(\"LastError scalar type\");}}rt.last_os_error=value.known_scalar().ok();child.clobber(CrtValue::Scalar{{bits:0,known:0}});child.finish_pop(rt,4)}})?;"),
   Target::Direct(0x408061)=>format!("frame.as_ref().ok_or(\"PTD missing frame\")?.live(rt,cpu)?;cpu.call_activation(rt,{next},4,|rt,child|{{ptd_fls_thunk(rt,child,fiber,slot)}})?;"),
   Target::Direct(0x408054)=>"return Err(\"PTD dynamic FlsGetValue2 effect unbound\");".into(),
   Target::Direct(0x40a1ee)=>format!("cpu.call_activation(rt,{next},0,|rt,child|lazy(rt,child))?;"),
   _=>return Err("PTD unexpected call target".into())})
 },&roles,4096,|_,_|Err("PTD getter direct FS unbound".into()),|_,_|Ok(String::new()),|_,pop|{if pop!=0{return Err("PTD getter RET cleanup".into());}Ok(Some("if !frame.as_ref().is_some_and(|f|f.phase==2){return Err(\"PTD incomplete epilog\");}return cpu.finish(rt);".into()))}).unwrap();
    source.push_str(&format!("fn ptd_get_with_lazy(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,previous:CrtThreadHead,fiber:CrtFiber,slot:CrtFlsSlot,mut lazy:impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{rt.check_fiber(fiber)?;rt.validate_thread_head(previous)?;let mut frame:Option<CrtPtdFrame>=None;{body}}}"));
    source.push_str("fn ptd_get(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,previous:CrtThreadHead,fiber:CrtFiber,slot:CrtFlsSlot)->Result<CrtValue,&'static str>{ptd_get_with_lazy(rt,cpu,previous,fiber,slot,|_,_|Err(\"PTD lazy acquisition/recursive errno unbound\"))}");
    source
}

const TYPES: &str = r#"
struct CrtPtdFrame{anchor:guest_memory::Capability,thread:u64,outer:u64,entry:[CrtValue;8],bp:CrtPointer,low:CrtPointer,previous:CrtValue,current:CrtValue,handler:u32,cookie:u32,phase:u8}
impl CrtPtdFrame{
 fn new(rt:&CrtStreamRuntime,cpu:&CrtCpu,previous:CrtThreadHead,handler:u32,cookie_address:u32)->Result<Self,&'static str>{
  cpu.validate_active(rt)?;rt.validate_thread_head(previous)?;let bp=CrtCpu::pointer(cpu.r[4])?;let n=rt.load(bp,32)?.known_scalar()?;
  if n>256||n%4!=0||cpu.r[0]!=CrtValue::scalar(handler)||bp!=rt.offset(CrtCpu::pointer(cpu.entry[4])?,-4)?{return Err("PTD helper input/allocation");}
  let low=rt.offset(bp,-28-i64::from(n))?;let bottom=rt.offset(low,-4)?;rt.valid(bottom,n+32)?;
  if !rt.overlapping_tags(bottom.address(),n+32).is_empty(){return Err("PTD frame overlaps protected/typed storage");}
  let cookie=rt.load(rt.resolve_absolute(cookie_address,CrtRegionKind::Module)?,32)?.known_scalar()?;
  Ok(Self{anchor:rt.anchor,thread:rt.thread,outer:cpu.return_id,entry:cpu.entry,bp,low,previous:CrtValue::ThreadHead(previous),current:CrtValue::ThreadHead(previous),handler,cookie,phase:0})
 }
 fn identity(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu)->Result<(),&'static str>{if self.anchor!=rt.anchor||self.thread!=rt.thread||self.outer!=cpu.return_id||self.entry!=cpu.entry||cpu.returned{return Err("PTD frame owner/caller lifetime");}cpu.validate_active(rt)?;Ok(())}
 fn live(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu)->Result<(),&'static str>{
  self.identity(rt,cpu)?;let record=rt.offset(self.bp,-12)?;
  if self.phase!=1||self.current!=CrtValue::Pointer(record)||cpu.r[5]!=CrtValue::Pointer(self.bp)||rt.load(record,32)?!=self.previous||rt.load(rt.offset(self.bp,-8)?,32)?!=CrtValue::scalar(self.handler){return Err("PTD live record/chain identity");}
  rt.load(rt.offset(self.bp,-4)?,32)?.known_scalar()?;Ok(())
 }
 fn move_continuation_source(&self,rt:&mut CrtStreamRuntime,cpu:&CrtCpu,id:u64)->Result<(),&'static str>{
  let old=rt.offset(self.bp,-4)?;let new=CrtCpu::pointer(cpu.r[4])?;
  if old==new||new!=rt.offset(self.low,-4)?||rt.load(old,32)?!=CrtValue::ProtectedReturn(id)||rt.load(new,32)?!=CrtValue::ProtectedReturn(id)||rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(id)).count()!=2{return Err("PTD moved continuation identity");}
  // The next certified instruction overwrites precisely this old source word.
  rt.consume_stack(old,CrtValue::ProtectedReturn(id))
 }
 fn check_fs(&self,rt:&CrtStreamRuntime,value:CrtValue,enter:bool)->Result<(),&'static str>{
  let record=rt.offset(self.bp,-12)?;
  if enter{if self.phase!=0||self.current!=self.previous||value!=CrtValue::Pointer(record)||rt.load(record,32)?!=self.previous{return Err("PTD FS installation");}}
  else if self.phase!=1||self.current!=CrtValue::Pointer(record)||value!=self.previous||rt.load(record,32)?!=self.previous{return Err("PTD FS restoration");}
  Ok(())
 }
 fn write_fs(&mut self,rt:&CrtStreamRuntime,value:CrtValue,enter:bool)->Result<(),&'static str>{
  self.check_fs(rt,value,enter)?;self.current=value;Ok(())
 }
 fn helper(&mut self,rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,enter:bool,continuation:u32,run:impl FnOnce(&mut CrtStreamRuntime,&mut CrtCpu,&mut Self,u64)->Result<(),&'static str>)->Result<(),&'static str>{
  self.identity(rt,cpu)?;if continuation==0{return Err("PTD unbound helper continuation");}
  if enter{if self.phase!=0||cpu.r[4]!=CrtValue::Pointer(self.bp){return Err("PTD prolog replay");}}
  else{self.live(rt,cpu)?;if cpu.r[4]!=CrtValue::Pointer(self.low){return Err("PTD epilog stack");}let guard=self.cookie^self.bp.address();if rt.load(self.low,32)?!=CrtValue::scalar(guard){return Err("PTD guard changed");}for(i,r)in[7,6,3].iter().enumerate(){if rt.load(rt.offset(self.low,4+i as i64*4)?,32)?!=self.entry[*r]{return Err("PTD saved register changed");}}if rt.load(self.bp,32)?!=self.entry[5]{return Err("PTD saved frame pointer changed");}}
  let generation=rt.generation.checked_add(1).filter(|n|*n<1u64<<63).ok_or("PTD continuation exhausted")?;let id=generation|(1<<63);
  if rt.tags.values().any(|&v|v==CrtValue::ProtectedReturn(id)){return Err("PTD continuation collision");}rt.generation=generation;cpu.push(rt,CrtValue::ProtectedReturn(id))?;
  let result=run(rt,cpu,self,id);if let Err(e)=result{self.phase=3;return Err(e);}
  if rt.tags.values().any(|&v|v==CrtValue::ProtectedReturn(id)){self.phase=3;return Err("PTD continuation not consumed");}
  // RET consumes authority, while a POP/PUSH shuttle leaves the numeric PC
  // observable in volatile registers. Never leave a reusable control token.
  for value in &mut cpu.r{if *value==CrtValue::ProtectedReturn(id){*value=CrtValue::scalar(continuation);}}
  if enter{self.phase=1;self.live(rt,cpu)?;if cpu.r[4]!=CrtValue::Pointer(self.low){self.phase=3;return Err("PTD prolog resulting stack");}}
  else{
   if self.current!=self.previous||cpu.r[4]!=self.entry[4]||[3,5,6,7].iter().any(|&i|cpu.r[i]!=self.entry[i]){self.phase=3;return Err("PTD epilog resulting state");}
   for offset in [-12,-8,-4]{let p=rt.offset(self.bp,offset)?;let v=rt.load(p,32)?;rt.consume_stack(p,v)?;}self.phase=2;
  }Ok(())
 }
}
"#;

#[test]
fn original_ptd_continuation_and_fls_normal_path() {
    crate::crt_stream_callees_tests::native(
        &source(),
        r#"
for (case,value,index) in [(0,0x7000,3),(1,u32::MAX,3),(2,0,3),(3,0x7000,u32::MAX),(4,0x7000,4),(5,0x7000,3),(6,0x7000,3)]{
 let mut rt=CrtStreamRuntime::new(7,9,0x8000,65536).unwrap();
 rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();
 rt.map_region(0x41d130,1,CrtRegionKind::Module,if case==5{Some(&[1])}else if case==6{None}else{Some(&[0])}).unwrap();
 rt.map_region(0x41c170,4,CrtRegionKind::Module,Some(&index.to_le_bytes())).unwrap();
 let ptd=rt.map_region(0x7000,32,CrtRegionKind::ThreadData,None).unwrap();rt.store(rt.offset(ptd,16).unwrap(),32,CrtValue::scalar(19)).unwrap();
 let fiber=rt.bind_fiber(9).unwrap();let slot=rt.bind_fls(fiber,3,if value==0x7000{CrtValue::Pointer(ptd)}else{CrtValue::scalar(value)}).unwrap();
 let stack=rt.map_region(0x9000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,768).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();let saved=cpu.r;
 let previous=rt.thread_head(17,8,[1,4,12]).unwrap();rt.last_os_error=Some(765);
 let got=ptd_get(&mut rt,&mut cpu,previous,fiber,slot);
 if case>=2{assert!(got.is_err(),"case {}",case);assert!(!cpu.returned);if case==2{assert_eq!(rt.last_os_error,None);}else{assert_eq!(rt.last_os_error,Some(765));}continue;}
 assert_eq!(got.unwrap(),if case==0{CrtValue::Pointer(ptd)}else{CrtValue::scalar(0)});assert_eq!(rt.last_os_error,Some(765));assert!(cpu.returned);
 for r in [3,5,6,7]{assert_eq!(cpu.r[r],saved[r]);}assert_eq!(CrtCpu::pointer(cpu.r[4]).unwrap().address(),sp.address()+4);assert!(!rt.tags.values().any(|v|matches!(v,CrtValue::ProtectedReturn(_)|CrtValue::ThreadHead(_)|CrtValue::OpaqueSaved(_))));assert!(cpu.finish(&mut rt).is_err());
}
"#,
        "ptd-original",
    );
}

#[test]
fn different_sized_continuations_preserve_words_and_reject_corruption() {
    crate::crt_stream_callees_tests::native(
        &helper_source(&raw(PROLOG), 0x414268, &raw(EPILOG), 0x414254, 0x41c000).unwrap(),
        r#"
for allocation in [0,4,16,256]{for fault in 0..7{
 let mut rt=CrtStreamRuntime::new(7,9,0x8000,65536).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();let stack=rt.map_region(0xa000,2048,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,1536).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();for r in [3,5,6,7]{cpu.r[r]=CrtValue::scalar(100+r as u32);cpu.entry[r]=cpu.r[r];}let saved=cpu.r;
 cpu.push(&mut rt,CrtValue::scalar(allocation)).unwrap();cpu.r[0]=CrtValue::scalar(0x414ad6);let previous=rt.thread_head(17,8,[1,4,12]).unwrap();let mut frame=CrtPtdFrame::new(&rt,&cpu,previous,0x414ad6,0x41c000).unwrap();
 ptd_prolog(&mut rt,&mut cpu,&mut frame,0x420005).unwrap();assert_eq!(CrtCpu::pointer(cpu.r[5]).unwrap().address(),sp.address()-4);assert_eq!(CrtCpu::pointer(cpu.r[4]).unwrap().address(),sp.address()-32-allocation);
 assert_eq!(rt.load(rt.offset(sp,-8).unwrap(),32).unwrap(),CrtValue::scalar(u32::MAX));assert!(ptd_prolog(&mut rt,&mut cpu,&mut frame,0x420005).is_err());
 if fault==1{rt.store(frame.low,32,CrtValue::scalar(0)).unwrap();}
 if fault==2{rt.store(rt.offset(frame.low,4).unwrap(),32,CrtValue::scalar(77)).unwrap();}
 if fault==3{frame.current=frame.previous;}
 if fault==4{cpu.r[5]=CrtValue::Pointer(rt.offset(stack,16).unwrap());}
 if fault==5{frame.thread+=1;}
 if fault==6{rt.store(rt.offset(frame.low,-4).unwrap(),32,CrtValue::ProtectedReturn(1234)).unwrap();}
 let result=ptd_epilog(&mut rt,&mut cpu,&mut frame,0x420105);if fault!=0{assert!(result.is_err(),"fault {}",fault);assert!(!cpu.returned);continue;}result.unwrap();assert_eq!(cpu.r[1],CrtValue::scalar(0x420105));assert!(!cpu.r.iter().any(|v|matches!(v,CrtValue::ProtectedReturn(_))));for r in [3,5,6,7]{assert_eq!(cpu.r[r],saved[r]);}assert_eq!(cpu.r[4],saved[4]);assert!(ptd_epilog(&mut rt,&mut cpu,&mut frame,0x420105).is_err());cpu.finish(&mut rt).unwrap();
}}
"#,
        "ptd-stack",
    );
}

#[test]
fn helper_certificates_reject_mutation_and_aliasing() {
    let p = raw(PROLOG);
    let e = raw(EPILOG);
    let thunk = raw(FLS_THUNK);
    for i in 0..thunk.len() {
        let mut bad = thunk.clone();
        bad[i] ^= 1;
        assert!(fls_thunk_source(&bad, 0x408061, 0x4150a0).is_err());
    }
    assert!(fls_thunk_source(&thunk, 0x4150a0, 0x4150a0).is_err());

    for i in 0..p.len() {
        if (24..28).contains(&i) {
            continue;
        }
        let mut bad = p.clone();
        bad[i] ^= 1;
        assert!(helper_source(&bad, 0x414268, &e, 0x414254, 0x41c000).is_err());
    }
    for i in 0..e.len() {
        let mut bad = e.clone();
        bad[i] ^= 1;
        assert!(helper_source(&p, 0x414268, &bad, 0x414254, 0x41c000).is_err());
    }
    assert!(helper_source(&p, 0x414268, &e, 0x414270, 0x41c000).is_err());
    let mut relocated = p;
    relocated[24..28].copy_from_slice(&0x500000u32.to_le_bytes());
    assert!(helper_source(&relocated, 0x420000, &e, 0x420100, 0x500000).is_ok());
}

#[test]
fn fls_context_is_fiber_scoped_and_stale_slots_cannot_rebind_authority() {
    crate::crt_stream_callees_tests::native(
        "",
        r#"
let mut rt=CrtStreamRuntime::new(7,9,0x8000,65536).unwrap();let p=rt.map_region(0x7000,32,CrtRegionKind::ThreadData,None).unwrap();let f=rt.bind_fiber(9).unwrap();assert!(rt.bind_fiber(9).is_err());assert!(rt.bind_fiber(10).is_err());let s=rt.bind_fls(f,2,CrtValue::Pointer(p)).unwrap();assert!(rt.retire_fiber(f).is_err());assert_eq!(rt.fls_get(f,s,2).unwrap(),CrtValue::Pointer(p));assert!(rt.load(rt.offset(p,16).unwrap(),32).unwrap().known_scalar().is_err());
for bad in [CrtValue::scalar(0x7000),CrtValue::Scalar{bits:0,known:0},CrtValue::Pointer(rt.offset(p,4).unwrap())]{assert!(rt.bind_fls(f,3,bad).is_err());}
let mut other=CrtStreamRuntime::new(7,9,0x8000,65536).unwrap();let f2=other.bind_fiber(9).unwrap();assert!(other.fls_get(f,s,2).is_err());assert!(rt.fls_get(f2,s,2).is_err());assert!(rt.fls_get(f,s,3).is_err());
let cell=rt.offset(p,16).unwrap();rt.store(cell,32,CrtValue::scalar(23)).unwrap();rt.bind_errno_cell(cell).unwrap();rt.retire_fls(f,s).unwrap();let newer=rt.bind_fls(f,2,CrtValue::Pointer(p)).unwrap();assert!(rt.fls_get(f,s,2).is_err());assert!(rt.retire_fls(f,s).is_err());rt.retire_region(p).unwrap();assert!(rt.fls_get(f,newer,2).is_err());rt.retire_fls(f,newer).unwrap();rt.retire_fiber(f).unwrap();assert!(rt.errno_cell.is_none());assert!(rt.errno.is_none());let next=rt.bind_fiber(9).unwrap();assert_ne!(next,f);assert!(rt.check_fiber(f).is_err());
"#,
        "fls-identity",
    );
}

#[test]
fn original_errno_call_executes_ptd_body_and_preserves_last_error() {
    let extra = format!(
        "{} {}",
        source(),
        crate::crt_standard_handles_tests::errno_source()
    );
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
for mode in 0..3{let sentinel=mode==1;
 let mut rt=CrtStreamRuntime::new(7,9,0x8000,65536).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();rt.map_region(0x41d130,1,CrtRegionKind::Module,Some(&[0])).unwrap();rt.map_region(0x41c170,4,CrtRegionKind::Module,Some(&7u32.to_le_bytes())).unwrap();let fallback=rt.map_region(0x41c130,4,CrtRegionKind::Module,Some(&73u32.to_le_bytes())).unwrap();let ptd=rt.map_region(0x7000,32,CrtRegionKind::ThreadData,None).unwrap();let cell=rt.offset(ptd,16).unwrap();if mode!=2{rt.store(cell,32,CrtValue::scalar(19)).unwrap();}let fiber=rt.bind_fiber(9).unwrap();let slot=rt.bind_fls(fiber,7,if sentinel{CrtValue::scalar(u32::MAX)}else{CrtValue::Pointer(ptd)}).unwrap();
 let stack=rt.map_region(0x9000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,768).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();let previous=rt.thread_head(17,8,[1,4,12]).unwrap();rt.last_os_error=Some(1123);
 let result=errno_routed_call(&mut rt,&mut cpu,|rt,child|ptd_get(rt,child,previous,fiber,slot)).unwrap();let selected=CrtCpu::pointer(result).unwrap();assert_eq!(selected.address(),if sentinel{fallback.address()}else{cell.address()});assert_eq!(rt.errno,if mode==2{None}else{Some(if sentinel{73}else{19})});assert_eq!(rt.last_os_error,Some(1123));rt.store(selected,32,CrtValue::scalar(12)).unwrap();assert_eq!(rt.errno,Some(12));assert!(cpu.returned);
}
"#,
        "ptd-errno-connected",
    );
}

pub(crate) const LAZY:&str="8bff57ff15445041006affff3570c141008bf8e867deffff85c0750b57ff154850410033c05fc3535668640300006a01e8cddaffff8bf0595985f6752033db53ff3570c14100e834deffff53e811dbffff5957ff154850410033c0eb4756ff3570c14100e816deffff85c0751733db53ff3570c14100e804deffff56e8e1daffff59eb176834d1410056e8eafdffff6a00e8ccdaffff83c40c8bde57ff15485041008bc35e5b5fc3";
pub(crate) const SET_THUNK: &str = "8bff558bec5dff25a4504100";
fn lazy_source() -> String {
    let thunk = raw(SET_THUNK);
    assert_eq!(&thunk[6..], &[0xff, 0x25, 0xa4, 0x50, 0x41, 0]);
    let pre = crt_stream_emit::emit_linear_fragment(
        &Graph::decode_linear_fragment(&thunk[..6], 0x40806d).unwrap(),
        &Default::default(),
    )
    .unwrap();
    let graph = Graph::decode(&raw(LAZY), 0x40a1ee).unwrap();
    let roles = BTreeMap::from([(0x41c170, "CrtRegionKind::Module".into())]);
    let body=crt_stream_emit::emit_body(&graph,|pc,target|{
 let next=pc+graph.nodes[&pc].length;
 Ok(match target{
 Target::Import(0x415044)=>format!("cpu.call_activation(rt,{next},0,|rt,child|{{child.clobber(rt.last_os_error.map(CrtValue::scalar).unwrap_or(CrtValue::Scalar{{bits:0,known:0}}));child.finish(rt)}})?;"),
 Target::Import(0x415048)=>format!("cpu.call_activation(rt,{next},4,|rt,child|{{let p=rt.offset(CrtCpu::pointer(child.r[4])?,4)?;let value=rt.load(p,32)?;if !matches!(value,CrtValue::Scalar{{..}}){{return Err(\"LastError scalar\");}}rt.last_os_error=value.known_scalar().ok();child.clobber(CrtValue::Scalar{{bits:0,known:0}});child.finish_pop(rt,4)}})?;"),
 Target::Direct(0x40806d)=>format!("cpu.call_activation(rt,{next},8,|rt,child|{{let cpu=&mut *child;let _=(||->Result<CrtValue,&'static str>{{{pre}}})()?;let sp=CrtCpu::pointer(child.r[4])?;let index=rt.load(rt.offset(sp,4)?,32)?.known_scalar()?;let value=rt.load(rt.offset(sp,8)?,32)?;let success=rt.fls_set(fiber,slot,index,value,set_success,None)?;child.clobber(CrtValue::scalar(u32::from(success)));child.finish_pop(rt,8)}})?;"),
 Target::Direct(0x407cf0)=>"return Err(\"PTD lazy calloc/recursive errno unbound\");".into(),
 Target::Direct(0x407d50)|Target::Direct(0x40a067)=>"return Err(\"PTD free/initializer effect unbound\");".into(),
 _=>return Err("unexpected lazy PTD call".into())})},&roles,4096).unwrap();
    format!("fn ptd_lazy(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,fiber:CrtFiber,slot:CrtFlsSlot,set_success:bool)->Result<CrtValue,&'static str>{{{body}}}")
}
#[test]
fn original_lazy_setter_preserves_failure_return_and_success_sentinel() {
    let extra = format!("{} {}", source(), lazy_source());
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
for initial_error in [Some(765),None]{for success in [false,true]{
 let mut rt=CrtStreamRuntime::new(7,9,0x8000,65536).unwrap();rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();rt.map_region(0x41d130,1,CrtRegionKind::Module,Some(&[0])).unwrap();rt.map_region(0x41c170,4,CrtRegionKind::Module,Some(&7u32.to_le_bytes())).unwrap();let fiber=rt.bind_fiber(9).unwrap();let slot=rt.bind_fls(fiber,7,CrtValue::scalar(0)).unwrap();let stack=rt.map_region(0x9000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,768).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut cpu=CrtCpu::new(sp,1).unwrap();let previous=rt.thread_head(17,8,[1,4,12]).unwrap();rt.last_os_error=initial_error;
 let result=ptd_get_with_lazy(&mut rt,&mut cpu,previous,fiber,slot,|rt,child|ptd_lazy(rt,child,fiber,slot,success));
 if success{assert!(result.unwrap_err().contains("calloc"));assert!(!cpu.returned);assert_eq!(rt.fls_get(fiber,slot,7).unwrap(),CrtValue::scalar(u32::MAX));}
 else{assert_eq!(result.unwrap(),CrtValue::scalar(0));assert!(cpu.returned);assert_eq!(rt.last_os_error,initial_error);assert!(rt.fls_get(fiber,slot,7).is_err());}
}}
"#,
        "ptd-lazy",
    );
}

#[test]
fn fls_mutation_invalidates_errno_and_rejects_stale_setter_before_effects() {
    crate::crt_stream_callees_tests::native(
        "",
        r#"
let mut rt=CrtStreamRuntime::new(7,9,0x8000,65536).unwrap();let p=rt.map_region(0x7000,32,CrtRegionKind::ThreadData,None).unwrap();let cell=rt.offset(p,16).unwrap();rt.store(cell,32,CrtValue::scalar(31)).unwrap();let f=rt.bind_fiber(9).unwrap();let slot=rt.bind_fls(f,7,CrtValue::Pointer(p)).unwrap();rt.bind_errno_cell(cell).unwrap();rt.retire_fls(f,slot).unwrap();assert!(rt.errno_cell.is_none());assert_eq!(rt.errno,None);assert_eq!(rt.load(cell,32).unwrap(),CrtValue::scalar(31));
let next=rt.bind_fls(f,7,CrtValue::Pointer(p)).unwrap();rt.bind_errno_cell(cell).unwrap();rt.last_os_error=Some(91);assert!(rt.fls_set(f,slot,7,CrtValue::scalar(u32::MAX),true,None).is_err());assert_eq!(rt.errno,Some(31));assert_eq!(rt.last_os_error,Some(91));assert!(rt.fls_set(f,next,8,CrtValue::scalar(0),true,None).is_err());assert!(rt.fls_set(CrtFiber{thread:10,..f},next,7,CrtValue::scalar(0),true,None).is_err());assert_eq!(rt.errno,Some(31));
rt.fls_set(f,next,7,CrtValue::scalar(u32::MAX),true,None).unwrap();assert!(rt.errno_cell.is_none());assert_eq!(rt.errno,None);assert_eq!(rt.fls_get(f,next,7).unwrap(),CrtValue::scalar(u32::MAX));rt.fls_set(f,next,7,CrtValue::scalar(0),false,Some(8)).unwrap();assert_eq!(rt.last_os_error,Some(8));assert!(rt.fls_get(f,next,7).is_err());
"#,
        "fls-set-lifetime",
    );
}

/// Shared-chain adapter for the original helper's FS instruction effects.
/// Legacy helper inputs remain available only as explicitly supplied components.
pub(crate) fn shared_chain_source() -> &'static str {
    SHARED_CHAIN
}
const SHARED_CHAIN: &str = r#"
struct CrtCxxChainBinding {
 anchor:guest_memory::Capability,identity:RegistryIdentity,epoch:u64,lease:Option<DeliveryChildAuthority>,
 previous:RegistryHead,token:CrtThreadHead,bp:CrtPointer,owner:u64,id:Option<RegistrationId>,done:bool,
}
impl CrtCxxChainBinding {
 fn bind(rt:&CrtStreamRuntime,cpu:&CrtCpu,epoch:&NormalCallEpoch<'_>)->RegistryResult<Self>{
  let state=epoch.state()?;cpu.validate_active(rt)?;CrtNormalBinding::validate_cxx_head(rt,epoch)?;
  if rt.owner!=epoch.registry.identity.owner||rt.thread!=epoch.registry.identity.instance{return Err("C++ chain runtime/thread identity");}
  let bp=CrtCpu::pointer(cpu.r[4])?;let previous=epoch.head()?;
  let token=rt.thread_head(epoch.registry.identity.instance,state.generation,CrtNormalBinding::head_bits(previous))?;
  Ok(Self{anchor:rt.anchor,identity:epoch.registry.identity,epoch:state.generation,lease:epoch.delivery,previous,token,bp,owner:cpu.return_id,id:None,done:false})
 }
 fn identity(&self,rt:&CrtStreamRuntime,epoch:&NormalCallEpoch<'_>,frame:&CrtPtdFrame)->RegistryResult<()>{
  epoch.state()?;rt.valid(self.bp,4)?;
  if self.done||self.anchor!=rt.anchor||self.identity!=epoch.registry.identity||self.epoch!=epoch.generation||self.lease!=epoch.delivery
   ||frame.anchor!=self.anchor||frame.thread!=rt.thread||frame.outer!=self.owner||frame.bp!=self.bp||frame.previous!=CrtValue::ThreadHead(self.token){return Err("C++ chain stale owner/epoch/lease");}Ok(())
 }
 fn effect(&mut self,rt:&CrtStreamRuntime,epoch:&mut NormalCallEpoch<'_>,frame:&CrtPtdFrame,value:CrtValue,enter:bool)->RegistryResult<()>{
  self.identity(rt,epoch,frame)?;frame.check_fs(rt,value,enter)?;
  CrtNormalBinding::validate_cxx_from(rt,epoch,self.previous)?;
  if enter {
   if self.id.is_some()||epoch.head()?!=self.previous{return Err("C++ chain changed predecessor/replay");}
   let low=rt.offset(frame.low,-4)?.address();let high=u64::from(CrtCpu::pointer(frame.entry[4])?.address())+4;
   epoch.registry.range(low,high)?;epoch.delivery_range(low,high)?;
   let state=epoch.state()?;
   if epoch.registry.cxx.len()>=32||state.issued>=4096||!epoch.registry.module_contains_address(frame.handler)
    ||epoch.registry.cxx.iter().any(|f|u64::from(low)<f.high&&u64::from(f.low)<high)
    ||epoch.registry.frames.iter().any(|f|f.live&&u64::from(low)<f.high&&u64::from(f.low)<high)
    ||state.frames.iter().any(|f|u64::from(low)<f.high&&u64::from(f.low)<high){return Err("C++ chain full frame overlap/budget/handler");}
   let parent_low=match self.previous{
    RegistryHead::Cxx(id)=>epoch.registry.cxx.iter().find(|f|f.id==id&&f.linked).ok_or("C++ chain stale predecessor")?.low,
    RegistryHead::Normal(id)=>state.frames.iter().find(|f|f.id==id&&f.installed&&!f.unlinked).ok_or("C++ chain stale normal predecessor")?.low,
    RegistryHead::Owned(id)=>epoch.registry.frames[epoch.registry.frame_index(id)?].low,
    _=>return Err("C++ chain borrowed predecessor not contained"),
   };
   if high>u64::from(parent_low){return Err("C++ chain outside caller stack");}
   let id=epoch.registry.next_id()?;
   epoch.registry.cxx.push(RegistryCxxFrame{id,epoch:self.epoch,lease:self.lease,previous:self.previous,low,high,record:rt.offset(frame.bp,-12)?.address(),handler:frame.handler,owner:self.owner,linked:true});
   epoch.registry.normal_epoch.as_mut().unwrap().issued+=1;
   epoch.registry.head=RegistryHead::Cxx(id);self.id=Some(id);
  }else{
   let id=self.id.ok_or("C++ chain missing registration")?;
   let f=epoch.registry.cxx.iter_mut().find(|f|f.id==id).ok_or("C++ chain retired registration")?;
   if !f.linked||f.owner!=self.owner||f.epoch!=self.epoch||f.lease!=self.lease||f.record!=rt.offset(frame.bp,-12)?.address()||f.previous!=self.previous
    ||epoch.registry.head!=RegistryHead::Cxx(id){return Err("C++ chain non-LIFO unlink/identity");}
   f.linked=false;epoch.registry.head=self.previous;
  }Ok(())
 }
}
fn ptd_prolog_registered(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>,frame:&mut CrtPtdFrame,binding:&mut CrtCxxChainBinding,continuation:u32)->RegistryResult<()>{
 let result=(||{binding.identity(rt,epoch,frame)?;ptd_prolog_with_fs(rt,cpu,frame,continuation,|rt,f,value,enter|binding.effect(rt,epoch,f,value,enter))})();
 match result{Ok(())=>Ok(()),Err(e)=>epoch.fail(e)}
}
fn ptd_epilog_registered(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,epoch:&mut NormalCallEpoch<'_>,frame:&mut CrtPtdFrame,binding:&mut CrtCxxChainBinding,continuation:u32)->RegistryResult<()>{
 let result=(||{binding.identity(rt,epoch,frame)?;ptd_epilog_with_fs(rt,cpu,frame,continuation,|rt,f,value,enter|binding.effect(rt,epoch,f,value,enter))?;
  let id=binding.id.ok_or("C++ chain epilog without registration")?;
  let index=epoch.registry.cxx.iter().position(|f|f.id==id&&!f.linked).ok_or("C++ chain missing unlink")?;
  if frame.phase!=2||epoch.registry.head!=binding.previous{return Err("C++ chain incomplete original epilog");}
  epoch.registry.cxx.remove(index);binding.done=true;Ok(())})();
 match result{Ok(())=>Ok(()),Err(e)=>epoch.fail(e)}
}
"#;
