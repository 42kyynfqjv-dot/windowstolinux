//! Original helper/epilog instructions with a live registry and shared storage.
//! Body effects and the completed-event fixture are explicit component inputs.
use super::{EpilogProof, PrologProof, Region};
use std::path::PathBuf;
use std::sync::OnceLock;

fn epilog_bytes() -> Vec<u8> {
    // Unchanged authored PE [0x404696,0x4046a8), independent of proof output.
    vec![
        0x8b, 0x4d, 0xf0, 0x64, 0x89, 0x0d, 0, 0, 0, 0, 0x59, 0x5f, 0x5e, 0x5b, 0xc9, 0xc2, 0x0c, 0,
    ]
}
// Literal original-byte regions; expected effects below are authored directly.
fn file_scope(p: &PrologProof) -> super::file_scope::FileScopeProof {
    let region = |name: &str, literal: &str| match std::env::var("W2L_EH4_CODE") {
        Ok(path) => std::fs::read(std::path::Path::new(&path).join(name)).unwrap(),
        Err(_) => bytes_hex(literal),
    };
    let wrapper = region("file-wrapper.bin", "8365e4008b4508ff30e8beffffff598365fc008b4d0ce8370c00008bf08975e4c745fcfeffffffe8170000008bc68b4df064890d00000000595f5e5bc9c20c00");
    let lock = region("file-lock.bin", "8bff558bec8b450883c02050ff154c5041005dc3");
    let unlock = region(
        "file-unlock.bin",
        "8bff558bec8b450883c02050ff15505041005dc3",
    );
    let cleanup = region("file-cleanup.bin", "8b4510ff30e893ffffff59c3");
    super::file_scope::FileScopeProof::prove(
        super::file_scope::Input {
            wrapper: Region {
                bytes: &wrapper,
                origin: 0x404668,
            },
            lock: Region {
                bytes: &lock,
                origin: 0x404634,
            },
            unlock: Region {
                bytes: &unlock,
                origin: 0x404648,
            },
            cleanup: Region {
                bytes: &cleanup,
                origin: 0x4046ab,
            },
            enter_iat: 0x41504c,
            leave_iat: 0x415050,
            driver: 0x4052ba,
        },
        p,
    )
    .unwrap()
}
fn bytes_hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}
fn prolog() -> PrologProof {
    PrologProof::prove(
        Region {
            bytes: &super::tests::bytes(),
            origin: 0x401e60,
        },
        12,
        0x41b400,
        0x41c000,
        0x402210,
    )
    .unwrap()
}
fn emitted_literal(source: &str) -> &str {
    source
        .split_once("r#\"")
        .unwrap()
        .1
        .split_once("\"#;")
        .unwrap()
        .0
}
const CASES: &str = r#"
fn runtime(r:&ThreadRegistry)->CrtStreamRuntime{
 let mut rt=CrtStreamRuntime::new(r.identity.owner,r.identity.instance,0x8000,65536).unwrap();
 rt.map_region(0x9000,0x6000,CrtRegionKind::Stack,None).unwrap();
 rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&0x12345678u32.to_le_bytes())).unwrap();rt
}
fn cpu(rt:&mut CrtStreamRuntime,entry:u32,id:u64)->CrtCpu{
 let p=rt.resolve_absolute(entry,CrtRegionKind::Stack).unwrap();rt.store(p,32,CrtValue::ProtectedReturn(id)).unwrap();
 for i in 1..=3{rt.store(rt.offset(p,i*4).unwrap(),32,CrtValue::scalar(i as u32*17)).unwrap();}
 let mut c=CrtCpu::new(p,id).unwrap();c.return_pop=12;c.r[3]=CrtValue::Scalar{bits:0xabcd0000,known:0xffff0000};
 c.r[6]=CrtValue::scalar(0x76543210);c.entry=c.r;c
}
fn start(rt:&mut CrtStreamRuntime,c:&mut CrtCpu,e:&mut NormalCallEpoch<'_>,b:&mut CrtNormalBinding,helper:u64)->RegistryResult<()>{
 c.push(rt,CrtValue::scalar(12))?;c.push(rt,CrtValue::scalar(0x41b400))?;c.push(rt,CrtValue::ProtectedReturn(helper))?;
 helper_run(rt,c,helper,b.token,|rt,c,record,head|b.install(rt,c,e,record,head))
}
fn nested_actual(){
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let previous=r.head;
 let before=m.owned_context;
 r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut outer=cpu(&mut rt,0xe000,71);let mut a=CrtNormalBinding::bind(&rt,&outer,e,epilog_run_layout())?;
  start(&mut rt,&mut outer,e,&mut a,99)?;let outer_id=a.id.unwrap();
  assert_eq!(e.head()?,RegistryHead::Normal(outer_id));
  // Independent body writes: scope becomes active and a local receives 93.
  rt.store(a.at(&rt,-8)?,32,CrtValue::scalar(0))?;rt.store(a.at(&rt,-32)?,32,CrtValue::scalar(93))?;
  let mut inner=cpu(&mut rt,0xd000,72);let mut b=CrtNormalBinding::bind(&rt,&inner,e,epilog_run_layout())?;
  assert_eq!(b.token.head,[3,e.generation,outer_id.generation]);start(&mut rt,&mut inner,e,&mut b,100)?;
  inner.r[0]=CrtValue::scalar(17);assert_eq!(epilog_run(&mut rt,&mut inner,e,&mut b)?,CrtValue::scalar(17));
  assert_eq!(inner.r[4],CrtValue::Pointer(rt.resolve_absolute(0xd010,CrtRegionKind::Stack)?));
  assert_eq!(e.head()?,RegistryHead::Normal(outer_id));assert!(b.authority(&rt,e).is_err());
  assert_eq!(rt.load(a.at(&rt,-32)?,32)?.known_scalar()?,93);
  rt.store(a.at(&rt,-8)?,32,CrtValue::scalar((-2i32)as u32))?;
  outer.r[0]=CrtValue::scalar(93);assert_eq!(epilog_run(&mut rt,&mut outer,e,&mut a)?,CrtValue::scalar(93));
  assert_eq!(outer.r[3],CrtValue::Scalar{bits:0xabcd0000,known:0xffff0000});
  assert_eq!(outer.r[5],CrtValue::OpaqueSaved(5));assert_eq!(outer.r[6],CrtValue::scalar(0x76543210));
  assert_eq!(outer.r[4],CrtValue::Pointer(rt.resolve_absolute(0xe010,CrtRegionKind::Stack)?));
  assert_eq!(e.head()?,previous);
  assert!(!rt.tags.values().any(|v|matches!(v,CrtValue::ProtectedReturn(71|72|99|100)|CrtValue::ThreadHead(_))));
  // Retired storage cannot supply initialized values to a stale stack alias.
  assert_eq!(rt.load(a.at(&rt,-32)?,32)?,CrtValue::Scalar{bits:0,known:0});Ok(())
 }).unwrap();assert_eq!(m.owned_context,before);assert_eq!(r.head,previous);assert!(r.normal_epoch.is_none());
}
fn mutations(){
 for mode in 0..15{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);
  let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;
   start(&mut rt,&mut c,e,&mut b,99)?;
   match mode{
    0=>rt.store(b.at(&rt,-36)?,32,CrtValue::Scalar{bits:0xabcd0000,known:0xffff00ff})?,
    1=>rt.store(b.at(&rt,-48)?,32,CrtValue::scalar(0))?,
    2=>rt.store(b.at(&rt,-12)?,32,CrtValue::scalar(0))?,
    3=>rt.store(b.at(&rt,-8)?,32,CrtValue::scalar(0))?,
    4=>{b.token.epoch+=1;},5=>{b.token.head[0]=0;},
    6=>{c.r[4]=CrtValue::Pointer(b.at(&rt,-44)?);},
    7=>{let foreign=runtime(e.registry);return epilog_run(&mut {foreign},&mut c,e,&mut b).map(|_|());},
    8=>{rt.store(rt.resolve_absolute(0x41c000,CrtRegionKind::Module)?,32,CrtValue::scalar(0))?;},
    9=>{c.return_id+=1;},10=>{e.registry.head=b.previous;},
    11=>{c.entry[3]=CrtValue::scalar(0xabcd0000);},
    12=>rt.store(b.at(&rt,-32)?,32,CrtValue::ProtectedReturn(456))?,
    13=>{c.r[0]=CrtValue::Pointer(b.at(&rt,-32)?);},
    _=>{let external=rt.map_region(0x7000,4,CrtRegionKind::Result,None)?;rt.store(external,32,CrtValue::Pointer(b.at(&rt,-32)?))?;},
   }
   epilog_run(&mut rt,&mut c,e,&mut b).map(|_|())
  });assert!(result.is_err(),"mutation {mode}");assert!(r.available().is_err());
  // Failure does not falsely complete the selected event or retire its frame.
  assert!(r.frames[0].linked&&r.frames[0].live);
 }
}
fn consumed_mutation(){
 for mode in 0..3{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);
  assert!(r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   b.load_previous(&rt,&mut c,e,1)?;b.unlink(&rt,&c,e,1)?;
   b.pop(&mut rt,&mut c,e,-48,1)?;
   if mode==0{rt.store(b.at(&rt,-48)?,32,CrtValue::scalar(0))?;}else if mode==1{c.r[1]=CrtValue::scalar(0);}else{c.r[4]=CrtValue::Pointer(b.at(&rt,-40)?);}
   b.pop(&mut rt,&mut c,e,-44,7)
  }).is_err());assert!(r.normal_epoch.as_ref().unwrap().frames[0].unlinked);
 }
}
fn body_failure(){
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let mut address=None;
 let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut c=cpu(&mut rt,0xe000,71);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
  let p=b.at(&rt,-32)?;rt.store(p,32,CrtValue::scalar(93))?;address=Some(p);Err::<(),_>("unresolved body exception")
 });assert_eq!(result,Err("unresolved body exception"));assert_eq!(rt.load(address.unwrap(),32).unwrap().known_scalar().unwrap(),93);
 assert!(r.normal_epoch.as_ref().unwrap().frames[0].installed);assert!(!r.normal_epoch.as_ref().unwrap().frames[0].unlinked);
}
fn wrong_certificate(){
 let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);
 assert!(r.with_normal_calls(&m,&mut permit,&main,|e|{
  let mut c=cpu(&mut rt,0xe000,71);c.return_pop=0;
  let mut layout=epilog_run_layout();layout.pop=0;
  let mut b=CrtNormalBinding::bind(&rt,&c,e,layout)?;start(&mut rt,&mut c,e,&mut b,99)?;
  let sp=c.r[4];let head=e.head()?;
  let result=epilog_run(&mut rt,&mut c,e,&mut b);
  assert_eq!(result,Err("EH4 epilog certificate/binding disagreement"));assert_eq!(c.r[4],sp);
  assert_eq!(e.registry.head,head);assert!(!c.returned);result.map(|_|())
 }).is_err());
}
fn observed(){
 let file=std::env::var("W2L_EH4_VECTORS").expect("original observation vectors required");
 assert!(std::fs::metadata(&file).unwrap().len()<65536);
 let text=std::fs::read_to_string(file).unwrap();let lines:Vec<_>=text.lines().collect();assert_eq!(lines.len(),5);
 for line in lines{
  let v:Vec<u32>=line.split_whitespace().map(|s|s.parse().unwrap()).collect();assert_eq!(v.len(),10);
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);
  rt.store(rt.resolve_absolute(0x41c000,CrtRegionKind::Module).unwrap(),32,CrtValue::scalar(v[0])).unwrap();
  r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);
   for (i,reg) in [3,5,6,7].into_iter().enumerate(){c.r[reg]=CrtValue::scalar(v[i+1]);}c.entry=c.r;
   let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   assert_eq!(CrtCpu::pointer(c.r[4])?.address(),0xe000-48);assert_eq!(CrtCpu::pointer(c.r[5])?.address(),0xe000-4);
   // Explicit unproved body boundary: observed EAX/flags are inputs here,
   // never substituted for execution of the full formatter body.
   c.r[0]=CrtValue::scalar(v[5]);c.flags=CrtFlags{cf:Some(v[6]&1!=0),zf:Some(v[6]&64!=0),sf:Some(v[6]&128!=0),of:Some(v[6]&2048!=0)};
   let result=epilog_run(&mut rt,&mut c,e,&mut b)?.known_scalar()?;
   let flags=u32::from(c.flags.cf.unwrap())|u32::from(c.flags.zf.unwrap())*64|u32::from(c.flags.sf.unwrap())*128|u32::from(c.flags.of.unwrap())*2048;
   let delta=CrtCpu::pointer(c.r[4])?.address()-0xe000;
   assert_eq!([result,flags,delta],[v[7],v[8],v[9]]);
   for (i,reg) in [3,5,6,7].into_iter().enumerate(){assert_eq!(c.r[reg].known_scalar()?,v[i+1]);}
   println!("{} {} {} {} {} {} {}",result,flags,delta,v[1],v[2],v[3],v[4]);Ok(())
  }).unwrap();
 }
}

fn file_setup(rt:&mut CrtStreamRuntime,c:&mut CrtCpu)->RegistryResult<CrtPointer>{
 let holders=rt.map_region(0x7000,16,CrtRegionKind::Context,None)?;
 rt.store(holders,32,CrtValue::Pointer(rt.file()))?;
 rt.store(rt.offset(holders,4)?,32,CrtValue::Pointer(rt.file()))?;
 rt.store(rt.offset(holders,8)?,32,CrtValue::scalar(0xfeed))?;
 let sp=CrtCpu::pointer(c.r[4])?;
 for(i,arg)in [CrtValue::Pointer(holders),CrtValue::Pointer(rt.offset(holders,8)?),CrtValue::Pointer(rt.offset(holders,4)?)].into_iter().enumerate(){rt.store(rt.offset(sp,4+i as i64*4)?,32,arg)?;}
 Ok(holders)
}
fn file_scope_normal(){
 for expected in [0,1,93,0x80000000,u32::MAX]{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let previous=r.head;
  let outer=rt.lock(rt.thread).unwrap(); // Recursive acquisition must release only its own level.
  r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let holders=file_setup(&mut rt,&mut c)?;
   let mut b=CrtNormalBinding::bind(&rt,&c,e,file_run_epilog_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   let mut calls=0;
   let value=file_run(&mut rt,&mut c,e,&mut b,|rt,child,lease|{
    calls+=1;rt.check_lock(lease)?;assert_eq!(rt.locks.len(),2);
    assert_eq!(child.r[1],CrtValue::Pointer(rt.offset(holders,8)?));
    let bp=CrtCpu::pointer(child.r[5])?;
    assert_eq!(rt.load(rt.offset(bp,-4)?,32)?.known_scalar()?,0);
    assert_eq!(rt.load(rt.offset(bp,-28)?,32)?.known_scalar()?,0);
    // A real nested native activation must return through its own token
    // without consuming the FILE wrapper or driver continuation.
    let driver_return=child.return_id;
    child.call_activation(rt,0x1234,0,|rt,nested|{
     assert_ne!(nested.return_id,driver_return);rt.check_lock(lease)?;
     rt.store(rt.offset(holders,12)?,32,CrtValue::scalar(expected^0x55))?;
     nested.clobber(CrtValue::scalar(expected));nested.finish(rt)
    })?;
    assert_eq!(child.return_id,driver_return);child.finish(rt)
   })?;
   assert_eq!(value,CrtValue::scalar(expected));assert_eq!(calls,1);
   assert_eq!(rt.load(rt.offset(holders,12)?,32)?.known_scalar()?,expected^0x55);
   assert_eq!(rt.locks,vec![outer]);assert_eq!(e.head()?,previous);
   assert_eq!(c.r[4],CrtValue::Pointer(rt.resolve_absolute(0xe010,CrtRegionKind::Stack)?));
   // Void external unlock does not grant knowledge of volatile flags/registers.
   assert!(c.flags.zf.is_none());assert_eq!(c.r[6],c.entry[6]);Ok(())
  }).unwrap();rt.unlock(outer).unwrap();
 }
}
fn file_scope_failure(){
 for mode in 0..8{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let mut reached=None;
  let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let holders=file_setup(&mut rt,&mut c)?;
   let mut b=CrtNormalBinding::bind(&rt,&c,e,file_run_epilog_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   if mode==0{rt.store(rt.offset(holders,4)?,32,CrtValue::scalar(0))?;}
   if mode==1{rt.lock_objects.clear();}
   file_run(&mut rt,&mut c,e,&mut b,|rt,child,lease|{
    let bp=CrtCpu::pointer(child.r[5])?;let marker=rt.offset(holders,12)?;
    rt.store(marker,32,CrtValue::scalar(123))?;reached=Some(marker);
    match mode{
     2=>return Err("unclosed formatter exception/termination"),
     3=>{rt.store(rt.offset(bp,-4)?,32,CrtValue::scalar((-2i32)as u32))?;},
     4=>{rt.unlock(lease)?;},
     5=>{child.r[0]=CrtValue::scalar(7);return Ok(child.r[0]);}, // no protected RET
     6=>{rt.lock_file(rt.thread,rt.file())?;}, // extra live recursive acquisition
     7=>{rt.store(rt.offset(holders,4)?,32,CrtValue::Pointer(rt.offset(rt.file(),4)?))?;},
     _=>panic!("preflight did not reject"),
    }
    child.r[0]=CrtValue::scalar(7);child.finish(rt)
   }).map(|_|())
  });assert!(result.is_err(),"mode {mode}");assert!(r.available().is_err());
  let f=&r.normal_epoch.as_ref().unwrap().frames[0];assert!(f.installed&&!f.unlinked);
  if let Some(p)=reached{assert_eq!(rt.load(p,32).unwrap().known_scalar().unwrap(),123);}
  if mode==2||mode==3||mode==5{assert_eq!(rt.locks.len(),1);}
  if mode==6||mode==7{
   assert_eq!(rt.locks.len(),if mode==6{2}else{1});
   let level=rt.resolve_absolute(0xdff8,CrtRegionKind::Stack).unwrap();
   // An extra body lock fails before the scope reset; a changed cleanup
   // argument fails inside original cleanup after the reset. Neither retires it.
   assert_eq!(rt.load(level,32).unwrap().known_scalar().unwrap(),if mode==6{0}else{(-2i32)as u32});
   let saved=rt.resolve_absolute(0xdfdc,CrtRegionKind::Stack).unwrap();
   assert_eq!(rt.load(saved,32).unwrap(),CrtValue::Scalar{bits:0xabcd0000,known:0xffff0000});
  }
  if mode==2{let level=rt.resolve_absolute(0xdff8,CrtRegionKind::Stack).unwrap();assert_eq!(rt.load(level,32).unwrap().known_scalar().unwrap(),0);}
 }
}

fn live_dispatch(){
 for mode in 0..30 {
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let outer=m.owned_context;
  let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   rt.store(b.at(&rt,b.layout.level)?,32,CrtValue::scalar(0))?;
   let marker=b.at(&rt,-32)?;rt.store(marker,32,CrtValue::scalar(91))?;
   for arg in [0,0,0,0xe0420042]{c.push(&mut rt,CrtValue::scalar(arg))?;}
   let mut event=CrtNormalException::issue(&mut rt,&mut c,e,&b,raise_site())?;let saved=c.r;
   let record=rt.map_region(0x50000,80,CrtRegionKind::Context,None)?;let context=rt.map_region(0x51000,716,CrtRegionKind::Context,None)?;
   for(offset,value)in [(0,event.code),(4,0),(8,0),(16,0)]{rt.store(rt.offset(record,offset)?,32,CrtValue::scalar(value))?;}
   rt.store(rt.offset(context,0xc4)?,32,CrtValue::scalar(0x9500))?;
   let objects=CrtNormalObjects::bind(&event,&rt,e,record,context)?;
   let mut d=cpu(&mut rt,0xc000,200);let sp=rt.resolve_absolute(0xbfc0,CrtRegionKind::Stack)?;d.r[4]=CrtValue::Pointer(sp);
   for(i,v)in [CrtValue::Pointer(record),CrtValue::Pointer(b.at(&rt,b.layout.record)?),CrtValue::Pointer(context),CrtValue::scalar(0)].into_iter().enumerate(){rt.store(rt.offset(sp,i as i64*4)?,32,v)?;}
   let file=rt.file();let mut lease=None;
   if mode==18||mode==19{
    lease=Some(rt.lock(rt.thread)?);let holder=rt.map_region(0x52000,4,CrtRegionKind::Result,None)?;
    rt.store(holder,32,if mode==19{CrtValue::scalar(0)}else{CrtValue::Pointer(file)})?;
    rt.store(b.at(&rt,12)?,32,CrtValue::Pointer(holder))?;
   }
   rt.map_region(0x415128,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes()))?;
   if mode==20{event.generation+=1;}
   if mode==21{event.frame.generation+=1;}
   if mode==22{rt.memory.release(context.cap,context.owner).map_err(|_|"test release")?;}
   let result=event.execute_context_checked_live_handler(&objects,&mut rt,&c,e,&b,&mut d,0x401900,|view,h|{
    assert!(!(20..=22).contains(&mode),"invalid event/object reached callback");
    if mode==0||mode>=27 {
     // Original PUSH EBP; MOV EBP,ESP; SUB ESP,28 effects. The full
     // original handler prefix and its helper calls remain a separate gate.
     original_handler_prolog(view,h)?;
     let mut pair=CrtHandlerPair::bind(view,h,&objects)?;let old_bx=h.r[3];
     h.r[0]=CrtValue::Pointer(record);h.r[3]=CrtValue::Pointer(b.at(view.rt,b.layout.record)?);
     live_install(&mut pair,view,h)?;let(actual_record,actual_context)=pair.read(view,h)?;
     assert_eq!(view.rt.load(actual_record,32)?.known_scalar()?,0xe0420042);
     assert_eq!(view.rt.load(view.rt.offset(actual_context,0xc4)?,32)?.known_scalar()?,0x9500);
     let filter=pair.call_filter(view,h,0x402300,|borrowed,k,r,c|{
      assert_eq!(borrowed.rt.load(r,32)?.known_scalar()?,0xe0420042);
      assert_eq!(borrowed.rt.load(borrowed.rt.offset(c,0xc4)?,32)?.known_scalar()?,0x9500);
      if mode>=27{
       borrowed.write_u32(-28,95)?;
       if mode==27{borrowed.write_u32(-20,0)?;}
       if mode==28{borrowed.rt.store(borrowed.rt.offset(pair.low,4)?,32,CrtValue::scalar(0))?;}
       if mode==29{borrowed.rt.store(r,32,CrtValue::scalar(0))?;let result=decoded_filter(borrowed,k);assert_eq!(result,Err("live filter event proof boundary"));return result;}
      }
      assert!(pair.read(borrowed,k).is_err()); // child cannot impersonate owner
      if mode==0{assert_eq!(decoded_filter(borrowed,k)?,CrtValue::scalar(1));assert_eq!(borrowed.read_u32(-28)?,0xe0420042);borrowed.write_u32(-28,91)?;}
      else{k.r[0]=CrtValue::scalar(1);}k.finish(borrowed.rt)
     })?;assert_eq!(filter,CrtValue::scalar(1));pair.read(view,h)?;
     if mode==0{
      let rejected=pair.call_filter(view,h,0x402310,|borrowed,k,_,_|{assert_eq!(decoded_false_filter(borrowed,k)?,CrtValue::scalar(0));k.finish(borrowed.rt)})?;
      assert_eq!(rejected,CrtValue::scalar(0));assert_eq!(view.read_u32(-28)?,0xe0420042);view.write_u32(-28,91)?;
     }
     assert!(live_install(&mut pair,view,h).is_err());
     let original_sp=h.r[4];let foreign=runtime(view.epoch.registry);h.r[4]=CrtValue::Pointer(foreign.resolve_absolute(pair.low.address(),CrtRegionKind::Stack)?);
     assert!(pair.read(view,h).is_err(),"foreign stack address accepted");h.r[4]=original_sp;
     let prior=h.return_id;h.return_id+=1;assert!(pair.read(view,h).is_err());h.return_id=prior;
     view.write_u32(-20,0)?;assert!(pair.read(view,h).is_err());view.write(-20,CrtValue::Pointer(pair.low))?;
     h.r[3]=old_bx;h.leave(view.rt)?;assert!(pair.read(view,h).is_err());
     let returned_bp=h.r[5];h.r[5]=CrtValue::Pointer(pair.bp);assert!(pair.read(view,h).is_err());h.r[5]=returned_bp;
    }
    assert_eq!(view.read_u32(-28)?,91);view.write_u32(-28,92)?;
    // A typed alias observes immediate bytes, before callback completion.
    assert_eq!(view.rt.load(marker,32)?.known_scalar()?,92);
    if mode==23{
     assert!(view.call(h,0x401910,|child,_|{child.write_u32(-28,95)?;Err("nested failure cannot be swallowed")}).is_err());
     return Ok(CrtValue::scalar(0));
    }
    if mode==24{h.return_id+=1;return view.call(h,0x401910,|_,_|panic!("foreign activation accepted"));}
    if mode==25{let foreign=runtime(view.epoch.registry);let p=foreign.resolve_absolute(marker.address(),CrtRegionKind::Stack)?;return view.write(-28,CrtValue::Pointer(p)).map(|_|CrtValue::scalar(0));}
    if mode==1{return view.write_u32(-16,0).map(|_|CrtValue::scalar(0));} // predecessor
    if mode==2{return view.write_u32(-32,0).map(|_|CrtValue::scalar(0));} // saved EBX
    if mode==3{return view.write_u32(-27,0).map(|_|CrtValue::scalar(0));} // partial word
    if mode==4{return view.write_u32(i32::MAX,0).map(|_|CrtValue::scalar(0));}
    if mode==5{view.write(-28,CrtValue::Scalar{bits:0x42,known:255})?;return view.read_u32(-28).map(CrtValue::scalar);}
    if mode==6{view.rt.store(b.at(view.rt,b.layout.level)?,32,CrtValue::scalar(7))?;return view.validate().map(|_|CrtValue::scalar(0));}
    if mode==7{view.state.calls=4096;assert!(view.call(h,0x401910,|_,_|panic!("budget bypass")).is_err());h.r[0]=CrtValue::scalar(0);return h.finish(view.rt);}
    if mode==8{view.state.depth=32;return view.call(h,0x401910,|_,_|panic!("depth bypass"));}
    if mode==9{view.write_stack(-20,-28)?;assert_eq!(view.read(-20)?,CrtValue::Pointer(marker));return view.write_u32(-24,0).map(|_|CrtValue::scalar(0));} // saved ESP
    if mode==10{h.r[4]=view.interrupted.r[4];return view.call(h,0x401910,|_,_|panic!("alias bypass"));}
    if mode==11{return view.call(h,0x600000,|_,_|panic!("module bypass"));}
    h.r[0]=CrtValue::Pointer(b.at(view.rt,b.layout.record)?);let ebx=h.r[3];h.r[3]=CrtValue::scalar((-2i32)as u32);
    if mode==12{h.r[0]=CrtValue::Pointer(marker);}
    if mode==26{h.r[0]=CrtValue::scalar(b.at(view.rt,b.layout.record)?.address());}
    if mode==13{h.r[3]=CrtValue::Scalar{bits:0,known:255};}
    original_scope_store(view,h)?;h.r[3]=ebx;
    assert_eq!(view.rt.load(b.at(view.rt,b.layout.level)?,32)?.known_scalar()?,(-2i32)as u32);
    assert_eq!(view.event.dispatch_source(view.rt,view.interrupted,view.epoch,view.binding)?.try_level,-2);
    if mode==14{return view.store_try_level(0,1).map(|_|CrtValue::scalar(0));}
    view.call(h,0x401910,|child,n|{
     assert_eq!(child.state.depth,2);assert_eq!(child.read_u32(-28)?,92);
     n.r[1]=CrtValue::Pointer(b.at(child.rt,b.layout.record)?);n.r[2]=CrtValue::scalar(1);
     permuted_scope_store(child,n)?;child.write_u32(-28,93)?;
     // A deeper cleanup/helper sees both preceding original stores.
     child.call(n,0x401920,|deep,k|{
      assert_eq!(deep.state.depth,3);assert_eq!(deep.read_u32(-28)?,93);
      deep.store_try_level(1,-2)?;deep.write_u32(-28,94)?;
      if mode==15{return Err("independent nested cleanup failure");}
      k.r[0]=CrtValue::scalar(1);k.finish(deep.rt)
     })?;
     n.r[0]=CrtValue::scalar(1);n.finish(child.rt)
    })?;
    assert_eq!(view.state.depth,1);assert_eq!(view.read_u32(-28)?,94);
    if mode==18||mode==19{
     let original_bp=h.r[5];h.r[5]=CrtValue::Pointer(b.at(view.rt,b.layout.bp)?);
     view.call(h,0x404694,|cleanup,k|file_run_cleanup(cleanup.rt,k,file,&mut lease))?;
     h.r[5]=original_bp;assert!(lease.is_none());
    }
    if mode==16{view.rt.store(b.at(view.rt,b.layout.scope_slot)?,32,CrtValue::scalar(0))?;}
    h.r[0]=CrtValue::scalar(1);h.finish(view.rt)
   });
   assert_eq!(c.r,saved);
   if mode==0||mode==17||mode==18{
    let receipt=result?;
    assert_eq!(rt.load(marker,32)?.known_scalar()?,94);assert_eq!(receipt.level,-2);
    if mode==17{rt.store(b.at(&rt,b.layout.level)?,32,CrtValue::scalar(0))?;assert!(event.take_handler_result(receipt,&rt,&c,e,&b).is_err());}
    else {assert_eq!(event.take_handler_result(receipt,&rt,&c,e,&b)?,1);assert!(e.state().is_err());}
   }else if (20..=22).contains(&mode){
    assert!(result.is_err());assert_eq!(event.delivery,CrtNormalDelivery::Pending);assert_eq!(rt.load(marker,32)?.known_scalar()?,91);
   }else{
    assert!(result.is_err(),"mode {mode}");assert_eq!(event.delivery,CrtNormalDelivery::Failed);
    if mode!=5{assert_eq!(rt.load(marker,32)?.known_scalar()?,if mode==23||mode>=27{95}else if mode==15||mode==16||mode==19{94}else{92});}
   }
   if mode==19{rt.check_lock(lease.unwrap())?;}if mode==18{assert!(rt.locks.is_empty());}
   Err::<(),_>("live handler effects still require containment/restoration proof")
  });
  assert!(result.is_err());assert_eq!(m.owned_context,outer);
 }
}

fn pending_normal_exception(){
 for flags in [0u32,1]{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let original=m.owned_context;
  assert_eq!(r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   let lease=rt.lock(rt.thread)?;rt.store(b.at(&rt,b.layout.level)?,32,CrtValue::scalar(0))?;
   let marker=b.at(&rt,-32)?;rt.store(marker,32,CrtValue::scalar(91))?;
   for arg in [0,0,flags,0xe0420042]{c.push(&mut rt,CrtValue::scalar(arg))?;}
   if flags==0{c.flags=CrtFlags::unknown();}
   let call_flags=(c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of);
   let registers=c.r;let before=CrtCpu::pointer(c.r[4])?;
   let pending=CrtNormalException::issue(&mut rt,&mut c,e,&b,raise_site())?;
   pending.validate_pending(&rt,e)?;
   let source=pending.dispatch_source(&rt,&c,e,&b)?;
   assert_eq!(source.try_level,0);assert_eq!(source.record,b.at(&rt,b.layout.record)?.address());
   assert_eq!(source.words.get(&-32),None); // ordinary writes are not promoted to protected metadata
   let flags_before=c.flags;c.flags.cf=Some(!c.flags.cf.unwrap_or(false));
   assert!(pending.dispatch_source(&rt,&c,e,&b).is_err());c.flags=flags_before;
   let reg=c.r[0];c.r[0]=CrtValue::scalar(123);assert!(pending.dispatch_source(&rt,&c,e,&b).is_err());c.r[0]=reg;
   let cookie=rt.resolve_absolute(b.layout.cookie_address,CrtRegionKind::Module)?;
   let value=rt.load(cookie,32)?;rt.store(cookie,32,CrtValue::scalar(0))?;
   assert!(pending.dispatch_source(&rt,&c,e,&b).is_err());rt.store(cookie,32,value)?;
   let scope=b.at(&rt,b.layout.scope_slot)?;let value=rt.load(scope,32)?;
   rt.store(scope,32,CrtValue::scalar(0))?;assert!(pending.dispatch_source(&rt,&c,e,&b).is_err());rt.store(scope,32,value)?;
   let saved=b.at(&rt,-36)?;let value=rt.load(saved,32)?;
   rt.store(saved,32,CrtValue::scalar(123))?;assert!(pending.dispatch_source(&rt,&c,e,&b).is_err());rt.store(saved,32,value)?;
   let issued_return=rt.offset(before,-4)?;let value=rt.tags.remove(&issued_return.address()).unwrap();
   assert!(pending.dispatch_source(&rt,&c,e,&b).is_err());rt.tags.insert(issued_return.address(),value);
   let frame=e.registry.normal_epoch.as_mut().unwrap().frames.last_mut().unwrap();frame.next=1;
   assert!(pending.dispatch_source(&rt,&c,e,&b).is_err());e.registry.normal_epoch.as_mut().unwrap().frames.last_mut().unwrap().next=0;
   pending.dispatch_source(&rt,&c,e,&b)?;
   let foreign=runtime(e.registry);assert!(pending.validate_pending(&foreign,e).is_err());
   let issued_sp=c.r[4];assert!(CrtNormalException::issue(&mut rt,&mut c,e,&b,raise_site()).is_err());assert_eq!(c.r[4],issued_sp);
   assert_eq!(pending.call_registers,registers);assert_eq!(pending.code,0xe0420042);assert_eq!(pending.noncontinuable,flags==1);
   assert_eq!(pending.continuation,0x401806);assert_eq!(c.r[4],CrtValue::Pointer(rt.offset(before,-4)?));
   for reg in [0,1,2,3,5,6,7]{assert_eq!(c.r[reg],registers[reg]);}
   assert_eq!((pending.call_flags.cf,pending.call_flags.zf,pending.call_flags.sf,pending.call_flags.of),call_flags);assert_eq!(rt.load(marker,32)?.known_scalar()?,91);rt.check_lock(lease)?;
   assert!(e.state().is_err());assert!(epilog_run(&mut rt,&mut c,e,&mut b).is_err());
   assert_eq!(rt.locks.len(),1);assert!(e.registry.normal_epoch.as_ref().unwrap().frames[0].installed);
   Err::<(),_>("pending delivery has no containment/dispatch certificate")
  }),Err("normal call suspended for owned exception"));
  assert_eq!(m.owned_context,original);assert!(r.normal_epoch.as_ref().unwrap().pending_exception.is_some());
 }
}
fn pending_handler_activation(){
 for mode in 0..14{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);let context=m.owned_context;
  let result=r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   let marker=b.at(&rt,-32)?;rt.store(marker,32,CrtValue::scalar(91))?;
   for arg in [0,0,0,0xe0420042]{c.push(&mut rt,CrtValue::scalar(arg))?;}
   let mut pending=CrtNormalException::issue(&mut rt,&mut c,e,&b,raise_site())?;
   let registers=c.r;let flags=(c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of);
   let mut dispatcher=cpu(&mut rt,0xc000,200);dispatcher.r[4]=CrtValue::Pointer(rt.resolve_absolute(0xbfc0,CrtRegionKind::Stack)?);
   for i in 0..4{rt.store(rt.offset(CrtCpu::pointer(dispatcher.r[4])?,i*4)?,32,CrtValue::scalar(i as u32))?;}
   if mode==4{dispatcher.r[4]=c.r[4];}
   if mode==6{rt.store(CrtCpu::pointer(dispatcher.r[4])?,32,CrtValue::Scalar{bits:0,known:0xffff})?;}
   let result=pending.execute_handler(&mut rt,&c,e,&b,&mut dispatcher,0x401900,|rt,h|{
    // Explicit native callback cut, with real protected CALL/RET. The marker
    // write must survive both success and rejection; no expected output stub.
    rt.store(marker,32,CrtValue::scalar(92))?;
    if mode==1{return Err("authored handler failure");}
    if mode==2{h.r[3]=CrtValue::scalar(777);}
    if mode==3{rt.store(b.at(rt,b.layout.scope_slot)?,32,CrtValue::scalar(0))?;}
    h.r[0]=if mode==10{CrtValue::Scalar{bits:1,known:0xffff}}else if mode==11{CrtValue::Pointer(marker)}else{CrtValue::scalar(1)};if mode==5{Ok(h.r[0])}else{h.finish(rt)}
   });
   assert_eq!(c.r,registers);assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),flags);
   assert_eq!(rt.load(marker,32)?.known_scalar()?,if mode==4||mode==6{91}else{92});
   if mode==0||mode>=7{
    let mut receipt=result?;if mode!=10&&mode!=11{assert_eq!(receipt.value,CrtValue::scalar(1));}assert_eq!(receipt.frame,pending.frame);
    assert_eq!((receipt.identity,receipt.epoch,receipt.generation),(pending.identity,pending.epoch,pending.generation));
    assert_eq!(pending.delivery,CrtNormalDelivery::Returned);pending.dispatch_source(&rt,&c,e,&b)?;
    assert!(pending.execute_handler(&mut rt,&c,e,&b,&mut dispatcher,0x401900,|_,_|panic!("replayed")).is_err());
    match mode{7=>receipt.generation+=1,8=>receipt.epoch+=1,9=>receipt.identity.owner+=1,
     12=>rt.store(b.at(&rt,b.layout.scope_slot)?,32,CrtValue::scalar(0))?,13=>receipt.frame.generation+=1,_=>{}}
    let receipt_level=receipt.level;let consumed=pending.take_handler_result(receipt,&rt,&c,e,&b);
    if mode==0{assert_eq!(consumed?,1);assert_eq!(pending.delivery,CrtNormalDelivery::ResultTaken);
     let replay=CrtNormalHandlerReturn{identity:pending.identity,epoch:pending.epoch,frame:pending.frame,generation:pending.generation,level:receipt_level,value:CrtValue::scalar(1)};
     assert!(pending.take_handler_result(replay,&rt,&c,e,&b).is_err());
    }else{assert!(consumed.is_err());assert_eq!(pending.delivery,CrtNormalDelivery::Failed);}
   }else{assert!(result.is_err());assert_eq!(pending.delivery,if mode==4||mode==6{CrtNormalDelivery::Pending}else{CrtNormalDelivery::Failed});}
   assert!(e.state().is_err());assert!(epilog_run(&mut rt,&mut c,e,&mut b).is_err());
   Err::<(),_>("component callback is not a disposition/restoration proof")
  });assert!(result.is_err());assert_eq!(m.owned_context,context);
 }
}
fn captured_objects(){
 for mode in 0..7{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);
  assert!(r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   for arg in [0,0,0,0xe0420042]{c.push(&mut rt,CrtValue::scalar(arg))?;}
   let mut event=CrtNormalException::issue(&mut rt,&mut c,e,&b,raise_site())?;
   rt.map_region(0x50000,80,CrtRegionKind::Context,None)?;rt.map_region(0x51000,716,CrtRegionKind::Context,None)?;
   let record=rt.resolve_absolute(0x50000,CrtRegionKind::Context)?;let context=rt.resolve_absolute(0x51000,CrtRegionKind::Context)?;
   for(offset,value)in [(0,0xe0420042),(4,0),(8,0),(16,0)]{rt.store(rt.offset(record,offset)?,32,CrtValue::scalar(value))?;}
   if mode!=1{rt.store(rt.offset(context,0xc4)?,32,CrtValue::scalar(if mode==2{0}else{0x9500}))?;}
   // Captured ESP is deliberately different from the interrupted CALL ESP;
   // all other context bytes remain unknown.
   let objects=CrtNormalObjects::bind(&event,&rt,e,record,if mode==3{record}else{context});
   if (1..=3).contains(&mode){assert!(objects.is_err());return Err("rejected captured input");}
   let objects=objects?;
   rt.map_region(0x415128,4,CrtRegionKind::Module,Some(&0u32.to_le_bytes()))?;
   objects.check_original_context(&event,&rt,e)?;
   let selector=rt.resolve_absolute(0x415128,CrtRegionKind::Module)?;
   rt.store(selector,32,CrtValue::Scalar{bits:0,known:0})?;assert!(objects.check_original_context(&event,&rt,e).is_err());
   rt.store(selector,32,CrtValue::scalar(0x401bf9))?;objects.check_original_context(&event,&rt,e)?;
   assert_ne!(objects.captured_esp,CrtCpu::pointer(c.r[4])?.address());
   assert_eq!(rt.load(context,32)?,CrtValue::Scalar{bits:0,known:0});
   let mut d=cpu(&mut rt,0xc000,200);let sp=rt.resolve_absolute(0xbfc0,CrtRegionKind::Stack)?;d.r[4]=CrtValue::Pointer(sp);
   for(i,value)in [CrtValue::Pointer(record),CrtValue::Pointer(b.at(&rt,b.layout.record)?),CrtValue::Pointer(context),CrtValue::scalar(0)].into_iter().enumerate(){rt.store(rt.offset(sp,i as i64*4)?,32,value)?;}
   if mode==4{rt.store(sp,32,CrtValue::Pointer(context))?;}
   if mode==6{rt.store(selector,32,CrtValue::Scalar{bits:0,known:0})?;}
   let result=event.execute_context_checked_handler(&objects,&mut rt,&c,e,&b,&mut d,0x401900,|rt,h|{
    assert_ne!(mode,6,"unproved selector reached handler body");
    if mode==5{rt.store(rt.offset(context,0xc4)?,32,CrtValue::scalar(0x9600))?;}
    // The existing decoded original helper executes over the same live
    // captured objects immediately before this explicit callback body cut.
    h.r[0]=CrtValue::scalar(1);h.finish(rt)
   });
   if mode==0{let receipt=result?;assert_eq!(event.take_handler_result(receipt,&rt,&c,e,&b)?,1);}else{assert!(result.is_err());}
   assert!(e.state().is_err());Err::<(),_>("captured inputs do not prove OS delivery/resumption")
  }).is_err());
 }
}
fn reject_normal_exception(){
 for mode in 0..10{
  let(m,mut r,main,mut permit)=fixture_with_extra(&[(0x410000,0x420000)]);let mut rt=runtime(&r);
  r.with_normal_calls(&m,&mut permit,&main,|e|{
   let mut c=cpu(&mut rt,0xe000,71);let mut b=CrtNormalBinding::bind(&rt,&c,e,epilog_run_layout())?;start(&mut rt,&mut c,e,&mut b,99)?;
   for arg in [0,0,0,0xe0420042]{c.push(&mut rt,CrtValue::scalar(arg))?;}
   let sp=CrtCpu::pointer(c.r[4])?;
   match mode{0=>rt.store(rt.offset(sp,4)?,32,CrtValue::scalar(2))?,1=>rt.store(rt.offset(sp,8)?,32,CrtValue::scalar(1))?,
    2=>rt.store(sp,32,CrtValue::scalar(0xf0420042))?,3=>rt.store(sp,32,CrtValue::Scalar{bits:0,known:0})?,
    4=>{c.r[4]=CrtValue::Pointer(b.at(&rt,b.layout.low)?);},_=>{}}
   let before=c.r;let generation=rt.generation;
   let mut site=raise_site();
   match mode{5=>site.continuation=0x401805,6=>site.iat=0x8000,7=>site.iat=0x401800,8=>site.iat=0x41ffff,9=>site.iat=0xffff_fffc,_=>{}}
   assert!(CrtNormalException::issue(&mut rt,&mut c,e,&b,site).is_err());
   assert_eq!(c.r,before);assert_eq!(rt.generation,generation);assert!(e.state()?.pending_exception.is_none());
   c.r[4]=CrtValue::Pointer(sp);c.discard(&mut rt,16)?;c.r[0]=CrtValue::scalar(0);epilog_run(&mut rt,&mut c,e,&mut b)?;Ok(())
  }).unwrap();
 }
}
fn main(){match std::env::args().nth(1).unwrap().as_str(){"live"=>live_dispatch(),"objects"=>captured_objects(),"handler"=>pending_handler_activation(),"pending"=>pending_normal_exception(),"pending-reject"=>reject_normal_exception(),"file"=>file_scope_normal(),"file-failure"=>file_scope_failure(),"nested"=>nested_actual(),"mutations"=>mutations(),"consumed"=>consumed_mutation(),"failure"=>body_failure(),"certificate"=>wrong_certificate(),"observed"=>observed(),_=>panic!("case")}}
"#;

fn run(case: &str) {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    let binary = BINARY.get_or_init(|| {
        let (p, epilog_bytes) = if let Ok(path)=std::env::var("W2L_EH4_CODE") {
            let root=std::path::Path::new(&path);
            let bytes=std::fs::read(root.join("helper.bin")).unwrap();
            let p=PrologProof::prove(Region{bytes:&bytes,origin:0x401e60},12,0x41b400,0x41c000,0x402210).unwrap();
            (p,std::fs::read(root.join("epilog.bin")).unwrap())
        }else{(prolog(),epilog_bytes())};
        let e = EpilogProof::prove(Region {bytes:&epilog_bytes,origin:0x404696}, &p).unwrap();
        let file_scope = file_scope(&p).emit_component("file_run").unwrap();
        let memory = include_str!("guest_memory.rs").split("#[cfg(test)]").next().unwrap().replace("//!", "//");
        // Reuse only the explicitly labelled completed-event fixture, not any
        // expected native result or frame projection under test.
        let fixture = emitted_literal(include_str!("thread_registry_normal_tests.rs"))
            .split("fn complete(").next().unwrap().replace("0x408000", "0x41c000");
        let raise = super::normal_frame::NormalRaiseCallProof::prove(&[0xff,0x15,0,0x50,0x41,0],0x401800,0x415000).unwrap().emit_site();
        let context_code=bytes_hex("558bec813d28514100f91b4000741f648b0d180000008b45088b80c40000003b410872053b410476056a0d59cd295dc3");
        let context_proof=crate::handler_context::prove_context_check(&context_code,0x402877,0x415128).unwrap();
        let scope_bytes=match std::env::var("W2L_EH4_CODE") { Ok(path)=>std::fs::read(std::path::Path::new(&path).join("handler-scope-store.bin")).unwrap(), Err(_)=>vec![0x89,0x58,0x0c] };
        let scope_store=super::normal_frame::NormalScopeStoreProof::prove(&scope_bytes,0x402355).unwrap().emit("original_scope_store");
        let permuted_store=super::normal_frame::NormalScopeStoreProof::prove(&[0x89,0x51,0x0c],0x402600).unwrap().emit("permuted_scope_store");
        let handler_bytes=|file:&str,literal:&str|match std::env::var("W2L_EH4_CODE"){Ok(path)=>std::fs::read(std::path::Path::new(&path).join(file)).unwrap(),Err(_)=>bytes_hex(literal)};
        let handler_prolog=super::normal_frame::emit_handler_prolog(&handler_bytes("handler-prolog.bin","558bec83ec1c"),0x402210).unwrap();
        let installer=crate::handler_bridge::prove_installer(&handler_bytes("handler-installer.bin","8945e48b45108945e88d45e48943fc"),0x402263,&crate::handler_bridge::InstallerLayout{handler_start:-28,handler_end:0,owner_start:-48,owner_end:0,writable_handler_words:vec![-28,-24],writable_owner_words:vec![-20]}).unwrap();
        let install=format!("fn live_install(pair:&mut CrtHandlerPair,frame:&mut CrtLiveFrame<'_,'_>,cpu:&mut CrtCpu)->RegistryResult<()>{{ {} }}",installer.live_body());
        let filter=crate::selection::prove_filter(&bytes_hex("8b55ec8b028b08894de48b55e433c081fa420042e00f94c0c3"),0x1333,&crate::selection::FilterLayout{start:-32,end:0,exception_pointers_offset:-20,writable_words:vec![-28]},0xe0420042).unwrap();
        let filter_source=format!("fn decoded_filter(frame:&mut CrtLiveFrame<'_,'_>,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{ {} }}",filter.live_body());
        let false_filter=crate::selection::prove_filter(&bytes_hex("8b55ec8b028b08894de48b55e433c081fa430042e00f94c0c3"),0x1433,&crate::selection::FilterLayout{start:-32,end:0,exception_pointers_offset:-20,writable_words:vec![-28]},0xe0420042).unwrap();
        let false_filter_source=format!("fn decoded_false_filter(frame:&mut CrtLiveFrame<'_,'_>,cpu:&mut CrtCpu)->RegistryResult<CrtValue>{{ {} }}",false_filter.live_body());
        let context_types=crate::handler_context::EMITTED_TYPES;
        let context_check=context_proof.normal_object_check();
        let source = format!("#![allow(dead_code)]\nmod guest_memory{{{memory}}}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{fixture}\n{file_scope}\n{context_types}\n{context_check}\n{scope_store}\n{permuted_store}\n{install}\n{handler_prolog}\n{filter_source}\n{false_filter_source}\nfn raise_site()->CrtNormalRaiseSite{{{{{raise}}}}}\n{CASES}",
            include_str!("linker/unwind_runtime.rs").replace("//!", "//"),
            emitted_literal(include_str!("frame_proof.rs")),emitted_literal(include_str!("thread_registry.rs")),
            crate::crt_stream_runtime::EMITTED_TYPES,crate::crt_stream_cpu::EMITTED_TYPES,
            super::normal_frame::EMITTED_TYPES,p.emit("helper_run").unwrap(),e.emit("epilog_run").unwrap());
        let dir=std::env::temp_dir().join(format!("w2l-normal-native-{}",std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();let file=dir.join("run.rs");
        let binary=dir.join(if cfg!(windows){"run.exe"}else{"run"});let source=source.replace("\r\n","\n");
        if let Ok(path)=std::env::var("W2L_EH4_EVIDENCE") {std::fs::create_dir_all(&path).unwrap();std::fs::write(std::path::Path::new(&path).join("normal-wrapper.rs"),&source).unwrap();}
        std::fs::write(&file,source).unwrap();
        let build=std::process::Command::new("rustc").args(["--edition=2021","-Awarnings"]).arg(&file).arg("-o").arg(&binary).output().unwrap();
        assert!(build.status.success(),"{}",String::from_utf8_lossy(&build.stderr));binary
    });
    let output = std::process::Command::new(binary)
        .arg(case)
        .output()
        .unwrap();
    if case == "observed" {
        if let Ok(path) = std::env::var("W2L_EH4_EVIDENCE") {
            std::fs::write(
                std::path::Path::new(&path).join("normal-wrapper-results.txt"),
                &output.stdout,
            )
            .unwrap();
        }
    }
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn original_prolog_and_epilog_execute_nested_live_registry_lifecycles() {
    run("nested");
}
#[test]
fn actual_storage_unknown_masks_foreign_arenas_and_stale_epochs_reject() {
    run("mutations");
}
#[test]
fn consumed_slot_receipts_require_actual_pop_and_restored_register() {
    run("consumed");
}
#[test]
fn unresolved_body_effects_remain_visible_and_block_completion() {
    run("failure");
}
#[test]
fn emitted_ret_immediate_cannot_use_another_registry_plan() {
    run("certificate");
}
#[test]
fn epilog_wrong_offsets_order_prefixes_and_cleanup_reject() {
    let original = epilog_bytes();
    let p = prolog();
    for (offset, value) in [
        (2, 0xf4),
        (3, 0x65),
        (10, 0x58),
        (11, 0x5e),
        (12, 0x5f),
        (13, 0x59),
        (14, 0x90),
        (16, 2),
        (17, 2),
    ] {
        let mut bytes = original.clone();
        bytes[offset] = value;
        assert!(
            EpilogProof::prove(
                Region {
                    bytes: &bytes,
                    origin: 0x404696
                },
                &p
            )
            .is_err(),
            "mutation {offset}"
        );
    }
    for n in 0..original.len() {
        assert!(EpilogProof::prove(
            Region {
                bytes: &original[..n],
                origin: 0x404696
            },
            &p
        )
        .is_err());
    }
}

#[test]
#[ignore = "requires separately instrumented original Windows wrapper vectors"]
fn original_windows_wrapper_state_matches_native_normal_lifecycle() {
    run("observed");
}

#[test]
fn file_scope_original_lock_cleanup_and_epilog_execute_with_live_registry() {
    run("file");
}
#[test]
fn file_scope_unclosed_body_effects_do_not_synthesize_cleanup_or_return() {
    run("file-failure");
}

#[test]
fn file_scope_certificate_rejects_effect_and_ownership_mutations() {
    let p = prolog();
    let originals=[
        bytes_hex("8365e4008b4508ff30e8beffffff598365fc008b4d0ce8370c00008bf08975e4c745fcfeffffffe8170000008bc68b4df064890d00000000595f5e5bc9c20c00"),
        bytes_hex("8bff558bec8b450883c02050ff154c5041005dc3"),
        bytes_hex("8bff558bec8b450883c02050ff15505041005dc3"),
        bytes_hex("8b4510ff30e893ffffff59c3")];
    let prove = |b: &[Vec<u8>; 4]| {
        super::file_scope::FileScopeProof::prove(
            super::file_scope::Input {
                wrapper: Region {
                    bytes: &b[0],
                    origin: 0x404668,
                },
                lock: Region {
                    bytes: &b[1],
                    origin: 0x404634,
                },
                unlock: Region {
                    bytes: &b[2],
                    origin: 0x404648,
                },
                cleanup: Region {
                    bytes: &b[3],
                    origin: 0x4046ab,
                },
                enter_iat: 0x41504c,
                leave_iat: 0x415050,
                driver: 0x4052ba,
            },
            &p,
        )
    };
    assert!(prove(&originals).is_ok());
    // Independent mutations: initialized local into EH4 metadata, missing
    // activation, premature scope disable, altered callee/cleanup target,
    // partial register source, wrong lock object/ABI and unwind entry as normal.
    for (region, offset, value) in [
        (0, 2, 0xf0),
        (0, 17, 0xfe),
        (0, 32, 0xf0),
        (0, 21, 0x90),
        (0, 10, 0xbf),
        (0, 39, 0x18),
        (0, 27, 0x66),
        (1, 10, 0x24),
        (2, 14, 0x4c),
        (3, 2, 0x0c),
        (3, 6, 0x94),
    ] {
        let mut b = originals.clone();
        b[region][offset] = value;
        assert!(prove(&b).is_err(), "region {region}, offset {offset}");
    }
    for region in 0..4 {
        let mut b = originals.clone();
        b[region].pop();
        assert!(prove(&b).is_err());
    }
    let mut b = originals.clone();
    let n = b[0].len();
    b[0][n - 2] = 0;
    assert!(prove(&b).is_err());
    let mut b = originals.clone();
    b[3].splice(0..0, [0x8b, 0x75, 0xe4]);
    assert!(prove(&b).is_err());
}

#[test]
fn normal_exception_issue_preserves_guest_call_state_and_blocks_normal_cleanup() {
    run("pending");
}
#[test]
fn normal_exception_invalid_arguments_and_continuations_have_no_issue_effect() {
    run("pending-reject");
}

#[test]
fn normal_raise_certificate_requires_exact_original_call_and_disjoint_iat() {
    use super::normal_frame::NormalRaiseCallProof as Proof;
    let bytes = [0xff, 0x15, 0, 0x50, 0x41, 0];
    assert!(Proof::prove(&bytes, 0x401800, 0x415000).is_ok());
    for cut in 0..6 {
        assert!(Proof::prove(&bytes[..cut], 0x401800, 0x415000).is_err());
    }
    for offset in 0..6 {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert!(Proof::prove(&changed, 0x401800, 0x415000).is_err());
    }
    for origin in [0, 0xfffffffc, 0x414ffd, 0x415000, 0x415003] {
        assert!(Proof::prove(&bytes, origin, 0x415000).is_err());
    }
    for iat in [0, 0x415001, 0xfffffffc] {
        assert!(Proof::prove(&bytes, 0x401800, iat).is_err());
    }
    let mut prefixed = vec![0x66];
    prefixed.extend(bytes);
    assert!(Proof::prove(&prefixed, 0x401800, 0x415000).is_err());
}

#[test]
fn suspended_handler_call_returns_owned_receipt_and_preserves_failures() {
    run("handler");
}

#[test]
fn captured_objects_bind_live_handler_arguments_without_inventing_registers() {
    run("objects");
}

#[test]
fn live_handler_storage_nested_calls_and_failure_effects_are_coherent() {
    run("live");
}
#[test]
fn scope_store_decoder_rejects_partial_prefixed_and_unbound_operands() {
    use super::normal_frame::NormalScopeStoreProof as Proof;
    for code in [
        vec![0x66, 0x89, 0x58, 12],
        vec![0x89, 0x58, 8],
        vec![0x89, 0xd8],
        vec![0x89, 0x58, 12, 0x90],
        vec![0x89, 0x18],
        vec![0x89, 0x60, 12],
        vec![0x89, 0x58],
    ] {
        assert!(Proof::prove(&code, 0x402500).is_err());
    }
    assert!(Proof::prove(&[0x89, 0x58, 12], u32::MAX - 1).is_err());
}

#[test]
fn handler_prolog_rejects_changed_allocation_and_truncated_code() {
    for bytes in [
        vec![0x55, 0x8b, 0xec, 0x83, 0xec, 0x18],
        vec![0x55, 0x8b, 0xec],
        vec![0x55, 0x8b, 0xec, 0x83, 0xec, 0x1c, 0x90],
    ] {
        assert!(super::normal_frame::emit_handler_prolog(&bytes, 0x402210).is_err());
    }
}
