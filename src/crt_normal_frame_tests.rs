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
    rt.store(rt.offset(holders,12)?,32,CrtValue::scalar(expected^0x55))?;
    child.clobber(CrtValue::scalar(expected));child.finish(rt)
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
 for mode in 0..6{
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
     _=>panic!("preflight did not reject"),
    }
    child.r[0]=CrtValue::scalar(7);child.finish(rt)
   }).map(|_|())
  });assert!(result.is_err(),"mode {mode}");assert!(r.available().is_err());
  let f=&r.normal_epoch.as_ref().unwrap().frames[0];assert!(f.installed&&!f.unlinked);
  if let Some(p)=reached{assert_eq!(rt.load(p,32).unwrap().known_scalar().unwrap(),123);}
  if mode==2||mode==3||mode==5{assert_eq!(rt.locks.len(),1);}
  if mode==2{let level=rt.resolve_absolute(0xdff8,CrtRegionKind::Stack).unwrap();assert_eq!(rt.load(level,32).unwrap().known_scalar().unwrap(),0);}
 }
}
fn main(){match std::env::args().nth(1).unwrap().as_str(){"file"=>file_scope_normal(),"file-failure"=>file_scope_failure(),"nested"=>nested_actual(),"mutations"=>mutations(),"consumed"=>consumed_mutation(),"failure"=>body_failure(),"certificate"=>wrong_certificate(),"observed"=>observed(),_=>panic!("case")}}
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
        let source = format!("#![allow(dead_code)]\nmod guest_memory{{{memory}}}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{fixture}\n{file_scope}\n{CASES}",
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
