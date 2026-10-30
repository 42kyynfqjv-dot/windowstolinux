//! Independent instruction and emitted-runtime completion checks. Synthetic
//! owned frames below are test fixtures, not Windows startup evidence.
use super::{frame_memory, frame_proof, main_completion};
use std::collections::{BTreeMap, BTreeSet};

const ORIGIN: u32 = 0x22000;
const PRINT: u32 = 0x28000;
const FORMAT: u32 = 0x30000;
const SECURITY: u32 = 0x31000;
fn layout() -> main_completion::Layout {
    main_completion::Layout {
        words: BTreeMap::from([
            (-40, main_completion::Word::Stack),
            (-44, main_completion::Word::Scalar),
        ]),
        esp: -64,
        saved: BTreeMap::from([(-60, 7), (-56, 6), (-52, 3), (0, 5)]),
        guards: BTreeSet::from([-64]),
        predecessor: -16,
    }
}
fn bindings() -> main_completion::Bindings {
    main_completion::Bindings {
        module_base: 0x10000,
        module_size: 0x30000,
        globals: BTreeMap::new(),
        printf: PRINT,
        format: FORMAT,
        security_check: SECURITY,
    }
}
fn call(code: &mut Vec<u8>, target: u32) {
    code.push(0xe8);
    code.extend(
        target
            .wrapping_sub(ORIGIN + code.len() as u32 + 4)
            .to_le_bytes(),
    );
}
fn instructions(clobber_saved: bool) -> Vec<u8> {
    // First argument changes actual ESP. The subsequent equality must observe
    // that changed value, rather than the initial frame SP retained by storage.
    let mut code = vec![
        0x6a, 1, 0x8b, 0xcc, 0x33, 0xc0, 0x3b, 0x4d, 0xd8, 0x0f, 0x94, 0xc0, 0x50, 0x68,
    ];
    code.extend(FORMAT.to_le_bytes());
    call(&mut code, PRINT);
    code.extend([
        0x83, 0xc4, 12, 0xb8, 7, 0, 0, 0, 0x8b, 0x4d, 0xf0, 0x64, 0x89, 0x0d, 0, 0, 0, 0, 0x59,
        0x5f, 0x5e, 0x5b,
    ]);
    if clobber_saved {
        code.extend([0xbb, 0, 0, 0, 0]);
    }
    code.extend([0x8b, 0x4d, 0xc0, 0x33, 0xcd]);
    call(&mut code, SECURITY);
    code.extend([0x8b, 0xe5, 0x5d, 0xc3]);
    code
}
fn source() -> String {
    source_for(&instructions(false), 2, 16)
}
fn source_for(code: &[u8], arguments: usize, scratch: u32) -> String {
    let proof = main_completion::prove(code, ORIGIN, &layout(), &bindings()).unwrap();
    assert_eq!(proof.argument_count, arguments);
    assert_eq!(proof.temporary_bytes(), scratch);
    format!(
        r#"
{frame}
{memory}
{types}
fn image()->FrameImage<&'static str>{{
 let entry_sp=0x9000;let ebp=0x8ffc;let cookie=0x12345678;
 let words=std::collections::BTreeMap::from([
 (-68,FrameWord::Guard{{frame:ebp,cookie,bits:ebp^cookie}}),
 (-64,FrameWord::Saved(7,Some(0x77777777))),(-60,FrameWord::Saved(6,None)),(-56,FrameWord::Saved(3,Some(0x33333333))),
 (-48,FrameWord::Scalar(0)),(-44,FrameWord::StackAddress(0x8fbc)),
 (-20,FrameWord::Borrowed("incoming-owned-predecessor")),(-16,FrameWord::Scalar(0x25000)),
 (-12,FrameWord::EncodedScope{{scope:0x29000,cookie,bits:0x29000^cookie}}),(-8,FrameWord::Scalar((-2i32)as u32)),
 (-4,FrameWord::Saved(5,None)),(0,FrameWord::Return),
 ]);
 FrameImage{{words,entry_sp,ebp,esp:0x8fbc,record:0x8fec,scope_va:0x29000,handler_va:0x25000,try_level:-2}}
}}
fn complete(image:&mut FrameImage<&'static str>,mut printf:impl FnMut(PrintRequest<'_>)->Result<Option<u32>,&'static str>,mut effects:impl FnMut(CompletionEffect<'_,&'static str>)->Result<(),&'static str>)->Result<CompletionOutcome<&'static str>,&'static str>{{
 let memory=&mut FrameMemory::new(image,7,&[-40,-44])?;let globals:&mut[u32]=&mut [];let cookie=0x12345678u32;{body}
}}
fn effect_name(effect:CompletionEffect<'_,&'static str>)->String{{
 match effect{{
 CompletionEffect::RestorePredecessor(p)=>{{assert_eq!(*p,"incoming-owned-predecessor");"unlink".into()}},
 CompletionEffect::Pop{{offset,register,saved,guard}}=>format!("pop:{{offset}}:{{register}}:{{saved:?}}:{{guard}}"),
 CompletionEffect::Cookie{{offset,frame,cookie,bits,target}}=>{{assert_eq!((offset,frame,cookie,bits,target),(-64,0x8ffc,0x12345678,0x1234d984,{security}));"cookie".into()}},
 CompletionEffect::Return{{offset,value,saved,caller_sp}}=>{{assert_eq!((offset,value,caller_sp),(4,7,0x9004));assert_eq!(saved[3],Some(0x33333333));assert_eq!(saved[5],None);assert_eq!(saved[6],None);assert_eq!(saved[7],Some(0x77777777));"return".into()}},
 }}
}}
"#,
        frame = frame_proof::EMITTED_TYPES,
        memory = frame_memory::EMITTED_TYPES,
        types = main_completion::EMITTED_TYPES,
        body = proof.source(),
        security = SECURITY
    )
}
fn run(source: String, name: &str) {
    let dir = std::env::temp_dir().join(format!("w2l-main-review-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let rust = dir.join("check.rs");
    let exe = dir.join(if cfg!(windows) { "check.exe" } else { "check" });
    std::fs::write(&rust, source).unwrap();
    let built = std::process::Command::new("rustc")
        .args(["--edition=2021", "-Awarnings"])
        .arg(&rust)
        .arg("-o")
        .arg(&exe)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let result = std::process::Command::new(&exe).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn actual_temporary_sp_and_ignored_output_failure_preserve_original_return() {
    run(
        source()
            + r#"
fn main(){
 for result in [Some(2u32),Some(0xffffffff),None]{
  let mut image=image();let trace=std::cell::RefCell::new(Vec::<String>::new());let bytes=std::cell::RefCell::new(Vec::<u8>::new());
  let returned=complete(&mut image,|request|{assert_eq!(request.target,0x28000);assert_eq!(request.format,0x30000);assert_eq!(request.arguments,&[0,1]);trace.borrow_mut().push("print".into());bytes.borrow_mut().extend_from_slice(b"prefix");Ok(result)},|effect|{trace.borrow_mut().push(effect_name(effect));Ok(())}).unwrap();
  assert_eq!(returned.value,7);assert_eq!(returned.caller_sp,0x9004);assert_eq!(returned.predecessor,"incoming-owned-predecessor");assert_eq!(&*bytes.borrow(),b"prefix");
  assert_eq!(&*trace.borrow(),&["print","unlink","pop:-64:1:None:true","pop:-60:7:Some(2004318071):false","pop:-56:6:None:false","pop:-52:3:Some(858993459):false","cookie","pop:0:5:None:false","return"]);
 }
}
"#,
        "stack-and-output",
    );
}
#[test]
fn corrupted_saved_return_and_effect_failures_keep_prior_observable_order() {
    run(
        source()
            + r#"
fn main(){
 for fault in ["saved","return","guard","cookie-effect","return-effect","output-effect"]{
  let mut image=image();match fault{"saved"=>{image.words.insert(-64,FrameWord::Saved(6,Some(0x77777777)));},"return"=>{image.words.insert(0,FrameWord::Scalar(0x22000));},"guard"=>{image.words.insert(-68,FrameWord::Guard{frame:0x8ffc,cookie:0x12345678,bits:0});},_=>{}}
  let trace=std::cell::RefCell::new(Vec::<String>::new());
  let result=complete(&mut image,|_|{trace.borrow_mut().push("print-prefix".into());if fault=="output-effect"{Err("unclosed output provider")}else{Ok(Some(0xffffffff))}},|effect|{let name=effect_name(effect);trace.borrow_mut().push(name.clone());if (fault=="cookie-effect"&&name=="cookie")||(fault=="return-effect"&&name=="return"){Err("injected owned effect rejection")}else{Ok(())}});
  assert!(result.is_err(),"{fault}");let trace=trace.borrow();assert_eq!(trace[0],"print-prefix");
  if fault=="output-effect"{assert_eq!(trace.len(),1);}else{assert_eq!(trace[1],"unlink");}
  if matches!(fault,"saved"|"return"|"guard"|"cookie-effect"){assert!(!trace.iter().any(|s|s=="return"),"{fault}");}
  if fault=="guard"{assert_eq!(trace.len(),6);assert!(trace[2].starts_with("pop:-64:1:"));}
 }
}
"#,
        "epilog-failures",
    );
}
#[test]
fn overwritten_saved_register_and_wrong_fs_or_return_forms_reject_before_emission() {
    assert!(main_completion::prove(&instructions(true), ORIGIN, &layout(), &bindings()).is_err());
    let mut wrong = instructions(false);
    let at = wrong
        .windows(3)
        .position(|b| b == [0x8b, 0x4d, 0xf0])
        .unwrap();
    wrong[at + 2] = 0xd4;
    assert!(main_completion::prove(&wrong, ORIGIN, &layout(), &bindings()).is_err());
    let mut wrong = instructions(false);
    let last = wrong.len() - 1;
    wrong[last] = 0xc2;
    wrong.extend([4, 0]);
    assert!(main_completion::prove(&wrong, ORIGIN, &layout(), &bindings()).is_err());
}

#[test]
fn original_varargs_and_main_return_survive_immediate_and_deferred_output_failure() {
    let mut code = Vec::new();
    for value in [u32::MAX, 0x8000_0000, u32::MAX, FORMAT] {
        code.push(0x68);
        code.extend(value.to_le_bytes());
    }
    call(&mut code, PRINT);
    code.extend([
        0x83, 0xc4, 16, 0xb8, 7, 0, 0, 0, 0x8b, 0x4d, 0xf0, 0x64, 0x89, 0x0d, 0, 0, 0, 0, 0x59,
        0x5f, 0x5e, 0x5b, 0x8b, 0x4d, 0xc0, 0x33, 0xcd,
    ]);
    call(&mut code, SECURITY);
    code.extend([0x8b, 0xe5, 0x5d, 0xc3]);
    let format = b"%lu,%ld,%d\n\0";
    assert_eq!(
        super::stdio_effect::prove_format(format)
            .unwrap()
            .arguments(),
        3
    );
    let mut source = source_for(&code, 3, 20);
    source.push_str(super::stdio_effect::EMITTED_TYPES);
    source.push_str(r#"
fn main(){
 let expected=b"4294967295,-2147483648,-1\r\n";
 for policy in [OutputPolicy::ImmediateProjection,OutputPolicy::Deferred]{
  for limit in [0usize,10,25,26,27]{
   let mut image=image();let mut state=OwnedStdio::new(7,0x35000,0x36000,[0x24,0],policy).unwrap();let bytes=std::cell::RefCell::new(Vec::<u8>::new());let count=std::cell::Cell::new(None);
   let mut sink=|data:&[u8]|->std::io::Result<usize>{let mut out=bytes.borrow_mut();if out.len()>=limit{return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));}let n=data.len().min(limit-out.len()).min(3);out.extend_from_slice(&data[..n]);Ok(n)};
   let returned=complete(&mut image,|request|{assert_eq!(request.arguments,&[0xffffffff,0x80000000,0xffffffff]);let result=state.write(7,b"%lu,%ld,%d\n\0",request.arguments,&mut sink)?;count.set(result.word());Ok(result.word())},|effect|{effect_name(effect);Ok(())}).unwrap();
   assert_eq!(returned.value,7);
   if policy==OutputPolicy::Deferred{assert!(bytes.borrow().is_empty());assert_eq!(count.get(),Some(26));assert_eq!(state.pending_bytes(),expected);assert_eq!(state.flush(7,&mut sink).unwrap(),if limit<27{FlushResult::Failure}else{FlushResult::Success});assert_eq!(returned.value,7);assert_eq!(count.get(),Some(26));}
   else{assert_eq!(count.get(),if limit<27{None}else{Some(26)});}
   assert_eq!(&*bytes.borrow(),&expected[..limit]);assert_eq!(state.written_bytes(),limit);assert!(state.pending_bytes().is_empty());assert_eq!(state.stream_error,limit<27);
  }
 }
}
"#);
    run(source, "varargs-stdio-failure");
}
