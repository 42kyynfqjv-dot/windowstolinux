//! Original cookie stores on canonical image storage. Entropy acquisition is
//! deliberately unresolved; a supplied established cookie is not its producer.
use crate::crt_stream_ir::{Graph, Target};
pub(crate) const CODE:&str="8b0d00c041005657bf4ee640bbbe0000ffff3bcf740485ce7526e894ffffff8bc83bcf7507b94fe640bbeb0e85ce750a0d11470000c1e0100bc8890d00c04100f7d15f890d40c041005ec3";
pub(crate) fn source(bytes: &[u8]) -> Result<String, String> {
    lower(bytes, false)
}
pub(crate) fn connected_source(bytes: &[u8]) -> Result<String, String> {
    lower(bytes, true)
}
fn lower(bytes: &[u8], connected: bool) -> Result<String, String> {
    let expected: Vec<u8> = CODE
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    if bytes != expected {
        return Err("cookie initializer original code binding".into());
    }
    let graph = Graph::decode(bytes, 0x401b71)?;
    let body = crate::crt_stream_emit::emit_body(
        &graph,
        |pc, target| {
            if pc != 0x401b8b || target != Target::Direct(0x401b24) {
                return Err("cookie initializer call binding".into());
            }
            Ok(if connected {
                "cpu.call_activation(rt,0x401b90,0,|rt,c|cookie_entropy(rt,c,inputs,backend))?;"
            } else {
                "return Err(\"cookie entropy producer unbound\");"
            }
            .into())
        },
        &std::collections::BTreeMap::from([
            (0x41c000, "CrtRegionKind::Module".into()),
            (0x41c040, "CrtRegionKind::Module".into()),
        ]),
        128,
    )?;
    let name = if connected {
        "original_cookie_init_connected"
    } else {
        "original_cookie_init"
    };
    let params = if connected {
        ",inputs:&CrtEntropyInputs,backend:&mut impl CrtEntropyBackend"
    } else {
        ""
    };
    Ok(format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu{params})->Result<CrtValue,&'static str>{{cpu.validate_active(rt)?;let token=rt.main_image.ok_or(\"cookie process image missing\")?;let p=rt.process_image_pointer(token,0x401b71,75)?;if rt.memory.read(p.address(),75).map_err(|_|\"cookie code lifetime\")?!=&{bytes:?}{{return Err(\"cookie live code changed\");}}{body}}}"))
}
#[test]
fn cookie_initializer_binds_every_original_byte_and_retains_entropy_rejection() {
    let code = crate::crt_ptd::raw(CODE);
    let text = source(&code).unwrap();
    assert!(text.contains("cookie entropy producer unbound"));
    for i in 0..code.len() {
        let mut mutant = code.clone();
        mutant[i] ^= 1;
        assert!(source(&mutant).is_err(), "changed cookie code {i}");
    }
}

/// Component inputs retain their explicit acquisition premise. The constructor
/// validates owner/lifetime; it does not establish OS ID uniqueness or entropy.
pub(crate) const ENTROPY_CODE:&str="558bec83ec148d45f40f57c050660f1345f4ff152c5041008b45f83345f48945fcff15285041003145fcff15245041003145fc8d45ec50ff15205041008b45f08d4dfc3345ec3345fc33c1c9c3";
pub(crate) const IMPORTS: [(u32, &str); 4] = [
    (0x41502c, "GetSystemTimeAsFileTime"),
    (0x415028, "GetCurrentThreadId"),
    (0x415024, "GetCurrentProcessId"),
    (0x415020, "QueryPerformanceCounter"),
];
pub(crate) fn entropy_source(
    bytes: &[u8],
    imports: &[(u32, String, String)],
) -> Result<String, String> {
    let expected: Vec<u8> = ENTROPY_CODE
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    if bytes != expected {
        return Err("cookie entropy original code binding".into());
    }
    if imports.len() != 4
        || IMPORTS.iter().any(|(at, name)| {
            imports
                .iter()
                .filter(|(a, d, n)| a == at && d.eq_ignore_ascii_case("kernel32.dll") && n == name)
                .count()
                != 1
        })
    {
        return Err("cookie entropy original import binding".into());
    }
    let graph = Graph::decode(bytes, 0x401b24)?;
    let body = crate::crt_stream_emit::emit_body(
        &graph,
        |pc, target| {
            let (iat, pop, kind) = match pc {
                0x401b36 => (0x41502c, 4, 0),
                0x401b45 => (0x415028, 0, 1),
                0x401b4e => (0x415024, 0, 2),
                0x401b5b => (0x415020, 4, 3),
                _ => return Err("cookie entropy call site".into()),
            };
            if target != Target::Import(iat) {
                return Err("cookie entropy call target".into());
            }
            Ok(format!(
                "cpu.call_activation(rt,{}, {pop},|rt,c|entropy_api(rt,c,inputs,backend,{kind}))?;",
                pc + 6
            ))
        },
        &Default::default(),
        128,
    )?;
    let native = crate::crt_cookie_native::TYPES;
    Ok(format!("{ENTROPY_TYPES}\n{native}\nfn cookie_entropy(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,backend:&mut impl CrtEntropyBackend)->Result<CrtValue,&'static str>{{cpu.validate_active(rt)?;inputs.validate(rt)?;let p=rt.process_image_pointer(inputs.image,0x401b24,77)?;if rt.memory.read(p.address(),77).map_err(|_|\"cookie entropy code lifetime\")?!=&{bytes:?}{{return Err(\"cookie entropy live code changed\");}}{body}}}"))
}
const ENTROPY_TYPES: &str = r#"
struct CrtEntropyInputs{init:CrtInitialization,image:CrtProcessImage,owner:u64,thread:u64,process_id:u32,thread_id:u32}
impl CrtEntropyInputs{
 fn bind(rt:&CrtStreamRuntime,init:CrtInitialization,process_id:u32,thread_id:u32)->Result<Self,&'static str>{
  rt.initialization(init)?;if process_id==0||thread_id==0{return Err("entropy identifier input");}
  let image=rt.main_image.ok_or("entropy main image authority")?;rt.process_image(image)?;
  Ok(Self{init,image,owner:rt.owner,thread:rt.thread,process_id,thread_id})
 }
 fn validate(&self,rt:&CrtStreamRuntime)->Result<(),&'static str>{
  rt.initialization(self.init)?;rt.process_image(self.image)?;
  if rt.owner!=self.owner||rt.thread!=self.thread{return Err("entropy process/thread identity");}Ok(())
 }
}
trait CrtEntropyBackend{
 fn validate(&self,_rt:&CrtStreamRuntime,_inputs:&CrtEntropyInputs)->Result<(),&'static str>{Ok(())}
 // Independently acquired observations, never an expected cookie/result.
 fn filetime(&mut self)->Result<u64,&'static str>;
 // The bounded profile requires a valid successful QPC result. An acquisition
 // failure rejects; it does not simulate Windows returning FALSE unchanged.
 fn counter(&mut self)->Result<u64,&'static str>;
}
fn entropy_api(rt:&mut CrtStreamRuntime,c:&mut CrtCpu,inputs:&CrtEntropyInputs,backend:&mut impl CrtEntropyBackend,kind:u8)->Result<CrtValue,&'static str>{
 c.validate_active(rt)?;inputs.validate(rt)?;backend.validate(rt,inputs)?;
 let result=match kind{
  0|3=>{
   let sp=CrtCpu::pointer(c.r[4])?;let p=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;let bp=CrtCpu::pointer(c.r[5])?;
   rt.identity_range(bp,4)?;
   if p.cap!=sp.cap||bp.cap!=sp.cap||p.owner!=sp.owner||p.address()<sp.address().checked_add(8).ok_or("entropy stack overflow")?||u64::from(p.address())+8>u64::from(bp.address()){return Err("entropy output is not an owned local pair");}
   rt.validate_stack_pair(p)?;
   let bits=if kind==0{backend.filetime()?}else{backend.counter()?};
   rt.store_stack_pair(p,[CrtValue::scalar(bits as u32),CrtValue::scalar((bits>>32)as u32)])?;
   // VOID has no result; QPC promises nonzero, not the exact value 1.
   // No admitted caller observes these bits. Keep conservative unknowns.
   CrtValue::Scalar{bits:0,known:0}
  },
  1=>CrtValue::scalar(inputs.thread_id),2=>CrtValue::scalar(inputs.process_id),_=>return Err("entropy API kind")
 };
 rt.last_os_error=None;c.clobber(result);c.finish_pop(rt,if kind==0||kind==3{4}else{0})
}
"#;

#[test]
fn entropy_code_and_imports_bind_independently_and_reject_changed_effects() {
    let bytes = crate::crt_ptd::raw(ENTROPY_CODE);
    let imports: Vec<_> = IMPORTS
        .iter()
        .map(|(a, n)| (*a, "kernel32.dll".to_string(), n.to_string()))
        .collect();
    entropy_source(&bytes, &imports).expect("original entropy instructions lower");
    for i in 0..bytes.len() {
        let mut m = bytes.clone();
        m[i] ^= 1;
        assert_eq!(
            entropy_source(&m, &imports).unwrap_err(),
            "cookie entropy original code binding"
        );
    }
    for i in 0..4 {
        for mode in 0..3 {
            let mut m = imports.clone();
            match mode {
                0 => m[i].0 += 4,
                1 => m[i].1 = "foreign.dll".into(),
                _ => m[i].2.push('_'),
            };
            assert_eq!(
                entropy_source(&bytes, &m).unwrap_err(),
                "cookie entropy original import binding"
            );
        }
    }
}

#[test]
fn scalar_vector_store_preserves_flags_unknowns_and_preflights_both_words() {
    let mut extra = String::new();
    for n in [0u8, 3, 7] {
        let code = [
            0x0f,
            0x57,
            0xc0 + n * 9,
            0x66,
            0x0f,
            0x13,
            0x02 + n * 8,
            0xc3,
        ];
        let graph = Graph::decode(&code, 0x450000).unwrap();
        let body = crate::crt_stream_emit::emit_body(
            &graph,
            |_, _| Err("unexpected vector call".into()),
            &Default::default(),
            8,
        )
        .unwrap();
        extra.push_str(&format!("fn vector_{n}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}"));
    }
    for bad in [
        vec![0x0f, 0x57, 0xc1, 0xc3],
        vec![0xf3, 0x0f, 0x57, 0xc0, 0xc3],
        vec![0x66, 0x0f, 0x12, 0x02, 0xc3],
    ] {
        assert!(Graph::decode(&bad, 0x450000).is_err());
    }
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
for (n,run) in [(0,vector_0 as fn(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>),(3,vector_3),(7,vector_7)]{for mode in 0..8{
 let mut rt=CrtStreamRuntime::new(7,9,0x8000,8192).unwrap();let stack=rt.map_region(0x9000,256,CrtRegionKind::Stack,None).unwrap();let p=rt.offset(stack,32).unwrap();let q=rt.offset(p,4).unwrap();rt.store(p,32,CrtValue::scalar(0x11223344)).unwrap();
 let sp=rt.offset(stack,200).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut c=CrtCpu::new(sp,1).unwrap();c.r[2]=CrtValue::Pointer(p);c.flags=CrtFlags{cf:Some(true),zf:Some(false),sf:Some(true),of:Some(true)};
 if mode==1{c.r[2]=CrtValue::Pointer(rt.subrange(p,4).unwrap());}
 if mode==2{rt.store(q,32,CrtValue::ProtectedReturn(99)).unwrap();}
 if mode==3{rt.store(q,32,CrtValue::Pointer(p)).unwrap();}
 if mode==4{rt.memory.release(stack.cap,stack.owner).unwrap();}
 if mode==5{rt.store_stack_pair(p,[CrtValue::Scalar{bits:0x78,known:255},CrtValue::Scalar{bits:0x12340000,known:0xffff0000}]).unwrap();assert_eq!(CrtCpu::bits(rt.load(p,32).unwrap()).unwrap(),(0x78,255));assert_eq!(CrtCpu::bits(rt.load(q,32).unwrap()).unwrap(),(0x12340000,0xffff0000));}
 if mode==6{assert_eq!(rt.store_stack_pair(p,[CrtValue::scalar(0),CrtValue::Pointer(p)]),Err("CRT scalar pair value type"));assert_eq!(rt.load(p,32).unwrap(),CrtValue::scalar(0x11223344));}
 if mode==7{let cap=rt.memory.map(0x7000,8,stack.owner,guest_memory::Permissions::READ,true).unwrap();let ro=CrtPointer{cap,owner:stack.owner,base:0x7000,size:8,address:0x7000,kind:CrtRegionKind::Stack};rt.regions.push(CrtRegion{pointer:ro,heap:false,file_owner:None});c.r[2]=CrtValue::Pointer(ro);}
 let got=run(&mut rt,&mut c);
 if (1..=4).contains(&mode)||mode==7{assert_eq!(got,Err(match mode{1=>"CRT pointer complete range/identity",2|3=>"CRT scalar pair role/typed alias",4=>"CRT pointer lifetime",7=>"CRT scalar pair permission",_=>unreachable!()}));if mode!=4{assert_eq!(rt.load(p,32).unwrap(),CrtValue::scalar(0x11223344));}assert!(!c.returned);}
 else{got.expect("valid original vector store returns");assert!(c.returned);assert_eq!(rt.load(p,32).unwrap(),CrtValue::scalar(0));assert_eq!(rt.load(q,32).unwrap(),CrtValue::scalar(0));}
 assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(Some(true),Some(false),Some(true),Some(true)));assert_eq!(c.xmm[n],[CrtValue::scalar(0);4]);
 c.clobber(CrtValue::scalar(0));assert!(c.xmm.iter().flatten().all(|v|*v==CrtValue::Scalar{bits:0,known:0}));
}}
"#,
        "scalar-vector-pair",
    );
}

#[test]
fn low_vector_store_uses_actual_payload_without_observing_high_lanes() {
    let mut extra = String::new();
    for n in [0u8, 3, 7] {
        let code = [0x66, 0x0f, 0x13, 0x02 + n * 8, 0xc3];
        let graph = Graph::decode(&code, 0x450000).unwrap();
        let body = crate::crt_stream_emit::emit_body(
            &graph,
            |_, _| Err("no calls".into()),
            &Default::default(),
            4,
        )
        .unwrap();
        extra.push_str(&format!("fn payload_{n}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}"));
    }
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
for(n,run)in [(0,payload_0 as fn(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>),(3,payload_3),(7,payload_7)]{for mode in 0..3{
 let mut rt=CrtStreamRuntime::new(7,9,0x8000,8192).unwrap();let stack=rt.map_region(0x9000,256,CrtRegionKind::Stack,None).unwrap();let p=rt.offset(stack,32).unwrap();let sp=rt.offset(stack,200).unwrap();rt.store(p,32,CrtValue::scalar(99)).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(1)).unwrap();let mut c=CrtCpu::new(sp,1).unwrap();c.r[2]=CrtValue::Pointer(p);
 c.xmm[n]=[CrtValue::scalar(0x12345678),CrtValue::scalar(0x90abcdef),CrtValue::Scalar{bits:0,known:0},CrtValue::Scalar{bits:0,known:0}];
 if mode==1{c.xmm[n][0]=CrtValue::Scalar{bits:0x78,known:255};c.xmm[n][1]=CrtValue::Scalar{bits:0x12340000,known:0xffff0000};}
 if mode==2{c.xmm[n][1]=CrtValue::Pointer(p);}
 let prior=c.xmm;let got=run(&mut rt,&mut c);
 if mode==2{assert_eq!(got,Err("CRT scalar pair value type"));assert_eq!(rt.load(p,32).unwrap(),CrtValue::scalar(99));}
 else{got.expect("MOVLPD must preserve actual low payload");assert_eq!(rt.load(p,32).unwrap(),prior[n][0]);assert_eq!(rt.load(rt.offset(p,4).unwrap(),32).unwrap(),prior[n][1]);}
 assert_eq!(c.xmm,prior);assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(None,None,None,None));
}}
"#,
        "vector-low-payload",
    );
}
