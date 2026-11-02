//! Original onexit routing and registered append prefix; no encoded pointer retagging.
use crate::crt_stream_ir::{Graph, Node, Op, Target};
use std::collections::BTreeMap;
pub(crate) const SCOPE: &str = "feffffff00000000d4ffffff00000000feffffff00000000ac72400000000000";
pub(crate) const ATEXIT: &str = "558becff7508e8c7fffffff7d8591bc0f7d8485dc3";
pub(crate) const COMMON: &str =
    "558bec833d88cc4100ffff75087507e8b3590000eb0b6888cc4100e8245a0000595933c985c00f444d088bc15dc3";
pub(crate) const GLOBAL: &str = "8bff558becff75086888ce4100e86b00000059595dc3";
pub(crate) const WRAPPER: &str = "8bff558bec83ec148d45088945ec8d4dff6a028d450c8945f0588945f88945f48d45f8508d45ec508d45f450e80afdffffc9c3";
pub(crate) const MANAGER: &str = "6a0c6800b54100e8f4abffff8365e4008b4508ff30e8554b0000598365fc008b4d0ce8340000008bf08975e4c745fcfeffffffe8170000008bc68b4df064890d00000000595f5e5bc9c20c00";
pub(crate) const CLEANUP: &str = "8b4510ff30e85e4b000059c3";
pub(crate) const BODY: &str = "8bff558bec83ec0c5356578bf9897df48b078b3085f60f84ef000000a100c041008bc88b1683e11f8b5e0433d08b760833d833f0d3cad3cbd3ce8955fc3bde0f85880000002bf2b800020000c1fe023bf08bfe6a200f47f803fe580f44f83bfe721f6a045752e82a5500008bd86a00895df8e81e0a000083c41085db75228b55fc6a048d7e045752e8085500006a008bd88945f8e8fc09000083c41085db746b8b45f8895dfc8d1cb38d34b833c08bce2bcb83c103c1e9023bde0f47c885c97409a100c041008bfbf3ab8b7df48b4704ff30e8d0f9ffffff75fc8903e8c6f9ffff8b0f8b0989018d430450e8b7f9ffff8b0f568b09894104e8aaf9ffff8b0f83c4108b0989410833c0eb0383c8ff5f5e5bc9c3";
pub(crate) const RECALLOC: &str = "8bff558bec568b750c85f6741b6ae033d258f7f63b4510730fe85fb4ffffc7000c00000033c0eb42538b5d085785db740b53e8c9430000598bf8eb0233ff0faf75105653e8074400008bd8595985db74153bfe73112bf78d043b566a0050e8bd5affff83c40c5f8bc35b5e5dc3";
pub(crate) const REALLOC: &str = "8bff558bec578b7d0885ff750bff750ce87b7affff59eb24568b750c85f6750957e88a70ffff59eb1083fee07625e8fa6fffffc7000c00000033c05e5f5dc3e8dc64ffff85c074e656e8d2bcffff5985c074db56576a00ff35c8d24100ff151451410085c074d8ebd2";
pub(crate) const MEMSET: &str = "8b4c240c0fb64424088bd78b7c240485c90f843c01000069c00101010183f9200f86df00000081f9800000000f828b0000000fba25bccc4100017309f3aa8b4424048bfac30fba2558c04100010f83b2000000660f6ec0660f70c00003cf0f110783c71083e7f02bcf81f980000000764c8da424000000008da4240000000090660f7f07660f7f4710660f7f4720660f7f4730660f7f4740660f7f4750660f7f4760660f7f47708dbf8000000081e980000000f7c100ffffff75c5eb130fba2558c0410001733e660f6ec0660f70c00083f920721cf30f7f07f30f7f471083c72083e92083f92073ecf7c11f00000074628d7c0fe0f30f7f07f30f7f47108b4424048bfac3f7c103000000740e88074783e901f7c10300000075f2f7c1040000007408890783c70483e904f7c1f8ffffff74208da424000000008d9b00000000890789470483c70883e908f7c1f8ffffff75ed8b4424048bfac3";
pub(crate) const ENCODE: &str = "8bff558beca100c0410083e01f6a20592bc88b4508d3c8330500c041005dc3";

fn guard(at: u32, bytes: &[u8]) -> String {
    format!("let p=rt.process_image_code(inputs.image,{at},{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"onexit code read\")?!=&{bytes:?}{{return Err(\"onexit original code changed\");}}",bytes.len(),bytes.len())
}
pub(crate) fn source() -> Result<String, String> {
    let mut out = String::from(
        r#"
/// An input/lifetime witness, not a successful registration or callback receipt.
struct CrtOnexitInput{entry:CrtPointer,argument:CrtPointer,identity:u64,value:CrtValue,target:CrtPointer,cookie:CrtValue}
impl CrtOnexitInput{
 fn bind(rt:&CrtStreamRuntime,cpu:&CrtCpu,inputs:&CrtEntropyInputs)->Result<Self,&'static str>{
  inputs.validate(rt)?;cpu.validate_active(rt)?;if cpu.return_pop!=0||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){return Err("onexit input phase/ABI");}
  let entry=CrtCpu::pointer(cpu.r[4])?;let argument=rt.offset(entry,4)?;let value=rt.load(argument,32)?;let address=value.known_scalar()?;if address==0{return Err("onexit null callback unsupported");}let target=rt.process_image_code(inputs.image,address,1)?;
  let cookie=rt.load(rt.process_image_pointer(inputs.image,0x41c000,4)?,32)?;cookie.known_scalar()?;
  let value=Self{entry,argument,identity:cpu.return_id,value,target,cookie};value.validate(rt,inputs)?;Ok(value)
 }
 fn validate(&self,rt:&CrtStreamRuntime,inputs:&CrtEntropyInputs)->Result<(),&'static str>{
  inputs.validate(rt)?;
  if rt.load(self.entry,32)?!=CrtValue::ProtectedReturn(self.identity)||rt.tags.values().filter(|&&v|v==CrtValue::ProtectedReturn(self.identity)).count()!=1||rt.load(self.argument,32)?!=self.value{return Err("onexit callback input/return changed");}
  if rt.process_image_code(inputs.image,self.value.known_scalar()?,1)?!=self.target{return Err("onexit callback target lifetime");}rt.memory.validate_immutable(self.target.cap,self.target.owner,self.target.address(),1).map_err(|_|"onexit callback code permission")?;
  if rt.load(rt.process_image_pointer(inputs.image,0x41c000,4)?,32)?!=self.cookie{return Err("onexit cookie changed");}Ok(())
 }
}
fn onexit_register_with(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,manager:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,&CrtEntropyInputs,&CrtOnexitInput)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{let input=CrtOnexitInput::bind(rt,cpu,inputs)?;onexit_atexit(rt,cpu,inputs,&input,manager)}
fn onexit_register_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,mut epoch:Option<&mut NormalCallEpoch<'_>>)->Result<CrtValue,&'static str>{onexit_register_with(rt,cpu,inputs,&mut |rt,c,inputs,input|{let e=epoch.as_deref_mut().ok_or("onexit live exception registry unbound at 0x407267")?;onexit_manager_original(rt,c,inputs,input,e)})}
"#,
    );
    let raw = crate::crt_ptd::raw;
    for (name, at, literal) in [
        ("onexit_atexit", 0x401b0f, ATEXIT),
        ("onexit_common", 0x401ae1, COMMON),
        ("onexit_global", 0x4074a8, GLOBAL),
        ("onexit_table", 0x407525, WRAPPER),
    ] {
        let bytes = raw(literal);
        let g = Graph::decode(&bytes, at)?;
        let body = crate::crt_stream_emit::emit_body_with_hooks(
            &g,
            |pc, t| {
                let next = pc + g.nodes[&pc].length;
                let callee=match t{Target::Direct(0x401ae1)=>"onexit_common",Target::Direct(0x4074a8)=>"onexit_global",Target::Direct(0x407525)=>"onexit_table",Target::Direct(0x407260)=>return Ok(format!("input.validate(rt,inputs)?;cpu.call_activation(rt,{next},12,|rt,c|manager(rt,c,inputs,input))?;cpu.r[0].known_scalar()?;input.validate(rt,inputs)?;")),_=>return Err("onexit wrapper target".into())};
                Ok(format!("input.validate(rt,inputs)?;cpu.call_activation(rt,{next},0,|rt,c|{callee}(rt,c,inputs,input,manager))?;input.validate(rt,inputs)?;"))
            },
            &BTreeMap::from([(0x41cc88, "CrtRegionKind::Module".into())]),
            256,
            |_, _| Err("onexit wrapper thread effect".into()),
            |_, _| Ok(String::new()),
            |_, _| Ok(None),
        )?;
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,input:&CrtOnexitInput,manager:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,&CrtEntropyInputs,&CrtOnexitInput)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{input.validate(rt,inputs)?;cpu.validate_active(rt)?;{} {body}}}",guard(at,&bytes)));
    }
    // Shared existing original EH4 prolog/epilog and logical global-lock helpers.
    let helper = raw(crate::crt_ucrt_locale::PROLOG);
    let proof = crate::crt_exception_wrapper::PrologProof::prove(
        crate::crt_exception_wrapper::Region {
            bytes: &helper,
            origin: 0x401e60,
        },
        12,
        0x41b500,
        0x41c000,
        0x402210,
    )?;
    let bytes = raw(MANAGER);
    let epbytes = bytes[(0x40729a - 0x407260)..].to_vec();
    let ep = crate::crt_exception_wrapper::EpilogProof::prove(
        crate::crt_exception_wrapper::Region {
            bytes: &epbytes,
            origin: 0x40729a,
        },
        &proof,
    )?;
    out.push_str(&proof.emit("onexit_prolog")?);
    out.push_str(&ep.emit("onexit_epilog")?);
    let clean = raw(CLEANUP);
    let cg = Graph::decode(&clean, 0x4072af)?;
    let cb = crate::crt_stream_emit::emit_body(
        &cg,
        |pc, t| {
            if t != Target::Direct(0x40be17) {
                return Err("onexit cleanup target".into());
            }
            Ok(format!(
                "cpu.call_activation(rt,{},0,|rt,c|startup_second_lock(rt,c,inputs,false,held))?;",
                pc + cg.nodes[&pc].length
            ))
        },
        &Default::default(),
        64,
    )?;
    out.push_str(&format!("fn onexit_cleanup(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,held:&mut Option<CrtGlobalLock>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{} {cb}}}",guard(0x4072af,&clean)));
    let mut g = crate::crt_startup_table::graph(&bytes[..(0x40729a - 0x407260)], 0x407260)?;
    // The epilog is proved above and is the only successful terminal boundary.
    g.end = 0x40729a;
    let body = crate::crt_stream_emit::emit_body_with_exit(
        &g,
        |pc, t| {
            let next = pc + g.nodes[&pc].length;
            Ok(match t{
  Target::Direct(0x401e60)=>"let n=rt.generation.checked_add(1).filter(|n|*n<1u64<<63).ok_or(\"onexit prolog generation\")?;let id=n|(1u64<<63);if rt.tags.values().any(|v|*v==CrtValue::ProtectedReturn(id)){return Err(\"onexit prolog collision\");}rt.generation=n;cpu.push(rt,CrtValue::ProtectedReturn(id))?;onexit_prolog(rt,cpu,id,b.token,|rt,c,record,head|b.install(rt,c,epoch,record,head))?;".into(),
  Target::Direct(0x40bdcf)=>format!("input.validate(rt,inputs)?;cpu.call_activation(rt,{next},0,|rt,c|startup_second_lock(rt,c,inputs,true,&mut held))?;"),
  Target::Direct(0x4072bb)=>format!("input.validate(rt,inputs)?;b.authority(rt,epoch)?;let lease=held.ok_or(\"onexit body missing lock\")?;cpu.call_activation(rt,{next},0,|rt,c|append(rt,c,inputs,input,epoch,&b,lease))?;cpu.r[0].known_scalar()?;input.validate(rt,inputs)?;"),
  Target::Direct(0x4072af)=>format!("input.validate(rt,inputs)?;b.authority(rt,epoch)?;cpu.call_activation(rt,{next},0,|rt,c|onexit_cleanup(rt,c,inputs,&mut held))?;"),_=>return Err(format!("onexit manager target {t:?}"))})
        },
        &Default::default(),
        512,
        |_, _| Err("onexit manager FS effect".into()),
        |_, _| Ok(String::new()),
        |_, _| Ok(None),
        Some(0x40729a),
    )?;
    let terminal = format!("if pc=={}{{return Ok(cpu.r[0]);}}", 0x40729a);
    if !body.contains(&terminal) {
        return Err("onexit epilog cut missing".into());
    }
    let body=body.replace(&terminal,"if pc==4223642{input.validate(rt,inputs)?;if held.is_some(){return Err(\"onexit epilog with held lock\");}return onexit_epilog(rt,cpu,epoch,&mut b);}");
    out.push_str(&format!("fn onexit_manager_with(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,input:&CrtOnexitInput,epoch:&mut NormalCallEpoch<'_>,append:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,&CrtEntropyInputs,&CrtOnexitInput,&mut NormalCallEpoch<'_>,&CrtNormalBinding,CrtGlobalLock)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{input.validate(rt,inputs)?;cpu.validate_active(rt)?;{}{}{}let scope=rt.process_image_pointer(inputs.image,0x41b500,32)?;rt.memory.validate_immutable(scope.cap,scope.owner,scope.address(),32).map_err(|_|\"onexit scope permission\")?;if rt.memory.read(scope.address(),32).map_err(|_|\"onexit scope read\")?!=&{scope_bytes:?}{{return Err(\"onexit scope changed\");}}let mut b=CrtNormalBinding::bind_initializing(rt,cpu,epoch,onexit_epilog_layout(),inputs.init)?;let mut held=None;{body}}}",guard(0x407260,&bytes),guard(0x401e60,&helper),guard(0x4072af,&clean),scope_bytes=raw(SCOPE)));
    out.push_str("fn onexit_manager_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,input:&CrtOnexitInput,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{onexit_manager_with(rt,cpu,inputs,input,epoch,&mut |rt,c,inputs,input,e,b,lease|onexit_append_prefix(rt,c,inputs,input,e,b,lease))}");
    let bytes = raw(BODY);
    let mut g = Graph::decode(&bytes, 0x4072bb)?;
    // Nonempty decoding and reallocation require a persistent producer association.
    // Numeric encodings, even ones naming live regions, never issue capabilities.
    g.nodes.insert(
        0x40733c,
        Node {
            length: g.nodes[&0x40733c].length,
            op: Op::Reject("onexit growth fallback unbound"),
            successors: vec![],
        },
    );
    let body = crate::crt_stream_emit::emit_body_with_repeated_memory(
        &g,
        |pc, t| {
            let next = pc + g.nodes[&pc].length;
            let callee = match t {
                Target::Direct(0x40c850) => "onexit_recalloc_prefix",
                Target::Direct(0x407d50) => "ucrt_free_null",
                Target::Direct(0x406d62) => "onexit_encode_original",
                _ => return Err("onexit append call target".into()),
            };
            Ok(format!("input.validate(rt,inputs)?;b.authority(rt,epoch)?;rt.check_global(lease)?;cpu.call_activation(rt,{next},0,|rt,c|{callee}(rt,c,inputs))?;"))
        },
        &BTreeMap::from([(0x41c000, "CrtRegionKind::Module".into())]),
        1024,
        |_, _| Err("onexit append thread effect".into()),
        |pc, _| {
            Ok(match pc {
          0x4072de => "let p=rt.module_word_pointer(inputs.image,cpu.r[6])?;rt.valid(p,12)?;let cookie=input.cookie.known_scalar()?;for n in 0..3{let v=rt.load(rt.offset(p,n*4)?,32)?;if !matches!(v,CrtValue::Scalar{..}){return Err(\"onexit encoded scalar word\");}if v.known_scalar()?!=cookie{return Err(\"onexit encoded allocation owner unbound\");}}table=Some(p);cpu.r[6]=CrtValue::Pointer(p);".into(),
          0x407326 => "let p=CrtCpu::pointer(cpu.r[0])?;rt.valid(p,128)?;if p.kind!=CrtRegionKind::Buffer||p.address()!=p.base||p.size!=128||!rt.regions.iter().any(|r|r.heap&&r.pointer==p){return Err(\"onexit fresh allocation identity/extent\");}allocation=Some(p);".into(),
          0x407395|0x4073a0|0x4073b0|0x4073bf => {
           let (step,value)=match pc{0x407395=>(0,"input.value.known_scalar()?"),0x4073a0=>(1,"p.address()"),0x4073b0=>(2,"p.address()+4"),_=>(3,"p.address()+128")};
           let destination=if step==0{"if CrtCpu::pointer(cpu.r[3])?!=p{return Err(\"onexit callback slot identity\");}".to_owned()}else{"let q=rt.module_word_pointer(inputs.image,cpu.r[1])?;if Some(q)!=table{return Err(\"onexit table publication identity\");}cpu.r[1]=CrtValue::Pointer(q);".to_owned()};
           format!("input.validate(rt,inputs)?;b.authority(rt,epoch)?;rt.check_global(lease)?;let p=allocation.ok_or(\"onexit allocation producer missing\")?;rt.valid(p,128)?;if written!={step}{{return Err(\"onexit original publication order\");}}{destination}let cookie=input.cookie.known_scalar()?;if cpu.r[0].known_scalar()?!=({value}).rotate_left(cookie&31)^cookie{{return Err(\"onexit original encoding mismatch\");}}written+=1;")
          },
          0x4073c2 => "if written!=4{return Err(\"onexit incomplete publication\");}".into(),
          _ => String::new()
        })
        },
        |_, _| Ok(None),
        None,
        |_, _, _| Ok(None),
        |_, _| Err("onexit indirect call".into()),
        |_, _| Err("onexit repeated copy".into()),
        |pc, width| {
            if pc != 0x407383 || width != 32 {
                return Err("onexit repeated store location".into());
            }
            Ok("input.validate(rt,inputs)?;b.authority(rt,epoch)?;rt.check_global(lease)?;let p=allocation.ok_or(\"onexit fill producer missing\")?;if cpu.r[7]!=CrtValue::Pointer(p)||cpu.r[1]!=CrtValue::scalar(32)||cpu.r[0]!=input.cookie{return Err(\"onexit cookie fill extent/value\");}cpu.repeat_store_units(rt,32,32)?;".into())
        },
    )?;
    out.push_str(&format!("fn onexit_append_prefix(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,input:&CrtOnexitInput,epoch:&mut NormalCallEpoch<'_>,b:&CrtNormalBinding,lease:CrtGlobalLock)->Result<CrtValue,&'static str>{{input.validate(rt,inputs)?;cpu.validate_active(rt)?;b.authority(rt,epoch)?;rt.check_global(lease)?;{}let mut table=None;let mut allocation=None;let mut written=0; {body}}}",guard(0x4072bb,&bytes)));
    let bytes = raw(ENCODE);
    let g = Graph::decode(&bytes, 0x406d62)?;
    let body = encode_body(&g)?;
    out.push_str(&format!("fn onexit_encode_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{} {body}}}",guard(0x406d62,&bytes)));
    for (name, at, literal) in [
        ("onexit_recalloc_prefix", 0x40c850, RECALLOC),
        ("onexit_realloc_prefix", 0x410ca0, REALLOC),
    ] {
        let bytes = raw(literal);
        let g = Graph::decode(&bytes, at)?;
        let body = crate::crt_stream_emit::emit_body(
            &g,
            |pc, t| {
                let next = pc + g.nodes[&pc].length;
                Ok(match t{
   Target::Direct(0x410ca0)=>format!("cpu.call_activation(rt,{next},0,|rt,c|onexit_realloc_prefix(rt,c,inputs))?;"),
   Target::Direct(0x408730)=>format!("cpu.call_activation(rt,{next},0,|rt,c|malloc_original_native(rt,c,inputs))?;"),
   Target::Direct(0x410c50)=>"return Err(\"onexit nonnull allocation size/owner unbound\");".into(),
   Target::Direct(0x402370)=>format!("cpu.call_activation(rt,{next},0,|rt,c|onexit_memset_original(rt,c,inputs))?;"),
   Target::Direct(0x407d50)=>"return Err(\"onexit realloc free effect unbound\");".into(),
   Target::Direct(0x407ccd|0x4071c0|0x40c9c0)=>"return Err(\"onexit realloc errno/new-handler unbound\");".into(),
   Target::Import(0x415114)=>"return Err(\"onexit HeapReAlloc ownership effect unbound\");".into(),
   _=>return Err(format!("onexit allocation target {t:?}"))})
            },
            &BTreeMap::from([(0x41d2c8, "CrtRegionKind::Module".into())]),
            512,
        )?;
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{} {body}}}",guard(at,&bytes)));
    }
    out.push_str(&memset_source()?);
    Ok(out)
}
#[test]
fn original_onexit_routes_tables_and_preserves_explicit_allocation_boundaries() {
    source().expect("onexit original regions must lower without admitted unbound effects");
}
#[test]
fn conditional_memory_selection_reads_before_condition_and_preserves_flags() {
    let mut extra = String::new();
    for (name, opcode) in [("equal", 0x44u8), ("above", 0x47), ("unequal", 0x45)] {
        let g = Graph::decode(&[0x0f, opcode, 0x01, 0xc3], 0x500000).unwrap();
        let body = crate::crt_stream_emit::emit_body(
            &g,
            |_, _| Err("call".into()),
            &Default::default(),
            8,
        )
        .unwrap();
        extra.push_str(&format!("fn select_{name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}"));
        assert!(Graph::decode_instruction(&[0x66, 0x0f, opcode, 0x01], 0x500000).is_err());
    }
    crate::crt_stream_callees_tests::native(
        &extra,
        r#"
for kind in 0..3{for cf in [false,true]{for zf in [false,true]{for bad in 0..3{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0x10000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(17)).unwrap();let source=rt.map_region(0x12000,4,CrtRegionKind::Stack,Some(&77u32.to_le_bytes())).unwrap();let mut c=CrtCpu::new(sp,17).unwrap();c.r[0]=CrtValue::scalar(9);c.r[1]=CrtValue::Pointer(source);c.flags=CrtFlags{cf:Some(cf),zf:Some(zf),sf:Some(true),of:Some(false)};if bad!=0{rt.memory.release(source.cap,source.owner).unwrap();}if bad==2{c.flags.cf=None;c.flags.zf=None;}let flags=(c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of);
 let result=match kind{0=>select_equal(&mut rt,&mut c),1=>select_above(&mut rt,&mut c),_=>select_unequal(&mut rt,&mut c)};
 if bad!=0{assert_eq!(result,Err("CRT pointer lifetime"),"source must read even when condition false or unknown");assert_eq!(c.r[0],CrtValue::scalar(9));assert!(!c.returned);}else{let yes=match kind{0=>zf,1=>!cf&&!zf,_=>!zf};assert_eq!(result,Ok(CrtValue::scalar(if yes{77}else{9})));assert!(c.returned);}assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),flags);
}}}}
"#,
        "onexit-cmov-memory",
    );
}

fn memset_graph() -> Result<Graph, String> {
    let mut g = Graph::decode(&crate::crt_ptd::raw(MEMSET), 0x402370)?;
    for pc in [0x4023cc, 0x4023d7] {
        g.numeric_result(pc)?;
    }
    Ok(g)
}
fn memset_body() -> Result<String, String> {
    let g = memset_graph()?;
    crate::crt_stream_emit::emit_body_with_repeated_memory(
        &g,
        |_, _| Err("memset unexpected call".into()),
        &BTreeMap::from([
            (0x41ccbc, "CrtRegionKind::Module".into()),
            (0x41c058, "CrtRegionKind::Module".into()),
        ]),
        16384,
        |_, _| Err("memset thread effect".into()),
        |_, _| Ok(String::new()),
        |_, _| Ok(None),
        None,
        |_, _, _| Ok(None),
        |_, _| Err("memset indirect effect".into()),
        |_, _| Err("memset repeated copy".into()),
        |pc, width| {
            if pc != 0x4023ac || width != 8 {
                return Err("memset repeated store location".into());
            }
            Ok("cpu.repeat_store_units(rt,8,65536)?;".into())
        },
    )
}
fn memset_source() -> Result<String, String> {
    let bytes = crate::crt_ptd::raw(MEMSET);
    let body = memset_body()?;
    Ok(format!("fn onexit_memset_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&impl CrtInstructionInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{} {body}}}",guard(0x402370,&bytes).replace("inputs.image","inputs.image()")))
}

#[test]
fn repeated_store_needs_its_own_issuer_and_rejects_other_encodings() {
    for op in [0xaa, 0xab] {
        let g = Graph::decode(&[0xf3, op, 0xc3], 0x1000).unwrap();
        assert_eq!(
            crate::crt_stream_emit::emit_body_with_hooks(
                &g,
                |_, _| Err("call".into()),
                &Default::default(),
                8,
                |_, _| Ok(String::new()),
                |_, _| Ok(String::new()),
                |_, _| Ok(None)
            )
            .unwrap_err(),
            "CRT emit repeated store effect unbound"
        );
    }
    for code in [
        &[0xf2, 0xaa, 0xc3][..],
        &[0x66, 0xf3, 0xab, 0xc3],
        &[0x67, 0xf3, 0xaa, 0xc3],
        &[0x64, 0xf3, 0xaa, 0xc3],
        &[0xfd, 0xc3],
    ] {
        assert!(Graph::decode(code, 0x1000).is_err(), "{code:?}");
    }
}
#[test]
fn original_memset_matches_independent_byte_oracle_across_paths_and_bounds() {
    let body = memset_body().unwrap();
    crate::crt_stream_callees_tests::native(&format!("fn fill(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}"),r#"
 let mut cases=0;
 for mode in 0..4 { for align in 0..16 { for count in (0..=65).chain([95,96,97,127,128,129,255,256,257,511,512,513,1024]) {
  let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0x10000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(17)).unwrap();
  let module=rt.map_region(0x41c000,4096,CrtRegionKind::Module,Some(&[0;4096])).unwrap();rt.store(rt.offset(module,0xcbc).unwrap(),32,CrtValue::scalar(if mode&1!=0{2}else{0})).unwrap();rt.store(rt.offset(module,0x58).unwrap(),32,CrtValue::scalar(if mode&2!=0{2}else{0})).unwrap();
  let CrtValue::Heap(heap)=rt.native_process_heap(init).unwrap()else{panic!()};let p=rt.native_heap_allocate(init,heap,0,2048).unwrap();let dst=rt.offset(p,32+align).unwrap();let value=0x12340000|((count*37+align as u32)&255);
  rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::Pointer(dst)).unwrap();rt.store(rt.offset(sp,8).unwrap(),32,CrtValue::scalar(value)).unwrap();rt.store(rt.offset(sp,12).unwrap(),32,CrtValue::scalar(count)).unwrap();let mut c=CrtCpu::new(sp,17).unwrap();let saved=c.r;
  assert_eq!(fill(&mut rt,&mut c),Ok(CrtValue::Pointer(dst)),"mode{mode} align{align} count{count}");assert!(c.returned);for n in [3,5,6,7]{assert_eq!(c.r[n],saved[n]);}
  for i in 0..2048 {let q=rt.offset(p,i).unwrap();if (32+align..32+align+i64::from(count)).contains(&i){assert_eq!(rt.load(q,8),Ok(CrtValue::scalar(value&255)));}else{assert!(rt.load(q,8).unwrap().known_scalar().is_err(),"original code must not touch bytes outside count mode{mode} align{align} count{count} i{i}");assert_eq!(rt.memory.read(q.address(),1),Err(guest_memory::Fault::Uninitialized));}}
  cases+=1;
 }}}
 assert_eq!(cases,5056);
 // Zero-length original path loads its arguments but never dereferences the null destination.
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0x10000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(19)).unwrap();for(n,v)in[(4,0),(8,7),(12,0)]{rt.store(rt.offset(sp,n).unwrap(),32,CrtValue::scalar(v)).unwrap();}let mut c=CrtCpu::new(sp,19).unwrap();assert_eq!(fill(&mut rt,&mut c),Ok(CrtValue::scalar(0)));
 // Explicit per-element progress, no source/destination/value observation at zero count.
 let sp=rt.offset(stack,600).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(20)).unwrap();let mut c=CrtCpu::new(sp,20).unwrap();c.r[1]=CrtValue::scalar(0);c.repeat_store_units(&mut rt,8,16).unwrap();
 let CrtValue::Heap(heap)=rt.native_process_heap(init).unwrap()else{panic!()};let p=rt.native_heap_allocate(init,heap,0,8).unwrap();c.r[0]=CrtValue::scalar(0x5a);c.r[1]=CrtValue::scalar(12);c.r[7]=CrtValue::Pointer(p);c.flags=CrtFlags{cf:Some(true),zf:Some(false),sf:Some(true),of:Some(false)};assert!(c.repeat_store_units(&mut rt,8,16).is_err());assert_eq!(c.r[1],CrtValue::scalar(4));assert_eq!(CrtCpu::pointer(c.r[7]).unwrap().address(),p.address()+8);assert_eq!(rt.memory.read(p.address(),8).unwrap(),&[0x5a;8]);assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(Some(true),Some(false),Some(true),Some(false)));
 // Unknown low lane stays unknown; upper MOVD lanes are zero. PSHUFD aliases read a snapshot.
 c.vector_from_dword(0,CrtValue::Scalar{bits:0x11220000,known:0xffff0000}).unwrap();assert_eq!(c.xmm[0][0],CrtValue::Scalar{bits:0x11220000,known:0xffff0000});assert_eq!(&c.xmm[0][1..],&[CrtValue::scalar(0);3]);c.xmm[0]=[CrtValue::scalar(1),CrtValue::scalar(2),CrtValue::scalar(3),CrtValue::scalar(4)];c.vector_shuffle(0,0,0x1b).unwrap();assert_eq!(c.xmm[0],[CrtValue::scalar(4),CrtValue::scalar(3),CrtValue::scalar(2),CrtValue::scalar(1)]);assert_eq!(c.vector_from_dword(0,CrtValue::Pointer(p)),Err("CRT vector scalar MOVD form"));
 // Stale destination and control value cannot be laundered into initialized bytes.
 let q=rt.native_heap_allocate(init,heap,0,8).unwrap();rt.memory.release(q.cap,q.owner).unwrap();c.r[7]=CrtValue::Pointer(q);c.r[1]=CrtValue::scalar(1);assert!(c.repeat_store_units(&mut rt,8,16).is_err());assert_eq!(c.r[1],CrtValue::scalar(1));c.r[7]=CrtValue::Pointer(p);c.r[0]=CrtValue::ProtectedReturn(20);assert_eq!(c.repeat_store_units(&mut rt,32,16),Err("CRT REP store scalar value"));
 "#,"onexit-memset");
}

fn encode_body(g: &Graph) -> Result<String, String> {
    crate::crt_stream_emit::emit_body_with_hooks(
        g,
        |_, _| Err("onexit encode call".into()),
        &BTreeMap::from([(0x41c000, "CrtRegionKind::Module".into())]),
        64,
        |_, _| Err("onexit encode thread".into()),
        |pc, _| {
            Ok(if pc == 0x406d77 {
                "if let CrtValue::Pointer(p)=cpu.r[0]{rt.identity_range(p,0)?;cpu.r[0]=CrtValue::scalar(p.address());}".into()
            } else {
                String::new()
            })
        },
        |_, _| Ok(None),
    )
}
#[test]
fn original_encoding_discards_authority_and_checks_live_pointer_operands() {
    let g = Graph::decode(&crate::crt_ptd::raw(ENCODE), 0x406d62).unwrap();
    let body = encode_body(&g).unwrap();
    crate::crt_stream_callees_tests::native(&format!("fn encode(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}"),r#"
 for bits in [0u32,0x401e2c,0x80000000,u32::MAX]{for count in 0..32{
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0x10000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(31)).unwrap();let cookie:u32=0x12345660|count;rt.map_region(0x41c000,4,CrtRegionKind::Module,Some(&cookie.to_le_bytes())).unwrap();rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::scalar(bits)).unwrap();let mut c=CrtCpu::new(sp,31).unwrap();assert_eq!(encode(&mut rt,&mut c),Ok(CrtValue::scalar(bits.rotate_left(count)^cookie)));assert!(c.returned);assert!(CrtCpu::pointer(c.r[0]).is_err());
 let CrtValue::Heap(heap)=rt.native_process_heap(init).unwrap()else{panic!()};let p=rt.native_heap_allocate(init,heap,0,8).unwrap();for stale in [false,true]{let sp=rt.offset(stack,600).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(32)).unwrap();rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::Pointer(p)).unwrap();let mut c=CrtCpu::new(sp,32).unwrap();if stale{rt.free_allocation(p).unwrap();}let got=encode(&mut rt,&mut c);if stale{assert_eq!(got,Err("CRT stale/foreign pointer"));assert!(!c.returned);}else{assert_eq!(got,Ok(CrtValue::scalar(p.address().rotate_left(count)^cookie)));assert!(c.returned);assert!(CrtCpu::pointer(c.r[0]).is_err());}}
 }}
 // The no-op LEA that aligns original code must preserve saved identity, not just unknown bits.
 let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0x10000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(33)).unwrap();let mut c=CrtCpu::new(sp,33).unwrap();for n in [3,5,6,7]{assert_eq!(c.lea(&rt,Some(n),None,1,0,None),Ok(c.r[n]));assert_ne!(c.lea(&rt,Some(n),None,1,1,None),Ok(c.r[n]));}
 "#,"onexit-encoding");
}
