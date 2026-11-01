//! Guarded original C-initializer iteration; unsupported callbacks never succeed.
use crate::crt_stream_ir::{Graph, Node, Op, Target};
use std::collections::BTreeMap;
pub(crate) const LOOP: &str =
    "8bff558bec568b750857eb178b3e85ff740e8bcfff1528514100ffd785c0750a83c6043b750c75e433c05f5e5dc3";
pub(crate) const EMPTY: &str =
    "5356bec0b14100bbc0b141003bf37319578b3e85ff740a8bcfff1528514100ffd783c6043bf372e95f5e5bc3";
pub(crate) const FIRST:&str="566a01e8cc500000e85c06000050e8e95a0000e84a0600008bf0e8865c00006a018930e8fc03000083c40c5e84c07473dbe2e86f080000682c1e4000e874050000e81f06000050e82e540000595985c07551e818060000e86906000085c0740b68bc1b4000e8ec50000059e82f060000e82a060000e804060000e8e305000050e8795b000059e8f005000084c07405e8ae560000e8c9050000e85407000085c07501c36a07e833060000cc";
pub(crate) const SECOND: &str = "e8f805000033c0c3";
pub(crate) const FILE_INIT:&str="a12ccd4100566a035e85c07507b800020000eb063bc67d078bc6a32ccd41006a0450e8b93700006a00a330cd4100e80d38000083c40c833d30cd410000752b6a045689352ccd4100e8933700006a00a330cd4100e8e737000083c40c833d30cd410000750583c8ff5ec35733ffbe80c041006a0068a00f00008d462050e8e73a0000a130cd41008bd7c1fa068934b88bc783e03f6bc8388b049508cf41008b44081883f8ff740983f8fe740485c07507c74610feffffff83c6384781fe28c1410075af5f33c05ec3";
pub(crate) const LOCALE: &str = "e86baaffff0fb6c083f001c3";
pub(crate) const MODE: &str = "833dbcd2410000750ac705bcd241000040000033c0c3";
pub(crate) const FEATURE: &str = "6a0aff151c504100a3fcd2410033c0c3";
pub(crate) const CPP: &str = "e881070000e8a505000050e8b35b000059c3";
pub(crate) const APP_TYPE: &str = "8bff558bec8b4508a338cd41005dc3";
pub(crate) const GET_MODE: &str = "b800400000c3";
pub(crate) const SET_MODE:&str="8bff558bec8b45083d0040000074233d00800000741c3d000001007415e8550c0000c70016000000e8cc0a00006a16585dc3b9bcd24100870133c05dc3";
pub(crate) const ZERO: &str = "33c0c3";
pub(crate) const GET_COMMODE: &str = "b884ce4100c3";
pub(crate) const ONEXIT:&str="558bec803d85cc4100007404b0015dc3568b750885f6740583fe017562e81f08000085c0742685f675226888cc4100e84a5b00005985c0750f6894cc4100e83b5b00005985c0742b32c0eb3083c9ff890d88cc4100890d8ccc4100890d90cc4100890d94cc4100890d98cc4100890d9ccc4100c60585cc410001b0015e5dc36a05e833020000cc";
pub(crate) const OPTIONS: &str = "e869f6ffff8b4804830824894804e8e7ffffff8b4804830802894804c3";
pub(crate) const OPTIONS_GET: &str = "b8e8d24100c3";
pub(crate) const SCAN_GET: &str = "b8a8cc4100c3";
fn cut_graph(
    bytes: &[u8],
    origin: u32,
    end: u32,
    cuts: &[(u32, &'static str)],
) -> Result<Graph, String> {
    let mut g = crate::crt_startup_table::graph(&bytes[..(end - origin) as usize], origin)?;
    for &(pc, reason) in cuts {
        g.nodes.insert(
            pc,
            Node {
                length: 2,
                op: Op::Reject(reason),
                successors: vec![],
            },
        );
    }
    Ok(g)
}
pub(crate) fn source() -> Result<String, String> {
    let registration_source = crate::crt_onexit::source()?;
    let raw = crate::crt_ptd::raw;
    let bytes = raw(LOOP);
    let g = crate::crt_startup_table::graph(&bytes, 0x406ccc)?;
    let body = crate::crt_stream_emit::emit_body_with_indirect(
        &g,
        |pc, t| {
            if t != Target::Import(0x415128) {
                return Err("C-array guard import".into());
            }
            Ok(format!("table.validate(rt,inputs.image)?;let index=table.cursor(rt,cpu)?;if completed[index]||(0..index).any(|j|table.words[j]!=0&&!completed[j]){{return Err(\"C-array callback order\");}}let address=cpu.r[7].known_scalar()?;if cpu.r[1].known_scalar()?!=address||address!=table.words[index]{{return Err(\"C-array guard register target\");}}let code=rt.process_image_code(inputs.image,address,1)?;let p=rt.process_image_pointer(inputs.image,0x415128,4)?;let guard=rt.process_image_code(inputs.image,0x401bf9,3)?;if rt.load(p,32)?.known_scalar()?!=0x401bf9||rt.memory.read(guard.address(),3).map_err(|_|\"C-array guard read\")?!=[0xc2,0,0]{{return Err(\"C-array guard identity\");}}cpu.call_activation(rt,{},0,startup_original_guard)?;guarded=Some((index,code));",pc+g.nodes[&pc].length))
        },
        &Default::default(),
        4096,
        |_, _| Err("C-array thread effect".into()),
        |pc, _| {
            Ok(if pc == 0x406cd5 {
                "if CrtCpu::number(cpu.r[6])?!=table.begin.address(){return Err(\"C-array initial cursor\");}cpu.r[6]=CrtValue::Pointer(table.begin);".into()
            } else {
                String::new()
            })
        },
        |_, pop| {
            if pop != 0 {
                return Err("C-array RET cleanup".into());
            }
            Ok(Some("table.validate(rt,inputs.image)?;if let Some(value)=failure{if cpu.r[0]!=value||value.known_scalar()?==0{return Err(\"C-array failure result changed\");}}else if cpu.r[0]!=CrtValue::scalar(0)||(0..table.len).any(|j|table.words[j]!=0&&!completed[j]){return Err(\"C-array incomplete traversal\");}return cpu.finish(rt);".into()))
        },
        None,
        |_, _, _| Ok(None),
        |pc, _| {
            Ok(format!("table.validate(rt,inputs.image)?;let index=table.cursor(rt,cpu)?;let Some((expected,code))=guarded.take()else{{return Err(\"C-array missing/replayed guard\");}};let address=target.known_scalar()?;if expected!=index||code!=rt.process_image_code(inputs.image,address,1)?||address!=table.words[index]{{return Err(\"C-array callback target changed\");}}cpu.call_activation(rt,{},0,|rt,c|callback(rt,c,index,code))?;inputs.validate(rt)?;table.validate(rt,inputs.image)?;let result=cpu.r[0].known_scalar()?;completed[index]=true;if result!=0{{failure=Some(cpu.r[0]);}}",pc+g.nodes[&pc].length))
        },
    )?;
    let mut out = format!(
        r#"
struct CrtCArray{{begin:CrtPointer,len:usize,words:[u32;64],arguments:CrtPointer,values:[CrtValue;2]}}
impl CrtCArray{{
 fn bind(rt:&CrtStreamRuntime,cpu:&CrtCpu,image:CrtProcessImage)->Result<Self,&'static str>{{
  let sp=CrtCpu::pointer(cpu.r[4])?;let arguments=rt.offset(sp,4)?;let values=[rt.load(arguments,32)?,rt.load(rt.offset(arguments,4)?,32)?];let begin=rt.module_word_pointer(image,values[0])?;let end=CrtCpu::number(values[1])?;let size=end.checked_sub(begin.address()).filter(|n|*n<=256&&*n%4==0).ok_or("C-array bound/alignment")?;if begin.address()%4!=0||rt.process_image_pointer(image,begin.address(),size.max(1))?!=begin{{return Err("C-array canonical extent");}}rt.memory.validate_immutable(begin.cap,begin.owner,begin.address(),size.max(1)).map_err(|_|"C-array table permission")?;
  let mut words=[0;64];for(i,w)in words.iter_mut().take((size/4)as usize).enumerate(){{*w=rt.load(rt.offset(begin,(i*4)as i64)?,32)?.known_scalar()?;}}Ok(Self{{begin,len:(size/4)as usize,words,arguments,values}})
 }}
 fn validate(&self,rt:&CrtStreamRuntime,image:CrtProcessImage)->Result<(),&'static str>{{
  if rt.process_image_pointer(image,self.begin.address(),(self.len as u32*4).max(1))?!=self.begin||rt.load(self.arguments,32)?!=self.values[0]||rt.load(rt.offset(self.arguments,4)?,32)?!=self.values[1]{{return Err("C-array owner/arguments changed");}}rt.memory.validate_immutable(self.begin.cap,self.begin.owner,self.begin.address(),(self.len as u32*4).max(1)).map_err(|_|"C-array table permission")?;
  for(i,value)in self.words[..self.len].iter().enumerate(){{if rt.load(rt.offset(self.begin,(i*4)as i64)?,32)?.known_scalar()?!=*value{{return Err("C-array table changed");}}}}{guard}Ok(())
 }}
 fn cursor(&self,rt:&CrtStreamRuntime,cpu:&CrtCpu)->Result<usize,&'static str>{{let p=CrtCpu::pointer(cpu.r[6])?;rt.valid(p,4)?;if p.cap!=self.begin.cap||p.owner!=self.begin.owner||p.base!=self.begin.base||p.size!=self.begin.size{{return Err("C-array cursor identity");}}let delta=p.address().checked_sub(self.begin.address()).filter(|n|*n%4==0&&((*n/4)as usize)<self.len).ok_or("C-array cursor extent")?;Ok((delta/4)as usize)}}
}}
fn startup_c_array(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,callback:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu,usize,CrtPointer)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;if cpu.return_pop!=0||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){{return Err("C-array entry phase/ABI");}}let table=CrtCArray::bind(rt,cpu,inputs.image)?;table.validate(rt,inputs.image)?;let mut completed=[false;64];let mut guarded:Option<(usize,CrtPointer)>=None;let mut failure:Option<CrtValue>=None;{body}}}
fn startup_c_array_real(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{startup_c_array_context(rt,cpu,inputs,None)}}
fn startup_c_array_context(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,mut epoch:Option<&mut NormalCallEpoch<'_>>)->Result<CrtValue,&'static str>{{startup_c_array_platform(rt,cpu,inputs,epoch,None)}}
fn startup_c_array_platform(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,mut epoch:Option<&mut NormalCallEpoch<'_>>,platform:Option<&CrtNativePlatform>)->Result<CrtValue,&'static str>{{startup_c_array(rt,cpu,inputs,&mut |rt,c,_,target|match target.address(){{0x40155a=>cinit_first_platform(rt,c,inputs,epoch.as_deref_mut(),platform),0x401605=>cinit_second_original(rt,c,inputs),0x40c109=>cinit_default_mode(rt,c,inputs),0x404510=>Err("C initializer FILE allocation/lock composition unbound"),0x4109ba=>Err("C initializer locale epoch composition unbound"),0x4127b0=>Err("C initializer raw feature BOOL storage unbound"),_=>Err("C initializer callback unbound")}})}}
"#,
        guard = guard(0x406ccc, &bytes).replace("inputs.image", "image")
    );
    out.push_str(&registration_source);
    out.push_str(&crate::crt_argv::source()?);
    for (name, at, literal) in [
        ("cinit_app_type", 0x40662e, APP_TYPE),
        ("cinit_get_mode", 0x401bc3, GET_MODE),
        ("cinit_zero", 0x401bbc, ZERO),
        ("cinit_get_commode", 0x4071ff, GET_COMMODE),
        ("cinit_options_get", 0x401270, OPTIONS_GET),
        ("cinit_scan_get", 0x401bfc, SCAN_GET),
        ("cinit_second_original", 0x401605, SECOND),
        ("cinit_options", 0x401c02, OPTIONS),
        ("cinit_default_mode", 0x40c109, MODE),
        ("cinit_set_mode", 0x407056, SET_MODE),
    ] {
        let bytes = raw(literal);
        let mut g = Graph::decode(&bytes, at)?;
        if at == 0x407056 {
            g.initializing_atomic(0x40708d)?;
        }
        let roles =
            BTreeMap::from_iter([0x41cd38, 0x41d2bc].map(|a| (a, "CrtRegionKind::Module".into())));
        let body = crate::crt_stream_emit::emit_body_with_hooks(
            &g,
            |pc, t| {
                let callee = match t {
                    Target::Direct(0x401c02) => "cinit_options",
                    Target::Direct(0x401270) => "cinit_options_get",
                    Target::Direct(0x401bfc) => "cinit_scan_get",
                    Target::Direct(0x407ccd | 0x407b4f) => return Ok(
                        "return Err(\"C initializer invalid file-mode errno/handler unbound\");"
                            .into(),
                    ),
                    _ => return Err("C initializer simple call".into()),
                };
                Ok(format!(
                    "cpu.call_activation(rt,{},0,|rt,c|{callee}(rt,c,inputs))?;",
                    pc + g.nodes[&pc].length
                ))
            },
            &roles,
            128,
            |_, op| {
                let Op::InitializingAtomic {
                    destination: crate::graph::Operand::Memory(a, 32),
                    source,
                    add: false,
                } = op
                else {
                    return Err("C initializer atomic effect".into());
                };
                Ok(format!("let p={};cpu.exchange_initializing_scalar(rt,inputs.init,inputs.image,p,{},false)?;",crate::crt_stream_emit::address(a,&roles)?,source.index))
            },
            |pc, _| {
                Ok(match pc{0x40c109=>"if !matches!(rt.load(rt.process_image_pointer(inputs.image,0x41d2bc,4)?,32)?,CrtValue::Scalar{..}){return Err(\"C initializer mode scalar field\");}".into(),0x40708d=>"cpu.r[1]=CrtValue::Pointer(rt.module_word_pointer(inputs.image,cpu.r[1])?);".into(),0x401c07|0x401c15=>"let p=rt.module_word_pointer(inputs.image,cpu.r[0])?;rt.valid(p,8)?;for offset in [0,4]{if !matches!(rt.load(rt.offset(p,offset)?,32)?,CrtValue::Scalar{..}){return Err(\"C initializer options scalar words\");}}cpu.r[0]=CrtValue::Pointer(p);".into(),_=>String::new()})
            },
            |_, _| Ok(None),
        )?;
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{} {body}}}",guard(at,&bytes)));
    }
    let bytes = raw(ONEXIT);
    let g = cut_graph(
        &bytes,
        0x40197e,
        0x4019fd,
        &[(
            0x4019fd,
            "C initializer onexit invalid argument/fastfail unbound",
        )],
    )?;
    let roles = BTreeMap::from_iter(
        [
            0x41cc85, 0x41cc88, 0x41cc8c, 0x41cc90, 0x41cc94, 0x41cc98, 0x41cc9c,
        ]
        .map(|a| (a, "CrtRegionKind::Module".into())),
    );
    let body = crate::crt_stream_emit::emit_body(
        &g,
        |pc, t| {
            let callee = match t {
                Target::Direct(0x4021bf) => "startup_runtime_flag",
                Target::Direct(0x4074fc) => "startup_exit_table_original",
                _ => return Err("C initializer onexit call".into()),
            };
            Ok(format!(
                "cpu.call_activation(rt,{},0,|rt,c|{callee}(rt,c,inputs))?;",
                pc + g.nodes[&pc].length
            ))
        },
        &roles,
        256,
    )?;
    out.push_str(&format!("fn cinit_onexit_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{} {body}}}",guard(0x40197e,&bytes)));
    let bytes = raw(EMPTY);
    let g = crate::crt_startup_table::graph(&bytes, 0x401e00)?;
    let body = crate::crt_stream_emit::emit_body_with_indirect(
        &g,
        |_, _| Ok("return Err(\"C initializer nonempty preinitializer guard unbound\");".into()),
        &Default::default(),
        128,
        |_, _| Err("preinitializer thread effect".into()),
        |_, _| Ok(String::new()),
        |_, _| Ok(None),
        None,
        |_, _, _| Ok(None),
        |_, _| Ok("return Err(\"C initializer nonempty preinitializer callback unbound\");".into()),
    )?;
    out.push_str(&format!("fn cinit_empty_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{} {body}}}",guard(0x401e00,&bytes)));
    let bytes = raw(FIRST);
    let g = cut_graph(
        &bytes,
        0x40155a,
        0x4015a6,
        &[
            (0x4015a6, "C initializer post-argv continuation unbound"),
            (0x4015fd, "C initializer fatal path unbound at 0x4015fd"),
        ],
    )?;
    let body = crate::crt_stream_emit::emit_body_with_hooks(
        &g,
        |pc, t| {
            let callee = match t {
                Target::Direct(0x401bbf) => "argv_mode_original",
                Target::Direct(0x4069d4) => return Ok(format!("cpu.call_activation(rt,{},0,|rt,c|argv_configure_wrapper(rt,c,inputs,platform,epoch.as_deref_mut()))?;",pc+g.nodes[&pc].length)),
                Target::Direct(0x401b0f) => return Ok(format!("cpu.call_activation(rt,{},0,|rt,c|onexit_register_original(rt,c,inputs,epoch.as_deref_mut()))?;",pc+g.nodes[&pc].length)),
                Target::Direct(0x401e00) => "cinit_empty_original",
                Target::Direct(0x40662e) => "cinit_app_type",
                Target::Direct(0x401bc3) => "cinit_get_mode",
                Target::Direct(0x407056) => "cinit_set_mode",
                Target::Direct(0x401bbc) => "cinit_zero",
                Target::Direct(0x4071ff) => "cinit_get_commode",
                Target::Direct(0x40197e) => "cinit_onexit_original",
                _ => return Err("first C initializer call".into()),
            };
            Ok(format!(
                "cpu.call_activation(rt,{},0,|rt,c|{callee}(rt,c,inputs))?;",
                pc + g.nodes[&pc].length
            ))
        },
        &Default::default(),
        256,
        |_, op| {
            if *op != Op::X87ClearExceptions {
                return Err("first C initializer thread effect".into());
            }
            Ok("inputs.validate(rt)?;cpu.validate_active(rt)?;if rt.x87.is_none(){return Err(\"startup x87 FNCLEX state unbound at 0x40158a\");}rt.clear_x87_exceptions(inputs.init)?;".into())
        },
        |pc, _| {
            Ok(if pc == 0x40157b {
                "cpu.r[0]=CrtValue::Pointer(rt.module_word_pointer(inputs.image,cpu.r[0])?);".into()
            } else {
                String::new()
            })
        },
        |_, _| Ok(None),
    )?;
    out.push_str(&format!("fn cinit_first_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{cinit_first_context(rt,cpu,inputs,None)}}fn cinit_first_context(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,mut epoch:Option<&mut NormalCallEpoch<'_>>)->Result<CrtValue,&'static str>{{cinit_first_platform(rt,cpu,inputs,epoch,None)}}fn cinit_first_platform(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,mut epoch:Option<&mut NormalCallEpoch<'_>>,platform:Option<&CrtNativePlatform>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{} {body}}}",guard(0x40155a,&bytes)));
    out.push_str(&format!("fn cinit_loop_bytes()->Vec<u8>{{vec!{:?}}}fn cinit_first_bytes()->Vec<u8>{{vec!{bytes:?}}}",raw(LOOP)));
    Ok(out)
}
fn guard(at: u32, bytes: &[u8]) -> String {
    format!("let p=rt.process_image_code(inputs.image,{at},{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"C initializer code read\")?!=&{bytes:?}{{return Err(\"C initializer code changed\");}}",bytes.len(),bytes.len())
}
#[test]
fn original_c_array_and_first_prefix_have_explicit_effect_boundaries() {
    assert!(Graph::decode(&crate::crt_ptd::raw(LOOP), 0x406ccc).is_err());
    let g = crate::crt_startup_table::graph(&crate::crt_ptd::raw(LOOP), 0x406ccc).unwrap();
    assert!(matches!(g.nodes[&0x406ce6].op, Op::IndirectCall(_)));
    source().expect("original guarded array and bounded callback bodies must lower");
}
