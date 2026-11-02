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
pub(crate) const TRUE_BYTE: &str = "b001c3";
pub(crate) const ENV_THUNK: &str = "e96afdffff";
pub(crate) const ENV_PREFIX: &str = "833d48ce410000740333c0c356e80d4a0000e8444f00008bf085f6750c50e8221300005983c8ff5ec35756e82a0000005985c0750583cfffeb0ca354ce410033ffa348ce41006a00e8f812000056e8f212000059598bc75f5ec3";
pub(crate) const ENV_PRODUCER_PREFIX: &str = "8bff558bec515156ff15e45041008bf085f60f84850000005356e8aaffffff33db2bc653535353d1f8505653538945f8e82affffff83c4248945fc85c0750b56ff15e850410033c0eb525750e879cdffff8bf8595385ff7511e88cc3ffff5956ff15e850410033c0eb3153ff75fc57ff75f8565353e8e5feffff83c42085c0750857e863c3ffffeb0853e85bc3ffff8bdf5956ff15e85041008bc35f5b5ec9c3";
pub(crate) const ENV_SCAN: &str = "8bff558bec8b55085733ff66393a7421568bca8d7102668b0183c102663bc775f52bced1f98d144a83c20266393a75e15e8d42025f5dc3";
pub(crate) const ENV_TABLE: &str = "8bff558bec5151538b5d0833c956578bf38a13eb1b80fa3d8bd60f44c18bc88d7a018a024284c075f92bd74603f28a168d410184d275de6a0450e84c1200008bf0595985f6750a50e89e12000033c0eb668975fceb528bcb8d79018a014184c075f92bcf8d41018945f880fa3d74376a0150e8141200008bf8595985ff743e53ff75f857e8820c000083c40c85c075488b45fc6a00893883c0048945fce8491200008b45f85903d88a1384d275a86a00e8361200008bc6595f5e5bc9c356e8220000006a00e8211200006a00e81a12000083c40c33c0ebe033c05050505050e816100000cc";
pub(crate) const ENV_TABLE_CLEANUP: &str = "8bff558bec568b750885f6741f8b06578bfeeb0c50e8ec1100008d7f048b075985c075f056e8dc110000595f5e5dc3";
pub(crate) const ENV_STRING_COPY: &str = "8bff558bec578b7d0885ff746a8b550c85d27463568b751085f6751ac60700e839050000c70016000000e8b00300008d46165e5f5dc38bcf2bf7660f1f4400008a040e8d49018841ff84c0742483ea0175ee85d2751b8817e800050000c70022000000e8770300005eb8220000005f5dc35e33c05f5dc3e8e1040000c70016000000e858030000b8160000005f5dc3";
pub(crate) const GET_COMMODE: &str = "b884ce4100c3";
pub(crate) const ONEXIT:&str="558bec803d85cc4100007404b0015dc3568b750885f6740583fe017562e81f08000085c0742685f675226888cc4100e84a5b00005985c0750f6894cc4100e83b5b00005985c0742b32c0eb3083c9ff890d88cc4100890d8ccc4100890d90cc4100890d94cc4100890d98cc4100890d9ccc4100c60585cc410001b0015e5dc36a05e833020000cc";
pub(crate) const OPTIONS: &str = "e869f6ffff8b4804830824894804e8e7ffffff8b4804830802894804c3";
pub(crate) const OPTIONS_GET: &str = "b8e8d24100c3";
pub(crate) const SCAN_GET: &str = "b8a8cc4100c3";
pub(crate) const POST_SLIST: &str = "68a0cc4100ff1530504100c3";
pub(crate) const POST_FLAG: &str = "33c0390548c041000f94c0c3";
pub(crate) const POST_ENCODE: &str =
    "8bff558beca100c04100b92000000083e01f2bc88b4508d3c8330500c04100a33ccd41005dc3";
pub(crate) const POST_NOOP: &str = "c20000";
pub(crate) const POST_FP: &str =
    "680000030068000001006a00e8b75a000083c40c85c07501c36a07e83f000000cc";
pub(crate) const FP_CONTROL:&str="8bff558bec8b4d108b550c81e1fffff7ff8bc223c1568b7508a9e0fcf0fc742a85f6740e6a006a00e83359000083c4088906e8f6050000c70016000000e86d040000b8160000005e5dc3515285f6740fe80b59000083c408890633c05e5dc3e8fc58000083c40833c05e5dc3";
pub(crate) const FP_WORD_PREFIX: &str = "8bff558bec83ec105356579bd97df8668b5df80fb7cb83e101c1e1048bd183ca08f6c3040f44d18bca83c904f6c3080f44ca8bd183ca02f6c3100f44d18bca83c901f6c3200f44ca8bf181ce00000800f6c3020f44f10fb7cb8bc18bd625000c00003d00080000771d741385c074243d00040000751d81ca00010000eb1581ca00020000eb0d3d000c0000750681ca0003000081e100030000741081f900020000750e81ca00000100eb0681ca000002008b7d0c8bca0fb7c381c900000400a9001000008bf78b4508f7d60f44ca23c723f10bf03bf10f84c900000056e8ae02000083c404668945fcd96dfc9bd97dfc668b5dfc0fb7cb83e1010fb7f3c1e1048bc68bd183ca08f6c3040f44d18bca83c904f6c3080f44ca8bd183ca02f6c3100f44d18bca83c901f6c3200f44ca8bd181ca00000800f6c3020f44d125000c00008bca3d00080000771d741385c074243d00040000751d81c900010000eb1581c900020000eb0d3d000c0000750681c90003000081e600030000741081fe00020000750e81c900000100eb0681c9000002008bf10fb7c381ce00000400a9001000000f44f1833db8cc4100010f8ccf01000081e71f030803897d0c0fae5df08b7df08bcfc1e9038bc783e1108bd183ca08f7c7000200000f44d18bca83c904f7c7000400000f44ca8bd183ca02f7c7000800000f44d18bca83c901f7c7001000000f44ca8bd981cb00000800f7c7000100000f44d925006000008bd33d00400000771d741385c074243d00200000751d81ca00010000eb1581ca00020000eb0d3d00600000750681ca0003000081e74080000083ef40741d81efc07f0000740d83ef40751681ca00000001eb0e81ca00000003eb0681ca000000028b4d0c8bc1234d08f7d023c20bc13bc20f84d200000050e879fbffff508945f4e8703a000083c4080fae5df48b7df48bcfc1e9038bc783e1108bd183ca08f7c7000200000f44d18bca83c904f7c7000400000f44ca8bd183ca02f7c7000800000f44d18bca83c901f7c7001000000f44ca8bd981cb00000800f7c7000100000f44d925006000008bd33d00400000771d741385c074243d00200000751d81ca00010000eb1581ca00020000eb0d3d00600000750681ca0003000081e74080000083ef40741d81efc07f0000740d83ef40751681ca00000001eb0e81ca00000003eb0681ca000000028bc233d60bc68bc881c900000080f7c21f0308005f5e0f45c15b8be55dc35f8bc65e5b8be55dc3";
pub(crate) const FP_WORD_CONVERT: &str = "8bff558bec5356578b7d088bf7c1ee048bd783e6018bdf8bc683c804f6c2080fb7c88bc60f44c80fb7d18bc283c808f6c3040fb7c88bc20f44c80fb7d18bc283c810f6c3020fb7c88bc20f44c80fb7d18bc283c820f6c3010fb7c88bc20f44c80fb7d18bc283c802f7c7000008000fb7c88bc20f44c88bd781e2000300000fb7c181fa00020000771e74158bc885d2742881fa0001000075200d00040000eb160d00080000eb0f8bc881fa0003000075080d000c00000fb7c88bc72500000300740f3d00000100750e81c900020000eb0681c9000300000fb7c98bc10d00100000f7c3000004005f0fb7c05e0f44c15b5dc3";
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
fn startup_c_array_platform(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,mut epoch:Option<&mut NormalCallEpoch<'_>>,platform:Option<&CrtNativePlatform>)->Result<CrtValue,&'static str>{{startup_c_array(rt,cpu,inputs,&mut |rt,c,_,target|match target.address(){{0x40155a=>cinit_first_platform(rt,c,inputs,epoch.as_deref_mut(),platform),0x401605=>cinit_second_original(rt,c,inputs),0x40c109=>cinit_default_mode(rt,c,inputs),0x404510=>{{let e=epoch.as_deref_mut().ok_or("FILE registry absent")?;let p=platform.ok_or("FILE platform absent")?;cinit_file_original(rt,c,inputs,p,e)}},0x4109ba=>Err("C initializer locale epoch composition unbound"),0x4127b0=>Err("C initializer raw feature BOOL storage unbound"),_=>Err("C initializer callback unbound")}})}}
"#,
        guard = guard(0x406ccc, &bytes).replace("inputs.image", "image")
    );
    out.push_str(&registration_source);
    out.push_str(&crate::crt_argv::source()?);
    out.push_str(&post_source()?);
    out.push_str(&thread_locale_source()?);
    out.push_str(&environment_prefix_source()?);
    out.push_str(&environment_producer_source()?);
    out.push_str(&environment_table_source()?);
    out.push_str(&file_source()?);
    let scan = environment_scan_body()?;
    out.push_str(&format!("fn cinit_environment_scan(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}{scan}}}",guard(0x40b92f,&raw(ENV_SCAN))));
    for (name, at, literal) in [
        ("cinit_app_type", 0x40662e, APP_TYPE),
        ("cinit_get_mode", 0x401bc3, GET_MODE),
        ("cinit_zero", 0x401bbc, ZERO),
        ("cinit_true_byte", 0x401bd5, TRUE_BYTE),
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
    let thunk = raw("e96bfeffff");
    if Graph::decode_instruction(&thunk, 0x401d4c)?.op
        != Op::Ordinary(crate::graph::Operation::Jump(0x401bbc))
    {
        return Err("post-environment original tail target".into());
    }
    out.push_str(&format!("fn cinit_post_environment_tail(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}cinit_zero(rt,cpu,inputs)}}",guard(0x401d4c,&thunk)));
    let bytes = raw(FIRST);
    let g = cut_graph(
        &bytes,
        0x40155a,
        0x4015fd,
        &[(0x4015fd, "C initializer fatal path unbound at 0x4015fd")],
    )?;
    let body = crate::crt_stream_emit::emit_body_with_hooks(
        &g,
        |pc, t| {
            let callee = match t {
                Target::Direct(0x401bc9) => return Ok(format!("let p=platform.ok_or(\"post-argv SLIST native profile unbound\")?;cpu.call_activation(rt,{},0,|rt,c|cinit_slist_original(rt,c,inputs,p))?;",pc+g.nodes[&pc].length)),
                Target::Direct(0x401c1f) => "cinit_post_flag",
                Target::Direct(0x4066b0) => "cinit_encode_callback",
                Target::Direct(0x401bf9) => "cinit_post_noop",
                Target::Direct(0x401bd8) => "cinit_fp_prefix",
                Target::Direct(0x401bd5) => "cinit_true_byte",
                Target::Direct(0x406c9c) => return Ok(format!("let e=epoch.as_deref_mut().ok_or(\"environment registry context absent\")?;let p=platform.ok_or(\"environment platform absent\")?;cpu.call_activation(rt,{},0,|rt,c|cinit_environment_thunk(rt,c,inputs,p,e))?;",pc+g.nodes[&pc].length)),
                Target::Direct(0x407158) => return Ok(format!("let e=epoch.as_deref_mut().ok_or(\"thread locale live registry absent\")?;let p=platform.ok_or(\"thread locale platform absent\")?;cpu.call_activation(rt,{},0,|rt,c|cinit_thread_locale_query(rt,c,inputs,p,e))?;",pc+g.nodes[&pc].length)),
                Target::Direct(0x401bbf) => "argv_mode_original",
                Target::Direct(0x4069d4) => return Ok(format!("cpu.call_activation(rt,{},0,|rt,c|argv_configure_wrapper(rt,c,inputs,platform,epoch.as_deref_mut()))?;",pc+g.nodes[&pc].length)),
                Target::Direct(0x401b0f) => return Ok(format!("cpu.call_activation(rt,{},0,|rt,c|onexit_register_original(rt,c,inputs,epoch.as_deref_mut()))?;",pc+g.nodes[&pc].length)),
                Target::Direct(0x401e00) => "cinit_empty_original",
                Target::Direct(0x40662e) => "cinit_app_type",
                Target::Direct(0x401bc3) => "cinit_get_mode",
                Target::Direct(0x407056) => "cinit_set_mode",
                Target::Direct(0x401bbc) => "cinit_zero",
                Target::Direct(0x401d4c) => "cinit_post_environment_tail",
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

fn post_source() -> Result<String, String> {
    let mut out = String::new();
    let roles = BTreeMap::from(
        [0x41c000, 0x41c048, 0x41cd3c, 0x41ccb8].map(|a| (a, "CrtRegionKind::Module".into())),
    );
    for (name, address, hex) in [
        ("cinit_slist_original", 0x401bc9, POST_SLIST),
        ("cinit_post_flag", 0x401c1f, POST_FLAG),
        ("cinit_encode_callback", 0x4066b0, POST_ENCODE),
        ("cinit_post_noop", 0x401bf9, POST_NOOP),
        ("cinit_fp_prefix", 0x401bd8, POST_FP),
        ("cinit_fp_control_original", 0x4076a0, FP_CONTROL),
        ("cinit_fp_word_prefix", 0x40d000, FP_WORD_PREFIX),
        ("cinit_fp_word_convert", 0x40d390, FP_WORD_CONVERT),
    ] {
        let bytes = crate::crt_ptd::raw(hex);
        let g = if name == "cinit_fp_prefix" {
            cut_graph(
                &bytes,
                address,
                0x401bf1,
                &[(0x401bf1, "original FP-control failure termination unbound")],
            )?
        } else {
            Graph::decode(&bytes, address)?
        };
        let body = crate::crt_stream_emit::emit_body_with_thread(
            &g,
            |pc, target| {
                let next = pc + g.nodes[&pc].length;
                Ok(match target {
                  Target::Import(0x415030)=>format!("rt.process_image_import(inputs.image,0x415030,\"kernel32.dll\",\"InitializeSListHead\")?;cpu.call_activation(rt,{next},4,|rt,c|platform.slist_head_call(rt,c,inputs.init,inputs.image))?;"),
                  Target::Direct(0x4076a0)=>format!("cpu.call_activation(rt,{next},0,|rt,c|cinit_fp_control_original(rt,c,inputs))?;"),
                  Target::Direct(0x40d000)=>format!("cpu.call_activation(rt,{next},0,|rt,c|cinit_fp_word_prefix(rt,c,inputs))?;"),
                  Target::Direct(0x40d390)=>format!("cpu.call_activation(rt,{next},0,|rt,c|cinit_fp_word_convert(rt,c,inputs))?;"),
                  Target::Direct(0x40ce10)|Target::Direct(0x410d10)=>"return Err(\"FP MXCSR change/EH4 loader unsupported\");".into(),
                  Target::Direct(0x407ccd)=>"return Err(\"FP invalid-mask errno acquisition unbound\");".into(),
                  Target::Direct(0x407b4f)=>"return Err(\"FP invalid-parameter effect unbound\");".into(),
                  _=>return Err("post-argv helper call".into())
                })
            },
            &roles,
            1024,
            |pc, op| crate::crt_stream_emit::fp_effect(pc, op, &roles, "inputs.init"),
        )?;
        let extra = if name == "cinit_slist_original" {
            ",platform:&CrtNativePlatform"
        } else {
            ""
        };
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs{extra})->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}{body}}}",guard(address,&bytes)));
    }
    Ok(out)
}

#[test]
fn slist_opaque_initialization_expires_reads_and_protects_state() {
    crate::crt_stream_callees_tests::native(
        "",
        r#"
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let data=rt.map_region(0x20000,512,CrtRegionKind::Module,Some(&[0xa5;512])).unwrap();let p=rt.offset(data,32).unwrap();let fact=rt.memory.prove_read(p.cap,p.owner,p.address(),8).unwrap();let old=rt.serial;let head=rt.initialize_slist_head(init,p).unwrap();assert!(head.serial>old);assert_eq!((head.header.cap,head.header.address(),head.header.size),(p.cap,p.address(),8));rt.slist_head(head).unwrap();assert!(rt.memory.read_proven(fact,p.owner).is_err());assert_eq!(rt.memory.read(p.address(),8),Err(guest_memory::Fault::Uninitialized));assert_eq!(rt.load(p,32),Err("CRT opaque SLIST header bytes"));assert_eq!(rt.store(p,8,CrtValue::scalar(0)),Err("CRT opaque SLIST header bytes"));assert_eq!(rt.memory.read(data.address(),32).unwrap(),&[0xa5;32]);assert_eq!(rt.memory.read(p.address()+8,8).unwrap(),&[0xa5;8]);let newer=rt.initialize_slist_head(init,p).unwrap();assert_ne!(newer,head);assert!(rt.slist_head(head).is_err());rt.slist_head(newer).unwrap();assert_eq!(rt.slist_heads.values().count(),1);let beside=rt.initialize_slist_head(init,rt.offset(p,8).unwrap()).unwrap();assert_ne!(beside,newer);assert_eq!(rt.slist_heads.values().count(),2);rt.memory.release(data.cap,data.owner).unwrap();assert!(rt.slist_head(newer).is_err());assert!(rt.slist_head(beside).is_err());
 for mode in 0..9{
  let(mut rt,mut init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let data=rt.map_region(0x20000,64,CrtRegionKind::Module,Some(&[0x5a;64])).unwrap();let stack=rt.map_region(0x30000,128,CrtRegionKind::Stack,None).unwrap();let mut p=rt.offset(data,32).unwrap();let serial=rt.serial;
  match mode{0=>p=rt.offset(data,60).unwrap(),1=>p=rt.offset(p,1).unwrap(),2=>{rt.memory.protect_data_with_old((data.cap,data.owner,data.address(),64),2,(stack.cap,stack.owner,stack.address())).unwrap();},3=>rt.memory.release(data.cap,data.owner).unwrap(),4=>init.serial+=1,5=>p=stack,6=>{rt.tags.insert(p.address(),CrtValue::ProtectedReturn(51));},7=>{rt.store(rt.offset(p,6).unwrap(),32,CrtValue::Pointer(stack)).unwrap();},8=>rt.errno_cell=Some(rt.subrange(p,4).unwrap()),_=>unreachable!()}
  let before=if mode!=3{Some(rt.memory.read(data.address()+32,8).unwrap().to_vec())}else{None};assert!(rt.initialize_slist_head(init,p).is_err(),"negative SLIST mode {mode}");assert!(rt.slist_heads.is_empty());assert_eq!(rt.serial,serial);if let Some(before)=before{assert_eq!(rt.memory.read(data.address()+32,8).unwrap(),before);}
 }
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let data=rt.map_region(0x20000,512,CrtRegionKind::Module,Some(&[0x69;512])).unwrap();for n in 0..32{rt.initialize_slist_head(init,rt.offset(data,n*8).unwrap()).unwrap();}let p=rt.offset(data,256).unwrap();assert_eq!(rt.initialize_slist_head(init,p),Err("CRT SLIST capacity domain"));assert_eq!(rt.memory.read(p.address(),8).unwrap(),&[0x69;8]);let before=rt.slist_heads.values().count();rt.initialize_slist_head(init,data).unwrap();assert_eq!(rt.slist_heads.values().count(),before);
 "#,
        "slist-opaque-state",
    );
}

pub(crate) const THREAD_LOCALE:&str="8bff558bec56e87e3100008b55088bf06a00588b8e50030000f6c1020f94c04083faff743385d2743683fa01741f83fa027415e83d0b0000c70016000000e8b409000083c8ffeb1783e1fdeb0383c902898e50030000eb07830db8c74100ff5e5dc3";
pub(crate) const THREAD_REQUIRED: &str = "e84c00000085c00f8411d5ffffc3";
fn thread_locale_body(
    call: impl FnMut(u32, Target) -> Result<String, String>,
) -> Result<String, String> {
    let g = Graph::decode(&crate::crt_ptd::raw(THREAD_LOCALE), 0x407158)?;
    crate::crt_stream_emit::emit_body(
        &g,
        call,
        &BTreeMap::from([(0x41c7b8, "CrtRegionKind::Module".into())]),
        128,
    )
}
fn thread_locale_source() -> Result<String, String> {
    let raw = crate::crt_ptd::raw(THREAD_REQUIRED);
    let mut g = Graph {
        origin: 0x40a2e1,
        end: 0x40a2e1 + raw.len() as u32,
        nodes: BTreeMap::new(),
    };
    // Decode every original instruction; the conditional external edge is an
    // explicit rejected termination boundary, never a successful graph exit.
    let mut at = 0;
    for length in [5, 2, 6, 1] {
        let pc = 0x40a2e1 + at as u32;
        let node = Graph::decode_instruction(&raw[at..at + length], pc)?;
        at += node.length as usize;
        g.nodes.insert(pc, node);
    }

    let body = crate::crt_stream_emit::emit_body_with_exit(
        &g,
        |pc, t| {
            if t != Target::Direct(0x40a332) {
                return Err("thread locale PTD target".into());
            }
            Ok(format!("cpu.call_activation(rt,{},0,|rt,c|ptd_get_native_registered_with_lazy(rt,c,epoch,inputs,platform,|rt,c,e|ucrt_lazy_native(rt,c,inputs,platform,e)))?;",pc+g.nodes[&pc].length))
        },
        &Default::default(),
        32,
        |_, _| Err("thread locale unexpected thread effect".into()),
        |_, _| Ok(String::new()),
        |_, _| Ok(None),
        Some(0x4077ff),
    )?;
    let terminal = "if pc==4225023{return Ok(cpu.r[0]);}";
    if !body.contains(terminal) {
        return Err("thread locale termination boundary missing".into());
    }
    let body = body.replace(
        terminal,
        "if pc==4225023{return Err(\"thread locale required PTD termination unbound\");}",
    );
    let mut out=format!("fn cinit_thread_required(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}{body}}}",guard(0x40a2e1,&raw));
    let body = thread_locale_body(|pc, t| {
        Ok(match t{Target::Direct(0x40a2e1)=>format!("cpu.call_activation(rt,{},0,|rt,c|cinit_thread_required(rt,c,inputs,platform,epoch))?;locale_required_view(rt,platform,cpu.r[0])?;CrtCpu::pointer(cpu.r[0])?;",pc+5),_=>"return Err(\"thread locale nonquery effects unsupported\");".into()})
    })?;
    let bytes = crate::crt_ptd::raw(THREAD_LOCALE);
    out.push_str(&format!("fn cinit_thread_locale_query(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;platform.validate(rt,inputs.init)?;cpu.validate_active(rt)?;epoch.state()?;let sp=CrtCpu::pointer(cpu.r[4])?;if rt.load(rt.offset(sp,4)?,32)?.known_scalar()?!=0{{return Err(\"thread locale nonquery mode unsupported\");}}{}{body}}}",guard(0x407158,&bytes)));
    Ok(out)
}

#[test]
fn original_thread_locale_query_preserves_memory_and_rejects_unknown_or_stale_inputs() {
    let body=thread_locale_body(|pc,t|Ok(match t{Target::Direct(0x40a2e1)=>format!("cpu.call_activation(rt,{},0,|rt,c|{{let value=lookup(rt)?;c.clobber(value);c.finish(rt)}})?;",pc+5),_=>"return Err(\"nonquery path\");".into()})).unwrap();
    let extra=format!("fn query(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,lookup:&mut impl FnMut(&mut CrtStreamRuntime)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{cpu.validate_active(rt)?;let sp=CrtCpu::pointer(cpu.r[4])?;if rt.load(rt.offset(sp,4)?,32)?.known_scalar()?!=0{{return Err(\"nonquery\");}}{body}}}");
    crate::crt_stream_callees_tests::native_bounded_stack(
        &extra,
        r#"
#[inline(never)]fn one(mode:u32){
 let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0x10000,4096,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,2048).unwrap();let p=rt.map_region(0x30000,868,CrtRegionKind::ThreadData,Some(&[0;868])).unwrap();let cell=rt.offset(p,848).unwrap();
 let value=if mode==0{CrtValue::scalar(1)}else if mode==1{CrtValue::scalar(3)}else if mode==2{CrtValue::Scalar{bits:0,known:!2}}else{CrtValue::scalar(0xffffffff)};rt.store(cell,32,value).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(73)).unwrap();rt.store(rt.offset(sp,4).unwrap(),32,if mode==3{CrtValue::Scalar{bits:0,known:0}}else if mode>=4&&mode<=7{CrtValue::scalar([1,2,3,u32::MAX][(mode-4)as usize])}else{CrtValue::scalar(0)}).unwrap();let mut cpu=CrtCpu::new(sp,73).unwrap();cpu.flags=CrtFlags{cf:Some(true),sf:Some(true),zf:Some(false),of:Some(true)};let saved=cpu.r;let mut calls=0;
 let result=query(&mut rt,&mut cpu,&mut|rt|{calls+=1;if mode==8{rt.memory.release(p.cap,p.owner).unwrap();}if mode==9{rt.store(cell,32,CrtValue::ProtectedReturn(77))?;}Ok(CrtValue::Pointer(p))});
 if mode==0||mode==1{assert_eq!(result,Ok(CrtValue::scalar(if mode==0{2}else{1})));assert!(cpu.returned);for i in[3,5,6,7]{assert_eq!(cpu.r[i],saved[i]);}assert_eq!((cpu.flags.cf,cpu.flags.zf,cpu.flags.sf,cpu.flags.of),(Some(false),Some(true),Some(false),Some(false)));assert_eq!(rt.load(cell,32).unwrap(),value);let before=calls;assert!(query(&mut rt,&mut cpu,&mut |_|{calls+=1;Ok(CrtValue::Pointer(p))}).is_err());assert_eq!(calls,before);}
 else{assert!(result.is_err(),"negative query {mode}");assert!(!cpu.returned);assert_eq!(calls,if (3..=7).contains(&mode){0}else{1});if mode!=8&&mode!=9{assert_eq!(rt.load(cell,32).unwrap(),value);}}
}
for mode in 0..10{one(mode);}
"#,
        "thread-locale-query",
    );
}

fn environment_prefix_source() -> Result<String, String> {
    let bytes = crate::crt_ptd::raw(ENV_PREFIX);
    let g = Graph::decode(&bytes, 0x406a0b)?;
    let body = crate::crt_stream_emit::emit_body(
        &g,
        |pc, t| {
            if t == Target::Direct(0x40b966) {
                return Ok(format!(
                    "cpu.call_activation(rt,{},0,|rt,c|cinit_env_producer_prefix(rt,c,inputs,platform))?;",
                    pc + 5
                ));
            }
            if t == Target::Direct(0x406a65) {
                return Ok(format!("cpu.call_activation(rt,{},0,|rt,c|cinit_environment_table(rt,c,inputs,platform,epoch))?;",pc+5));
            }
            if t == Target::Direct(0x407d50) {
                return Ok(format!(
                    "cpu.call_activation(rt,{},0,|rt,c|ucrt_free_native(rt,c,inputs))?;",
                    pc + 5
                ));
            }
            if t != Target::Direct(0x40b42a) {
                return Err("environment locale initialization target".into());
            }
            Ok(format!("cpu.call_activation(rt,{},0,|rt,c|locale_startup_original(rt,c,inputs,platform,epoch))?;",pc+5))
        },
        &BTreeMap::from_iter([0x41ce48, 0x41ce54].map(|a| (a, "CrtRegionKind::Module".into()))),
        128,
    )?;
    let thunk = crate::crt_ptd::raw(ENV_THUNK);
    let node = Graph::decode_instruction(&thunk, 0x406c9c)?;
    if node.op != Op::Ordinary(crate::graph::Operation::Jump(0x406a0b)) {
        return Err("environment original tail target".into());
    }
    Ok(format!("fn cinit_environment_prefix(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}{body}}}fn cinit_environment_thunk(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}cinit_environment_prefix(rt,cpu,inputs,platform,epoch)}}",guard(0x406a0b,&bytes),guard(0x406c9c,&thunk)))
}

#[test]
fn original_boolean_helper_preserves_upper_knowledge_flags_and_return_authority() {
    let raw = crate::crt_ptd::raw(TRUE_BYTE);
    let g = Graph::decode(&raw, 0x401bd5).unwrap();
    let body = crate::crt_stream_emit::emit_body(
        &g,
        |_, _| Err("unexpected call".into()),
        &Default::default(),
        8,
    )
    .unwrap();
    let extra=format!("fn helper(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{cpu.validate_active(rt)?;{body}}}");
    crate::crt_stream_callees_tests::native_bounded_stack(
        &extra,
        r#"
#[inline(never)]fn one(mode:u32){let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0x10000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(81)).unwrap();let mut c=CrtCpu::new(sp,81).unwrap();let bits=[0,0xffffffff,0x12345678,0xaabbccdd][(mode%4)as usize];let known=if mode==4{0}else if mode==5{0xffff0000}else{u32::MAX};c.r[0]=CrtValue::Scalar{bits:bits&known,known};c.flags=CrtFlags{cf:Some(true),zf:None,sf:Some(false),of:Some(true)};let saved=c.r;let flags=(c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of);if mode==6{rt.tags.insert(sp.address(),CrtValue::ProtectedReturn(82));}let got=helper(&mut rt,&mut c);if mode==6{assert!(got.is_err());assert!(!c.returned);assert_eq!(c.r,saved);}else{assert_eq!(got,Ok(CrtValue::Scalar{bits:(bits&known&!255)|1,known:known|255}));assert!(c.returned);for n in[1,2,3,5,6,7]{assert_eq!(c.r[n],saved[n]);}assert!(helper(&mut rt,&mut c).is_err());}assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),flags);}
for mode in 0..7{one(mode);}
"#,
        "original-bool-helper",
    );
}

#[test]
fn environment_prefix_observes_init_flag_and_preserves_prior_callback_failure_effects() {
    let bytes = crate::crt_ptd::raw(ENV_PREFIX);
    let g = cut_graph(
        &bytes,
        0x406a0b,
        0x406a1d,
        &[(0x406a1d, "environment acquisition unsupported")],
    )
    .unwrap();
    let body = crate::crt_stream_emit::emit_body(
        &g,
        |pc, t| {
            assert_eq!(t, Target::Direct(0x40b42a));
            Ok(format!(
                "cpu.call_activation(rt,{},0,|rt,c|callback(rt,c))?;",
                pc + 5
            ))
        },
        &BTreeMap::from([(0x41ce48, "CrtRegionKind::Module".into())]),
        64,
    )
    .unwrap();
    let extra=format!("fn prefix(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,callback:&mut impl FnMut(&mut CrtStreamRuntime,&mut CrtCpu)->Result<CrtValue,&'static str>)->Result<CrtValue,&'static str>{{cpu.validate_active(rt)?;{body}}}");
    crate::crt_stream_callees_tests::native_bounded_stack(
        &extra,
        r#"
#[inline(never)]fn one(mode:u32){let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let cell=rt.map_region(0x41ce48,4,CrtRegionKind::Module,None).unwrap();rt.store(cell,32,if mode==2{CrtValue::Scalar{bits:0,known:0}}else{CrtValue::scalar(u32::from(mode==0))}).unwrap();let marker=rt.map_region(0x420000,4,CrtRegionKind::Module,Some(&[0;4])).unwrap();let stack=rt.map_region(0x10000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(91)).unwrap();let mut c=CrtCpu::new(sp,91).unwrap();let saved=c.r;let mut calls=0;let got=prefix(&mut rt,&mut c,&mut|rt,c|{calls+=1;rt.store(marker,32,CrtValue::scalar(77))?;if mode==3{return Err("injected callback failure");}c.clobber(CrtValue::scalar(1));c.finish(rt)});
 if mode==0{assert_eq!(got,Ok(CrtValue::scalar(0)));assert!(c.returned);assert_eq!(calls,0);for n in[3,5,6,7]{assert_eq!(c.r[n],saved[n]);}assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),(Some(false),Some(true),Some(false),Some(false)));}else{assert_eq!(got,Err(if mode==2{"CRT unknown scalar bits observed"}else if mode==3{"injected callback failure"}else{"environment acquisition unsupported"}));assert!(!c.returned);assert_eq!(calls,u32::from(mode!=2));if mode!=2{let sp=CrtCpu::pointer(c.r[4]).unwrap();if mode==3{assert!(matches!(rt.load(sp,32).unwrap(),CrtValue::ProtectedReturn(_)));assert_eq!(rt.load(rt.offset(sp,4).unwrap(),32).unwrap(),saved[6]);}else{assert_eq!(rt.load(sp,32).unwrap(),saved[6]);}assert_eq!(rt.load(marker,32).unwrap(),CrtValue::scalar(77));}else{assert_eq!(c.r[4],saved[4]);assert_eq!(rt.load(marker,32).unwrap(),CrtValue::scalar(0));}}
}for mode in 0..4{one(mode);}
"#,
        "env-prefix",
    );
}

fn environment_producer_source() -> Result<String, String> {
    let bytes = crate::crt_ptd::raw(ENV_PRODUCER_PREFIX);
    let g = Graph::decode(&bytes, 0x40b966)?;
    let body = crate::crt_stream_emit::emit_body(
        &g,
        |pc, target| {
            if target == Target::Direct(0x40b92f) {
                return Ok(format!(
                    "cpu.call_activation(rt,{},0,|rt,c|cinit_environment_scan(rt,c,inputs))?;",
                    pc + g.nodes[&pc].length
                ));
            }
            let next = pc + g.nodes[&pc].length;
            Ok(match target{
                Target::Direct(0x40b8c5)=>format!("cpu.call_activation(rt,{next},0,|rt,c|argv_wide_original(rt,c,inputs,platform))?;"),
                Target::Direct(0x408730)=>format!("cpu.call_activation(rt,{next},0,|rt,c|malloc_original_native(rt,c,inputs))?;"),
                Target::Direct(0x407d50)=>format!("cpu.call_activation(rt,{next},0,|rt,c|ucrt_free_null(rt,c,inputs))?;"),
                Target::Import(0x4150e4)=>format!("rt.process_image_import(inputs.image,0x4150e4,\"kernel32.dll\",\"GetEnvironmentStringsW\")?;cpu.call_activation(rt,{next},0,|rt,c|platform.environment_call(rt,c,inputs.init,false))?;"),
                Target::Import(0x4150e8)=>format!("rt.process_image_import(inputs.image,0x4150e8,\"kernel32.dll\",\"FreeEnvironmentStringsW\")?;cpu.call_activation(rt,{next},4,|rt,c|platform.environment_call(rt,c,inputs.init,true))?;"),
                _=>return Err("environment producer unexpected call".into())
            })
        },
        &Default::default(),
        256,
    )?;
    Ok(format!("fn cinit_env_producer_prefix(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}{body}}}",guard(0x40b966,&bytes)))
}

// The declared block is <=32767 words and <=256 entries. The original loop
// needs five instructions per word plus bounded per-entry/frame work.
fn environment_scan_body() -> Result<String, String> {
    let bytes = crate::crt_ptd::raw(ENV_SCAN);
    let graph = Graph::decode(&bytes, 0x40b92f)?;
    crate::crt_stream_emit::emit_body(
        &graph,
        |_, _| Err("environment scan unexpected call".into()),
        &Default::default(),
        262144,
    )
}

#[test]
fn original_environment_scan_preserves_word_bounds_lifetime_and_failure_progress() {
    let body = environment_scan_body().unwrap();
    let extra=format!("fn scan(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{cpu.validate_active(rt)?;{body}}}");
    crate::crt_stream_callees_tests::native_bounded_stack(
        &extra,
        r#"
 #[inline(never)]fn one(mode:u32){
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,131072).unwrap();
 let words:Vec<u16>=match mode{0=>vec![0,0],1=>"A=雪😀\0B=\0\0".encode_utf16().collect(),2=>vec![65,0],3=>vec![65,66],4=>vec![0xd800,0xdc00,0,0],5=>vec![0],6=>vec![65,0,0],7=>vec![65,0,0],8=>vec![65,0,0],10=>vec![0xd800,0,0],11=>{let mut v=vec![65;32765];v.extend([0,0]);v},_=>vec![65,0,66,0,0]};
 let bytes:Vec<u8>=words.iter().copied().flat_map(u16::to_le_bytes).collect();
 let p=rt.map_region(0x20000,bytes.len()as u32,CrtRegionKind::Stack,if mode==7{None}else{Some(&bytes)}).unwrap();
 let stack=rt.map_region(0x40000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(91)).unwrap();rt.store(rt.offset(sp,4).unwrap(),32,if mode==8{CrtValue::scalar(p.address())}else{CrtValue::Pointer(p)}).unwrap();let mut c=CrtCpu::new(sp,91).unwrap();let saved=c.r;
 if mode==6{rt.retire_region(p).unwrap();}if mode==7{rt.partial.insert(p.address(),(0,0));}
 let got=scan(&mut rt,&mut c);
 if matches!(mode,2|3|6|7|8){assert_eq!(got,Err(match mode{2|3=>"CRT pointer complete range/identity",6=>"CRT stale/foreign pointer",7=>"CRT unknown scalar bits observed",8=>"CRT scalar address lacks provenance",_=>unreachable!()}),"invalid scan{mode}");assert!(!c.returned);assert_eq!(rt.load(rt.offset(sp,-4).unwrap(),32).unwrap(),saved[5]);if mode==2||mode==3{let cursor=CrtCpu::pointer(c.r[2]).unwrap();assert_eq!(cursor.cap,p.cap);if mode==2{assert_eq!(c.r[1],CrtValue::scalar(1));assert_eq!(cursor.address(),p.address()+4);}else{assert_eq!(CrtCpu::pointer(c.r[1]).unwrap().address(),p.address()+4);}assert_ne!(c.r[5],saved[5]);}}
 else{let result=CrtCpu::pointer(got.unwrap()).unwrap();assert_eq!(result.cap,p.cap);assert_eq!(result.owner,p.owner);assert_eq!(result.address(),p.address()+if mode==0||mode==5{2}else{bytes.len()as u32});assert!(c.returned);for r in[3,5,6,7]{assert_eq!(c.r[r],saved[r]);}assert!(scan(&mut rt,&mut c).is_err());}
 assert_eq!(rt.memory.read(p.address(),p.size).ok(),if mode==6||mode==7{None}else{Some(bytes.as_slice())});let _=init;
 }for mode in 0..12{one(mode);}
 "#,
        "environment-original-scan",
    );
}

fn environment_table_source() -> Result<String, String> {
    let mut source = String::new();
    for (name, start, literal, budget) in [
        ("cinit_environment_table", 0x406a65, ENV_TABLE, 1048576),
        (
            "cinit_environment_table_cleanup",
            0x406b4a,
            ENV_TABLE_CLEANUP,
            8192,
        ),
        (
            "cinit_environment_string_copy",
            0x407770,
            ENV_STRING_COPY,
            1048576,
        ),
    ] {
        let bytes = crate::crt_ptd::raw(literal);
        let mut graph = if start == 0x406a65 {
            crate::crt_startup_table::graph(&bytes[..bytes.len() - 1], start)?
        } else {
            Graph::decode(&bytes, start)?
        };
        // The invalid-parameter routine is declared nonreturning; retain a rejected
        // terminator after its actual CALL rather than trying to decode INT3.
        if start == 0x406a65 {
            graph.nodes.insert(
                0x406b49,
                Node {
                    length: 1,
                    op: Op::Reject("environment table invalid-parameter termination unbound"),
                    successors: vec![],
                },
            );
        }
        if start == 0x407770 {
            crate::crt_stream_emit::bind_address_relation(&mut graph, 0x4077a8, 0x4077b0, 12, 4)?;
        }
        let body = crate::crt_stream_emit::emit_body(
            &graph,
            |pc, target| {
                let next = pc + graph.nodes[&pc].length;
                Ok(match target{
    Target::Direct(0x407cf0)=>format!("cpu.call_activation(rt,{next},0,|rt,c|ucrt_calloc_native(rt,c,inputs,platform,epoch))?;"),
    Target::Direct(0x407770)=>format!("cpu.call_activation(rt,{next},0,|rt,c|cinit_environment_string_copy(rt,c,inputs,platform,epoch))?;"),
    Target::Direct(0x406b4a)=>format!("cpu.call_activation(rt,{next},0,|rt,c|cinit_environment_table_cleanup(rt,c,inputs,platform,epoch))?;"),
    Target::Direct(0x407d50)=>format!("cpu.call_activation(rt,{next},0,|rt,c|ucrt_free_native(rt,c,inputs))?;"),
    Target::Direct(0x407ccd|0x407b4f|0x407b5f)=>"return Err(\"environment string-copy errno/invalid-parameter effect unbound\");".into(),
    _=>return Err(format!("environment table unexpected target{target:?}"))
   })
            },
            &Default::default(),
            budget,
        )?;
        source.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}{body}}}",guard(start,&bytes)));
    }
    Ok(source)
}

#[test]
fn original_string_copy_exposes_cross_allocation_address_cancellation_without_granting_authority() {
    let graph = Graph::decode(&crate::crt_ptd::raw(ENV_STRING_COPY), 0x407770).unwrap();
    let body = crate::crt_stream_emit::emit_body(
        &graph,
        |_, _| Ok("return Err(\"copy error contract unbound\");".into()),
        &Default::default(),
        256,
    )
    .unwrap();
    let extra = format!("fn copy(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{cpu.validate_active(rt)?;{body}}}");
    crate::crt_stream_callees_tests::native_bounded_stack(
        &extra,
        r#"
#[inline(never)]fn one(mode:u32){
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let CrtValue::Heap(heap)=rt.native_process_heap(init).unwrap()else{panic!()};let stack=rt.map_region(0x40000,1024,CrtRegionKind::Stack,None).unwrap();let shared=mode==1||mode==5;
 let source=if shared{rt.offset(stack,64).unwrap()}else{rt.native_heap_allocate(init,heap,0,3).unwrap()};let target=if shared{rt.offset(stack,128).unwrap()}else{rt.native_heap_allocate(init,heap,0,3).unwrap()};
 for(i,b)in [65,66,0].into_iter().enumerate(){rt.store(rt.offset(source,i as i64).unwrap(),8,if mode==5&&i==1{CrtValue::Scalar{bits:0,known:0}}else{CrtValue::scalar(b)}).unwrap();}
 if mode==3{rt.free_allocation(source).unwrap();}if mode==4{rt.free_allocation(target).unwrap();}
 let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(91)).unwrap();for(i,v)in [CrtValue::Pointer(target),CrtValue::scalar(3),CrtValue::Pointer(source)].into_iter().enumerate(){rt.store(rt.offset(sp,4+i as i64*4).unwrap(),32,v).unwrap();}let mut c=CrtCpu::new(sp,91).unwrap();let saved=c.r;
 if mode==2{let difference=c.binary_number(&rt,2,CrtValue::Pointer(source),CrtValue::Pointer(target)).unwrap();assert!(CrtCpu::pointer(difference).is_err());c.r[6]=difference;c.r[1]=CrtValue::Pointer(target);assert_eq!(CrtCpu::number(difference).unwrap().wrapping_add(target.address()),source.address());assert_eq!(c.address(&rt,Some(6),Some(1),1,0,None),Err("CRT pointer complete range/identity"));return;}
 let got=copy(&mut rt,&mut c);
 if mode==1{assert_eq!(got,Ok(CrtValue::scalar(0)));assert!(c.returned);assert_eq!(rt.memory.read(target.address(),3).unwrap(),&[65,66,0]);for n in[3,5,6,7]{assert_eq!(c.r[n],saved[n]);}}
 else{assert_eq!(got,Err(match mode{0=>"CRT unrelated pointer subtraction",3|4=>"CRT stale/foreign pointer",5=>"CRT unknown ZF",_=>unreachable!()}));assert!(!c.returned);if mode==0{assert!(rt.load(target,8).unwrap().known_scalar().is_err());assert_eq!(c.r[6],CrtValue::Pointer(source));assert_eq!(c.r[7],CrtValue::Pointer(target));}if mode==5{assert_eq!(rt.load(target,8),Ok(CrtValue::scalar(65)));assert!(rt.load(rt.offset(target,1).unwrap(),8).unwrap().known_scalar().is_err());assert!(rt.load(rt.offset(target,2).unwrap(),8).unwrap().known_scalar().is_err());}}
}for mode in 0..6{one(mode);}
"#,
        "environment-copy-address-gap",
    );
}

#[test]
fn checked_original_copy_binds_live_arguments_and_preserves_partial_effects() {
    let mut graph = Graph::decode(&crate::crt_ptd::raw(ENV_STRING_COPY), 0x407770).unwrap();
    crate::crt_stream_emit::bind_address_relation(&mut graph, 0x4077a8, 0x4077b0, 12, 4).unwrap();
    let body = crate::crt_stream_emit::emit_body(
        &graph,
        |_, _| Ok("return Err(\"copy error contract unbound\");".into()),
        &Default::default(),
        256,
    )
    .unwrap();
    let extra=format!("fn copy(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{cpu.validate_active(rt)?;{body}}}");
    crate::crt_stream_callees_tests::native_bounded_stack(
        &extra,
        r#"
#[inline(never)]fn one(mode:u32){
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let CrtValue::Heap(heap)=rt.native_process_heap(init).unwrap()else{panic!()};let stack=rt.map_region(0x40000,1024,CrtRegionKind::Stack,None).unwrap();
 let root=rt.native_heap_allocate(init,heap,0,8).unwrap();let source=if mode==2{rt.offset(root,2).unwrap()}else if mode==3{rt.subrange(root,1).unwrap()}else{root};let target=if mode==1{root}else{rt.native_heap_allocate(init,heap,0,4).unwrap()};
 for(i,b)in [65,66,0].into_iter().enumerate(){rt.store(rt.offset(root,if mode==2{2+i as i64}else{i as i64}).unwrap(),8,if mode==4&&i==1{CrtValue::Scalar{bits:0,known:0}}else{CrtValue::scalar(b)}).unwrap();}
 let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(91)).unwrap();for(i,v)in [CrtValue::Pointer(target),CrtValue::scalar(if mode==5{1}else{4}),CrtValue::Pointer(source)].into_iter().enumerate(){rt.store(rt.offset(sp,4+i as i64*4).unwrap(),32,v).unwrap();}let mut c=CrtCpu::new(sp,91).unwrap();let saved=c.r;
 if mode==6{rt.free_allocation(root).unwrap();}if mode==7{rt.free_allocation(target).unwrap();}
 let got=copy(&mut rt,&mut c);
 if mode<=2{assert_eq!(got,Ok(CrtValue::scalar(0)));assert!(c.returned);assert_eq!(rt.memory.read(target.address(),3).unwrap(),&[65,66,0]);for n in[3,5,6,7]{assert_eq!(c.r[n],saved[n]);}assert!(copy(&mut rt,&mut c).is_err());}
 else{assert_eq!(got,Err(match mode{3=>"CRT pointer complete range/identity",4=>"CRT unknown ZF",5=>"copy error contract unbound",6|7=>"CRT stale/foreign pointer",_=>unreachable!()}));assert!(!c.returned);if mode==3||mode==4{assert_eq!(rt.load(target,8),Ok(CrtValue::scalar(65)));assert!(rt.load(rt.offset(target,2).unwrap(),8).unwrap().known_scalar().is_err());}if mode==5{assert_eq!(rt.load(target,8),Ok(CrtValue::scalar(0)));}}
}for mode in 0..8{one(mode);}
"#,
        "checked-original-copy",
    );
}

#[test]
fn address_relation_revalidates_call_roots_arguments_and_numeric_operands() {
    crate::crt_stream_callees_tests::native_bounded_stack(
        "",
        r#"
#[inline(never)]fn one(mode:u32){
 let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let CrtValue::Heap(heap)=rt.native_process_heap(init).unwrap()else{panic!()};let source=rt.native_heap_allocate(init,heap,8,8).unwrap();let dest=rt.native_heap_allocate(init,heap,8,8).unwrap();rt.store(source,32,CrtValue::scalar(0x12345678)).unwrap();let stack=rt.map_region(0x40000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(91)).unwrap();rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::Pointer(dest)).unwrap();rt.store(rt.offset(sp,8).unwrap(),32,CrtValue::Pointer(source)).unwrap();let mut c=CrtCpu::new(sp,91).unwrap();c.return_site=Some((91,0x1234));c.r[3]=CrtValue::Pointer(source);c.r[2]=CrtValue::Pointer(dest);c.r[7]=CrtValue::Pointer(dest);
 let (relation,value)=CrtAddressRelation::subtract(&rt,&mut c,3,2,8,4).unwrap();assert_eq!(value,CrtValue::scalar(source.address().wrapping_sub(dest.address())));assert_eq!(c.flags.cf,Some(source.address()<dest.address()));assert_eq!(c.flags.zf,Some(source.address()==dest.address()));c.r[3]=value;let before=(c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of);
 match mode{1=>rt.free_allocation(source).unwrap(),2=>rt.free_allocation(dest).unwrap(),3=>{rt.store(rt.offset(sp,8).unwrap(),32,CrtValue::Pointer(dest)).unwrap();},4=>c.r[3]=CrtValue::scalar(CrtCpu::number(value).unwrap()^1),5=>c.r[7]=CrtValue::Pointer(source),6=>c.r[7]=CrtValue::Pointer(rt.subrange(dest,4).unwrap()),7=>rt.thread+=1,8=>{rt.bind_fiber(rt.thread).unwrap();},9=>{c.return_id=92;rt.tags.insert(sp.address(),CrtValue::ProtectedReturn(92));},10=>c.returned=true,11=>{rt.free_allocation(source).unwrap();let new=rt.native_heap_allocate(init,heap,8,8).unwrap();assert_eq!(new.address(),source.address());assert_ne!(new.cap,source.cap);},12=>c.r[7]=CrtValue::Pointer(rt.offset(dest,8).unwrap()),13=>c.r[3]=CrtValue::Scalar{bits:CrtCpu::number(value).unwrap(),known:0},14=>{rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::scalar(dest.address())).unwrap();},15=>c.return_site=None,16=>c.return_pop=4,_=>{}}
 let got=relation.load(&rt,&c,3,7,32);if mode==0{assert_eq!(got,Ok(CrtValue::scalar(0x12345678)));assert_eq!(c.address(&rt,Some(3),Some(7),1,0,None),Err("CRT pointer complete range/identity"));}else{assert!(got.is_err(),"relation negative{mode}");}assert_eq!((c.flags.cf,c.flags.zf,c.flags.sf,c.flags.of),before);
}for mode in 0..17{one(mode);}
"#,
        "checked-address-relation",
    );
}

#[test]
fn address_relation_binding_rejects_changed_instruction_operands() {
    let original = crate::crt_ptd::raw(ENV_STRING_COPY);
    for (pc, offset, value) in [
        (0x4077a8, 0usize, 0x03u8),
        (0x4077b0, 0, 0x88),
        (0x4077b0, 2, 0x4e),
    ] {
        let mut bytes = original.clone();
        bytes[(pc - 0x407770) as usize + offset] = value;
        if let Ok(mut graph) = Graph::decode(&bytes, 0x407770) {
            assert!(crate::crt_stream_emit::bind_address_relation(
                &mut graph, 0x4077a8, 0x4077b0, 12, 4
            )
            .is_err());
        }
    }
}

#[test]
fn checked_relation_lowers_unrelated_registers_and_word_load_without_host_pointer_casts() {
    let bytes = crate::crt_ptd::raw("558bec5356578b5d0c8b75088bfe2bde668b043b5f5e5b5dc3");
    let mut graph = Graph::decode(&bytes, 0x1000).unwrap();
    crate::crt_stream_emit::bind_address_relation(&mut graph, 0x100e, 0x1010, 8, 4).unwrap();
    let body = crate::crt_stream_emit::emit_body(
        &graph,
        |_, _| Err("independent word helper has no calls".into()),
        &Default::default(),
        32,
    )
    .unwrap();
    let extra=format!("fn word(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{body}}}");
    crate::crt_stream_callees_tests::native_bounded_stack(
        &extra,
        r#"
for reverse in [false,true]{let(mut rt,init)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let CrtValue::Heap(heap)=rt.native_process_heap(init).unwrap()else{panic!()};let a=rt.native_heap_allocate(init,heap,8,2).unwrap();let b=rt.native_heap_allocate(init,heap,8,2).unwrap();let(src,dst)=if reverse{(b,a)}else{(a,b)};rt.store(src,16,CrtValue::scalar(0x5678)).unwrap();let stack=rt.map_region(0x40000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(91)).unwrap();rt.store(rt.offset(sp,4).unwrap(),32,CrtValue::Pointer(dst)).unwrap();rt.store(rt.offset(sp,8).unwrap(),32,CrtValue::Pointer(src)).unwrap();let mut c=CrtCpu::new(sp,91).unwrap();c.r[0]=CrtValue::scalar(0xaabb0000);let saved=c.r;assert_eq!(word(&mut rt,&mut c),Ok(CrtValue::scalar(0xaabb5678)));assert_eq!(c.flags.cf,Some(src.address()<dst.address()));assert_eq!(c.flags.zf,Some(false));assert_eq!(rt.load(dst,16),Ok(CrtValue::scalar(0)));for r in[3,5,6,7]{assert_eq!(c.r[r],saved[r]);}}
"#,
        "independent-word-relation",
    );
}

#[test]
fn post_environment_original_calls_branch_and_return_preserve_failure_boundaries() {
    let bytes = crate::crt_ptd::raw(FIRST);
    let tail = &bytes[(0x4015ee - 0x40155a)..];
    let graph = cut_graph(
        tail,
        0x4015ee,
        0x4015fd,
        &[(0x4015fd, "original fatal path unbound")],
    )
    .unwrap();
    let zero = crate::crt_stream_emit::emit_body(
        &Graph::decode(&crate::crt_ptd::raw(ZERO), 0x401bbc).unwrap(),
        |_, _| Err("zero call".into()),
        &Default::default(),
        8,
    )
    .unwrap();
    let body=crate::crt_stream_emit::emit_body(&graph,|pc,t|{assert_eq!(t,if pc==0x4015ee{Target::Direct(0x401bbc)}else{Target::Direct(0x401d4c)});Ok(format!("calls+=1;cpu.call_activation(rt,{},0,|rt,c|{{let v=zero(rt,c)?;if calls==2&&mode==1{{c.r[0]=CrtValue::scalar(7);return Ok(c.r[0]);}}if calls==2&&mode==2{{c.r[0]=CrtValue::Scalar{{bits:0,known:0}};return Ok(c.r[0]);}}if calls==2&&mode==3{{rt.tags.insert(outer.address(),CrtValue::ProtectedReturn(999));}}Ok(v)}})?;",pc+5))},&Default::default(),32).unwrap();
    let extra=format!("fn zero(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{{zero}}}fn tail(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,mode:u32)->Result<CrtValue,&'static str>{{let outer=CrtCpu::pointer(cpu.entry[4])?;let mut calls=0;let result=(||{{{body}}})();assert_eq!(calls,2);result}}");
    crate::crt_stream_callees_tests::native_bounded_stack(
        &extra,
        r#"
for mode in 0..4{let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0x10000,1024,CrtRegionKind::Stack,None).unwrap();let sp=rt.offset(stack,512).unwrap();rt.store(sp,32,CrtValue::ProtectedReturn(91)).unwrap();let mut c=CrtCpu::new(sp,91).unwrap();let got=tail(&mut rt,&mut c,mode);if mode==0{assert_eq!(got,Ok(CrtValue::scalar(0)));assert!(c.returned);}else{assert_eq!(got,Err(match mode{1=>"original fatal path unbound",2=>"CRT unknown ZF",_=>"CRT original protected return"}));assert!(!c.returned);}}
"#,
        "post-environment-return",
    );
}

fn file_source() -> Result<String, String> {
    let bytes = crate::crt_ptd::raw(FILE_INIT);
    let graph = Graph::decode(&bytes, 0x404510)?;
    let roles = BTreeMap::from_iter(
        [0x41cd2c, 0x41cd30, 0x41cf08].map(|a| (a, "CrtRegionKind::Module".into())),
    );
    let body = crate::crt_stream_emit::emit_body_with_hooks(
        &graph,
        |pc, t| {
            let next = pc + graph.nodes[&pc].length;
            Ok(match t{
 Target::Direct(0x407cf0)=>format!("cpu.call_activation(rt,{next},0,|rt,c|ucrt_calloc_native(rt,c,inputs,platform,epoch))?;"),
 Target::Direct(0x407d50)=>format!("cpu.call_activation(rt,{next},0,|rt,c|ucrt_free_null(rt,c,inputs))?;"),
 Target::Direct(0x408079)=>format!("cpu.call_activation(rt,{next},12,|rt,c|startup_file_lock(rt,c,inputs,platform))?;"),
 _=>return Err("FILE unexpected original call".into())})
        },
        &roles,
        8192,
        |_, _| Err("FILE thread effect".into()),
        |pc, _| {
            Ok(if pc == 0x404582 {
                "let p=rt.file();let image=rt.process_image_pointer(inputs.image,0x41c080,168)?;rt.valid(p,168)?;if p.cap!=image.cap||p.owner!=image.owner||p.address()!=0x41c080||p.size!=168{return Err(\"FILE canonical array identity\");}if matches!(cpu.r[6],CrtValue::Scalar{..}){if cpu.r[6]!=CrtValue::scalar(p.address()){return Err(\"FILE initial cursor\");}cpu.r[6]=CrtValue::Pointer(p);}else{let cursor=CrtCpu::pointer(cpu.r[6])?;rt.file_record(cursor)?;if cursor.cap!=p.cap||cursor.base!=p.base||cursor.size!=p.size{return Err(\"FILE loop cursor identity\");}}".into()
            } else {
                String::new()
            })
        },
        |_, _| Ok(None),
    )?;
    let thunk = crate::crt_ptd::raw("8bff558bec5dff25ac504100");
    let g = Graph::decode_linear_fragment(&thunk[..6], 0x408079)?;
    let pre = crate::crt_stream_emit::emit_linear_fragment(&g, &Default::default())?;
    Ok(format!("fn cinit_file_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}{body}}}fn startup_file_lock(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:&CrtNativePlatform)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;platform.validate(rt,inputs.init)?;cpu.validate_active(rt)?;{}let _=(||->Result<CrtValue,&'static str>{{{pre}}})()?;rt.process_image_import(inputs.image,0x4150ac,\"kernel32.dll\",\"InitializeCriticalSectionEx\")?;if cpu.return_pop!=12||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&i|cpu.r[i]!=cpu.entry[i]){{return Err(\"FILE lock ABI\");}}let sp=CrtCpu::pointer(cpu.r[4])?;rt.offset(sp,16)?;rt.memory.validate_writable(sp.cap,sp.owner,sp.address(),16).map_err(|_|\"FILE lock return stack permission\")?;let p=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;let spin=rt.load(rt.offset(sp,8)?,32)?.known_scalar()?;let flags=rt.load(rt.offset(sp,12)?,32)?.known_scalar()?;let value=rt.native_file_initialize(inputs.init,platform.function,p,spin,flags)?;cpu.clobber(CrtValue::scalar(u32::from(value)));cpu.finish_pop(rt,12)}}",guard(0x404510,&bytes),guard(0x408079,&thunk)))
}
