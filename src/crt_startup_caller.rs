//! Original post-initializer caller; live frame checks grant no exception/TEB effects.
use crate::crt_stream_ir::{Graph, Node, Op, Target};
use std::collections::BTreeMap;
pub(crate) const CALLER:&str="5984c00f845301000032db885de7c745fc00000000e8c70200008845dca17ccc410033c9413bc10f842f01000085c07549890d7ccc41006858514100683c514100e854560000595985c07411c745fcfeffffffb8ff000000e9ef00000068385141006830514100e8035600005959c7057ccc410002000000eb058ad9885de7ff75dce8e303000059";
pub(crate) const LOCK:&str="56e8a608000085c0742064a118000000be80cc41008b5004eb043bd0741033c08bcaf00fb10e85c075f032c05ec3b0015ec3";
pub(crate) const RELEASE: &str = "558bece81b07000085c0740f807d0800750933c0b980cc410087015dc3";
pub(crate) const FLAG: &str = "33c03905f0d241000f95c0c3";
pub(crate) const CALLBACK_CELLS: &str = "e86c0500008bf033ff393e741b56e8380300005984c074108b36576a02578bceff1528514100ffd6e84a0500008bf0393e741356e8120300005984c07408ff36e81b59000059";
pub(crate) const INIT_CELL: &str = "b8f8d24100c3";
pub(crate) const DTOR_CELL: &str = "b8f4d24100c3";
pub(crate) const MAIN_ARGS: &str = "e8835500008bf8e8a65900008b30e8995900005756ff30";
pub(crate) const ENV_GET: &str = "a154ce410085c0750ae849fdffffa354ce4100c3";
pub(crate) const ENV_FALLBACK: &str =
    "a148ce410085c0752239054cce41007418e81600000085c07409e87b01000085c07506a148ce4100c333c0c3";
pub(crate) const ARGC_CELL: &str = "b868ce4100c3";
pub(crate) const ARGV_CELL: &str = "b86cce4100c3";
pub(crate) const MAIN_CALL: &str = "e864fbffff";
pub(crate) const MAIN_PROLOG: &str = "558bec6afe6818b24100681022400064a1000000005081c404fdffffa100c041003145f833c58945e4535657508d45f064a3000000008965e8";
pub(crate) const MAIN_INITIAL: &str = "c78500fdffff2c010000c78510fdffff0000000068cc0200006a008d8518fdffff50e89010000083c40cc7850cfdffff00000000c78508fdffff00000000c78504fdffff000000006a00ff1508504100898514fdffffc745fc00000000";
pub(crate) const MAIN_EPILOG: &str = "8b4df064890d00000000595f5e5b8b4de433cde8340000008be55dc3";
pub(crate) const MAIN_SCOPE: &str = "e4ffffff00000000e4fcffff00000000feffffff331340005c134000";
pub(crate) const SCOPE: &str = "feffffff00000000ccffffff00000000feffffff491740005d174000";
/// Derive registration metadata from the existing inline instruction proof,
/// then check its restoration shape. This does not execute or admit a return.
fn inline_contract(prolog: &[u8], epilog: &[u8]) -> Result<(String, String, String), String> {
    use crate::graph::{Address, Binary, Operand, Operation, Reg};
    let f = crate::frame_proof::prove_frame(
        prolog,
        0x401280,
        0x41c000,
        &std::collections::BTreeSet::from([0x41b218]),
        &std::collections::BTreeSet::from([0x402210]),
    )?;
    f.validate_eh4_header([-28, 0, -796, 0])?;
    if f.end() != 0x4012b9 || f.try_level() != -2 || !f.guard_offsets().contains(&f.esp_offset()) {
        return Err("inline frame prolog shape".into());
    }
    let bp = f.ebp_offset();
    let low = bp + f.esp_offset();
    let saved_sp: Vec<_> = f
        .stack_words()
        .iter()
        .filter(|(_, target)| **target == f.esp_offset())
        .map(|(&at, _)| bp + at)
        .collect();
    if saved_sp.len() != 1 {
        return Err("inline frame saved-SP producer".into());
    }
    let reg = |index| Reg {
        index,
        width: 32,
        shift: 0,
    };
    let memory = |offset: i32| {
        Operand::Memory(
            Address {
                base: Some(5),
                index: None,
                scale: 1,
                displacement: offset as u32,
            },
            32,
        )
    };
    let g = Graph::decode(epilog, 0x401500)?;
    let ops: Vec<_> = g.nodes.values().map(|n| n.op.clone()).collect();
    let expected = vec![
        Op::Ordinary(Operation::Binary(
            Binary::Move,
            Operand::Reg(reg(1)),
            memory(f.record_offset()),
        )),
        Op::FsWrite(reg(1)),
        Op::Ordinary(Operation::Pop(reg(1))),
        Op::Ordinary(Operation::Pop(reg(7))),
        Op::Ordinary(Operation::Pop(reg(6))),
        Op::Ordinary(Operation::Pop(reg(3))),
        Op::Ordinary(Operation::Binary(
            Binary::Move,
            Operand::Reg(reg(1)),
            memory(-28),
        )),
        Op::Ordinary(Operation::Binary(
            Binary::Xor,
            Operand::Reg(reg(1)),
            Operand::Reg(reg(5)),
        )),
        Op::Call(Target::Direct(0x40154c)),
        Op::Ordinary(Operation::Binary(
            Binary::Move,
            Operand::Reg(reg(4)),
            Operand::Reg(reg(5)),
        )),
        Op::Ordinary(Operation::Pop(reg(5))),
        Op::Ordinary(Operation::Return),
    ];
    if ops != expected || g.end != 0x40151c {
        return Err("inline original epilog shape".into());
    }
    let pops = [
        (f.esp_offset() + 4, 7),
        (f.esp_offset() + 8, 6),
        (f.esp_offset() + 12, 3),
        (0, 5),
    ];
    if f.saved_slots() != &pops.into_iter().collect::<BTreeMap<_, _>>() {
        return Err("inline original saved-slot order".into());
    }
    if !(-744..-28)
        .step_by(4)
        .all(|n| f.ordinary_words().contains(&n))
    {
        return Err("inline original memset ordinary extent".into());
    }
    let saved: Vec<_> = f
        .saved_slots()
        .iter()
        .map(|(&at, &r)| (bp + at, r))
        .collect();
    let guards: Vec<_> = f
        .guard_offsets()
        .iter()
        .filter(|&&at| at != f.esp_offset())
        .map(|&at| bp + at)
        .collect();
    let layout=format!("CrtNormalLayout{{low:{low},bp:{bp},record:{},scope_slot:{},level:{},saved_sp:{},guard:{low},saved:vec!{saved:?},scope:{},handler:{},cookie_address:0x41c000,pop:0}}",bp+f.record_offset(),bp+f.record_offset()+8,bp+f.try_level_offset(),saved_sp[0],f.scope_va(),f.handler_va());
    let mut steps=format!("vec![NormalFrameStep::RestorePredecessor,NormalFrameStep::DiscardGuard{{offset:{low},register:1}},");
    for (at, r) in &pops[..3] {
        steps.push_str(&format!(
            "NormalFrameStep::PopSaved{{offset:{},register:{r}}},",
            bp + at
        ));
    }
    steps.push_str(&format!("NormalFrameStep::CheckGuard{{offset:{},target:0x40154c}},NormalFrameStep::PopSaved{{offset:{bp},register:5}}]",bp-28));
    Ok((
        layout,
        format!("vec!{guards:?}"),
        format!("NormalFramePlan{{steps:{steps},callee_pop:0}}"),
    ))
}
fn main_source() -> Result<String, String> {
    let raw = crate::crt_ptd::raw;
    let p = raw(MAIN_PROLOG);
    let ep = raw(MAIN_EPILOG);
    let scope = raw(MAIN_SCOPE);
    let (layout, guards, plan) = inline_contract(&p, &ep)?;
    let g = crate::crt_startup_table::graph(&p[..54], 0x401280)?;
    let body = crate::crt_stream_emit::emit_body_with_store(
        &g,
        |_, _| Err("inline Main prolog call".into()),
        &BTreeMap::from([(0x41c000, "CrtRegionKind::Module".into())]),
        128,
        |_, op| {
            Ok(match op {
            Op::FsRead(r)=>format!("b.authority(rt,epoch)?;if epoch.head()?!=b.previous{{return Err(\"inline Main previous head changed\");}}cpu.set({},32,0,CrtValue::ThreadHead(b.token))?;",r.index),
            Op::FsWrite(r)=>format!("b.install_inline(rt,cpu,epoch,CrtCpu::pointer(cpu.r[{}])?,b.token,original_main_plan())?;",r.index),
            _=>return Err("inline Main thread effect".into()),
        })
        },
        |_, _| Ok(String::new()),
        |_, _| Err("inline Main prolog return".into()),
        Some(0x4012b6),
        |_, _, _| Ok(None),
    )?;
    let last = crate::crt_startup_table::graph(&p[54..], 0x4012b6)?;
    let store = crate::crt_stream_emit::emit_body_with_store(
        &last,
        |_, _| Err("inline Main saved-SP call".into()),
        &Default::default(),
        4,
        |_, _| Err("inline Main saved-SP FS".into()),
        |_, _| Ok(String::new()),
        |_, _| Err("inline Main saved-SP return".into()),
        Some(0x4012b9),
        |pc, a, w| {
            if pc != 0x4012b6 || w != 32 {
                return Err("inline Main saved-SP instruction".into());
            }
            Ok(Some(format!(
                "let p={};b.store_inline_saved_sp(rt,cpu,epoch,p,v)?;",
                crate::crt_stream_emit::address(a, &Default::default())?
            )))
        },
    )?;
    let mut out=format!("fn original_main_layout()->CrtNormalLayout{{{layout}}}fn original_main_guards()->Vec<i32>{{{guards}}}fn original_main_plan()->NormalFramePlan{{{plan}}}");
    out.push_str(&format!("fn original_main_install(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,epoch:&mut NormalCallEpoch<'_>,b:&mut CrtNormalBinding)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;b.authority(rt,epoch)?;if b.id.is_some()||!b.saved_sp_pending||cpu.r[4]!=cpu.entry[4]{{return Err(\"Main inline prolog activation phase\");}}{}{}{body}}}",guard(0x401280,&p),guard(0x401500,&ep)));
    out.push_str(&format!("fn original_main_saved_sp(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,epoch:&mut NormalCallEpoch<'_>,b:&mut CrtNormalBinding)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;b.authority(rt,epoch)?;{}{store}}}",guard(0x401280,&p)));
    let bytes = raw(MAIN_INITIAL);
    let g = crate::crt_startup_table::graph(&bytes, 0x4012b9)?;
    let body = crate::crt_stream_emit::emit_body_with_store(
        &g,
        |pc, t| {
            Ok(match(pc,t){
        (0x4012db,Target::Direct(0x402370))=>"b.authority(rt,epoch)?;let sp=CrtCpu::pointer(cpu.r[4])?;if rt.load(sp,32)?!=CrtValue::Pointer(b.at(rt,b.layout.bp-744)?)||rt.load(rt.offset(sp,4)?,32)?!=CrtValue::scalar(0)||rt.load(rt.offset(sp,8)?,32)?!=CrtValue::scalar(716){return Err(\"Main original fill arguments\");}cpu.call_activation(rt,0x4012e0,0,|rt,c|onexit_memset_original(rt,c,inputs))?;".into(),
        (0x401303,Target::Import(0x415008))=>"rt.process_image_import(inputs.image,0x415008,\"kernel32.dll\",\"GetModuleHandleW\")?;let view=CrtModuleImage::main(rt)?;cpu.call_activation(rt,0x401309,4,|rt,c|CrtModuleImage::null_handle_call(Some(&view),rt,c))?;".into(),
        _=>return Err("Main original initial call".into()),
    })
        },
        &Default::default(),
        128,
        |_, _| Err("Main initial FS effect".into()),
        |_, _| Ok(String::new()),
        |_, _| Err("Main initial return".into()),
        Some(0x401316),
        |pc, a, w| {
            if w != 32 {
                return Err("Main initial store width".into());
            }
            let offset = match pc {
                0x4012b9 => -768,
                0x4012c3 => -752,
                0x4012e3 => -756,
                0x4012ed => -760,
                0x4012f7 => -764,
                0x401309 => -748,
                0x40130f => -4,
                _ => return Err("Main initial store instruction".into()),
            };
            let transition = if pc == 0x40130f {
                "if rt.load(p,32)?!=CrtValue::scalar((-2i32)as u32)||v!=CrtValue::scalar(0){return Err(\"Main initial scope transition\");}"
            } else {
                ""
            };
            Ok(Some(format!("b.authority(rt,epoch)?;let p={};if p!=b.at(rt,b.layout.bp+({offset}))?{{return Err(\"Main initial destination alias\");}}{transition}rt.store(p,32,v)?;let image=b.image(rt,cpu,epoch)?;epoch.validate_image(b.id.ok_or(\"Main initial missing frame\")?,&image)?;",crate::crt_stream_emit::address(a,&Default::default())?)))
        },
    )?;
    out.push_str(&format!("fn original_main_initial(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,epoch:&mut NormalCallEpoch<'_>,b:&mut CrtNormalBinding)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let image=b.image(rt,cpu,epoch)?;epoch.validate_image(b.id.ok_or(\"Main initial missing frame\")?,&image)?;{}{body}}}",guard(0x4012b9,&bytes)));
    out.push_str(&format!("fn startup_main_original(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let scope=rt.process_image_pointer(inputs.image,0x41b218,{})?;rt.memory.validate_immutable(scope.cap,scope.owner,scope.address(),{}).map_err(|_|\"Main scope permission\")?;if rt.memory.read(scope.address(),{}).map_err(|_|\"Main scope read\")?!=&{scope:?}{{return Err(\"Main scope bytes changed\");}}let mut b=CrtNormalBinding::bind_inline_initializing(rt,cpu,epoch,original_main_layout(),inputs.init,original_main_guards())?;original_main_install(rt,cpu,inputs,epoch,&mut b)?;original_main_saved_sp(rt,cpu,inputs,epoch,&mut b)?;original_main_initial(rt,cpu,inputs,epoch,&mut b)?;Err(\"startup Main Inner call unbound at 0x401316\")}}",scope.len(),scope.len(),scope.len()));
    Ok(out)
}
fn argument_source() -> Result<String, String> {
    let mut out = String::new();
    for (name, at, raw) in [
        ("startup_argc_cell", 0x4070ac, ARGC_CELL),
        ("startup_argv_cell", 0x4070b2, ARGV_CELL),
    ] {
        let bytes = crate::crt_ptd::raw(raw);
        let g = Graph::decode(&bytes, at)?;
        let body = crate::crt_stream_emit::emit_body(
            &g,
            |_, _| Err("argument cell getter call".into()),
            &Default::default(),
            8,
        )?;
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;if cpu.return_pop!=0||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){{return Err(\"argument cell getter entry ABI\");}}{}{body}}}",guard(at,&bytes)));
    }
    for (name, at, raw) in [
        ("startup_environment_fallback", 0x4069df, ENV_FALLBACK),
        ("startup_environment_get", 0x406c88, ENV_GET),
    ] {
        let bytes = crate::crt_ptd::raw(raw);
        let g = Graph::decode(&bytes, at)?;
        let body = crate::crt_stream_emit::emit_body(
            &g,
            |pc, target| {
                Ok(match target {
                Target::Direct(0x4069df) if pc==0x406c91 => "cpu.call_activation(rt,0x406c96,0,|rt,c|startup_environment_fallback(rt,c,inputs,platform,epoch.as_deref_mut()))?;".into(),
                Target::Direct(0x406a0b) if pc==0x4069f0 => "let p=platform.ok_or(\"environment fallback platform unbound\")?;let e=epoch.as_deref_mut().ok_or(\"environment fallback registry unbound\")?;cpu.call_activation(rt,0x4069f5,0,|rt,c|cinit_environment_prefix(rt,c,inputs,p,e))?;".into(),
                Target::Direct(0x406b79) if pc==0x4069f9 => "cpu.call_activation(rt,0x4069fe,0,|_,_|Err(\"startup wide environment copy unbound at 0x406b79\"))?;return Err(\"unexpected wide environment copy return\");".into(),
                _ => return Err("environment getter call identity".into()),
            })
            },
            &BTreeMap::from_iter(
                [0x41ce48, 0x41ce4c, 0x41ce54].map(|a| (a, "CrtRegionKind::Module".into())),
            ),
            64,
        )?;
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:Option<&CrtNativePlatform>,mut epoch:Option<&mut NormalCallEpoch<'_>>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;if cpu.return_pop!=0||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){{return Err(\"environment getter entry ABI\");}}{}{body}}}",guard(at,&bytes)));
    }
    let bytes = crate::crt_ptd::raw(MAIN_ARGS);
    let g = crate::crt_startup_table::graph(&bytes, 0x401700)?;
    let body = crate::crt_stream_emit::emit_body_with_store(
        &g,
        |pc, target| {
            Ok(match (pc,target) {
            (0x401700,Target::Direct(0x406c88))=>"cpu.call_activation(rt,0x401705,0,|rt,c|startup_environment_get(rt,c,inputs,platform,Some(epoch)))?;".into(),
            (0x401707,Target::Direct(0x4070b2))=>"cpu.call_activation(rt,0x40170c,0,|rt,c|startup_argv_cell(rt,c,inputs))?;".into(),
            (0x40170e,Target::Direct(0x4070ac))=>"cpu.call_activation(rt,0x401713,0,|rt,c|startup_argc_cell(rt,c,inputs))?;".into(),
            _=>return Err("Main argument caller target".into()),
        })
        },
        &Default::default(),
        32,
        |_, _| Err("Main argument thread effect".into()),
        |pc, _| {
            Ok(match pc {
                0x40170c | 0x401715 => {
                    let address = if pc == 0x40170c { 0x41ce6c } else { 0x41ce68 };
                    format!("let p=rt.module_word_pointer(inputs.image,cpu.r[0])?;if p!=rt.process_image_pointer(inputs.image,{address},4)?{{return Err(\"argument cell live identity\");}}cpu.r[0]=CrtValue::Pointer(p);")
                }
                _ => String::new(),
            })
        },
        |_, _| Err("Main argument unexpected return".into()),
        Some(0x401717),
        |_, _, _| Err("Main argument unexpected store".into()),
    )?;
    out.push_str(&format!("fn startup_main_arguments(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,platform:Option<&CrtNativePlatform>,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}{body}}}",guard(0x401700,&bytes)));
    Ok(out)
}
// The mapped words are read at the original CMPs. Neither getter supplies their
// values, nor does this prefix grant authority to call a non-NULL value.
fn callback_source() -> Result<String, String> {
    let mut out = String::new();
    for (name, at, raw) in [
        ("startup_init_cell", 0x401c2b, INIT_CELL),
        ("startup_dtor_cell", 0x401c31, DTOR_CELL),
    ] {
        let bytes = crate::crt_ptd::raw(raw);
        let g = Graph::decode(&bytes, at)?;
        let body = crate::crt_stream_emit::emit_body(
            &g,
            |_, _| Err("callback cell getter call".into()),
            &Default::default(),
            8,
        )?;
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;if cpu.return_pop!=0||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){{return Err(\"callback cell getter entry ABI\");}}{}{body}}}",guard(at,&bytes)));
    }
    let bytes = crate::crt_ptd::raw(CALLBACK_CELLS);
    let mut g = crate::crt_startup_table::graph(&bytes, 0x4016ba)?;
    // A non-NULL cell requires the original EH4-backed PE section validator.
    // Keep its CALL as the rejection frontier, including the original PUSH.
    // Do not classify by current page permissions or eagerly resolve a target.
    for (start, end) in [(0x4016cd, 0x4016e2), (0x4016f3, 0x401700)] {
        g.nodes.retain(|pc, _| *pc < start || *pc >= end);
    }
    for pc in [0x4016c8, 0x4016ee] {
        g.nodes
            .get_mut(&pc)
            .ok_or("callback validator CALL missing")?
            .successors
            .clear();
    }
    let body = crate::crt_stream_emit::emit_body_with_store(
        &g,
        |pc, target| {
            Ok(match (pc, target) {
            (0x4016ba, Target::Direct(0x401c2b)) => "cpu.call_activation(rt,0x4016bf,0,|rt,c|startup_init_cell(rt,c,inputs))?;".into(),
            (0x4016e2, Target::Direct(0x401c31)) => "cpu.call_activation(rt,0x4016e7,0,|rt,c|startup_dtor_cell(rt,c,inputs))?;".into(),
            (0x4016c8 | 0x4016ee, Target::Direct(0x401a05)) => format!("cpu.call_activation(rt,{},0,|_,_|Err(\"startup callback-cell PE/EH4 validation unbound at 0x401a05\"))?;return Err(\"unexpected callback validator return\");",pc+5),
            _ => return Err("callback cell prefix call target".into()),
        })
        },
        &Default::default(),
        32,
        |_, _| Err("callback cell thread effect".into()),
        |pc, _| {
            Ok(match pc {
                0x4016c3 | 0x4016e9 => {
                    let address = if pc == 0x4016c3 { 0x41d2f8 } else { 0x41d2f4 };
                    format!("let p=rt.module_word_pointer(inputs.image,cpu.r[6])?;if p!=rt.process_image_pointer(inputs.image,{address},4)?{{return Err(\"callback cell live identity\");}}cpu.r[6]=CrtValue::Pointer(p);")
                }
                _ => String::new(),
            })
        },
        |_, _| Err("callback prefix unexpected RET".into()),
        Some(0x401700),
        |_, _, _| Err("callback prefix unexpected store".into()),
    )?;
    out.push_str(&format!("fn startup_callback_cells(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{}{body}}}fn startup_callback_cells_bytes()->Vec<u8>{{vec!{bytes:?}}}",guard(0x4016ba,&bytes)));
    Ok(out)
}
fn lock_graph() -> Result<Graph, String> {
    let bytes = crate::crt_ptd::raw(LOCK);
    let mut nodes = crate::crt_startup_table::graph(&bytes[..10], 0x401913)?.nodes;
    nodes.extend(Graph::decode(&bytes[42..46], 0x40193d)?.nodes);
    nodes.insert(
        0x40191d,
        Node {
            length: 6,
            op: Op::Reject("startup TEB/atomic ownership unbound at 0x40191d"),
            successors: vec![],
        },
    );
    if nodes
        .values()
        .flat_map(|n| &n.successors)
        .any(|t| !nodes.contains_key(t))
    {
        return Err("startup lock original closed-prefix edges".into());
    }
    Ok(Graph {
        origin: 0x401913,
        end: 0x401945,
        nodes,
    })
}
pub(crate) fn source() -> Result<String, String> {
    let array_source = crate::crt_c_initializers::source()?;
    let flag = crate::crt_ptd::raw(FLAG);
    let g = Graph::decode(&flag, 0x4021bf)?;
    let body = crate::crt_stream_emit::emit_body_with_hooks(
        &g,
        |_, _| Err("startup flag call".into()),
        &BTreeMap::from([(0x41d2f0, "CrtRegionKind::Module".into())]),
        32,
        |_, _| Err("startup flag thread effect".into()),
        |pc, _| {
            Ok(if pc == 0x4021c1 {
                "if !matches!(rt.load(rt.process_image_pointer(inputs.image,0x41d2f0,4)?,32)?,CrtValue::Scalar{..}){return Err(\"startup flag scalar field\");}".into()
            } else {
                String::new()
            })
        },
        |_, _| Ok(None),
    )?;
    let mut out=format!("fn startup_runtime_flag(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{} {body}}}",guard(0x4021bf,&flag));
    out.push_str(&array_source);
    out.push_str(&callback_source()?);
    out.push_str(&argument_source()?);
    out.push_str(&main_source()?);
    let lock = crate::crt_ptd::raw(LOCK);
    let g = lock_graph()?;
    let body = crate::crt_stream_emit::emit_body(
        &g,
        |pc, t| {
            if t != Target::Direct(0x4021bf) {
                return Err("startup lock guard target".into());
            }
            Ok(format!(
                "cpu.call_activation(rt,{},0,|rt,c|startup_runtime_flag(rt,c,inputs))?;",
                pc + g.nodes[&pc].length
            ))
        },
        &Default::default(),
        64,
    )?;
    out.push_str(&format!("fn startup_runtime_lock(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;{} {body}}}",guard(0x401913,&lock)));
    let release = crate::crt_ptd::raw(RELEASE);
    let mut graph = Graph::decode(&release, 0x401a9c)?;
    graph.initializing_atomic(0x401ab5)?;
    let body = crate::crt_stream_emit::emit_body_with_hooks(
        &graph,
        |pc, target| {
            if pc != 0x401a9f || target != Target::Direct(0x4021bf) {
                return Err("startup release guard target".into());
            }
            Ok(
                "cpu.call_activation(rt,0x401aa4,0,|rt,c|startup_runtime_flag(rt,c,inputs))?;"
                    .into(),
            )
        },
        &Default::default(),
        64,
        |_, op| {
            let Op::InitializingAtomic {
                destination: crate::graph::Operand::Memory(a, 32),
                source,
                add: false,
            } = op
            else {
                return Err("startup release atomic shape".into());
            };
            Ok(format!("let p={};if p!=rt.process_image_pointer(inputs.image,0x41cc80,4)?{{return Err(\"startup release cell identity\");}}cpu.exchange_initializing_scalar(rt,inputs.init,inputs.image,p,{},false)?;",crate::crt_stream_emit::address(a,&Default::default())?,source.index))
        },
        |pc, _| {
            Ok(if pc == 0x401ab5 {
                "cpu.r[1]=CrtValue::Pointer(rt.module_word_pointer(inputs.image,cpu.r[1])?);".into()
            } else {
                String::new()
            })
        },
        |_, _| Ok(None),
    )?;
    out.push_str(&format!("fn startup_runtime_release(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;if cpu.return_pop!=0||cpu.r[4]!=cpu.entry[4]||[3,5,6,7].iter().any(|&r|cpu.r[r]!=cpu.entry[r]){{return Err(\"startup release entry ABI\");}}{}{body}}}",guard(0x401a9c,&release)));
    let bytes = crate::crt_ptd::raw(CALLER);
    let mut g = crate::crt_startup_table::graph(&bytes, 0x401632)?;
    for (pc, reason) in [
        (0x40178e, "startup failure branch unbound at 0x40178e"),
        (
            0x40177e,
            "startup C initializer failure continuation unbound at 0x40177e",
        ),
        (
            0x4016ac,
            "startup existing-state branch unbound at 0x4016ac",
        ),
    ] {
        g.nodes.insert(
            pc,
            Node {
                length: 2,
                op: Op::Reject(reason),
                successors: vec![],
            },
        );
    }

    let roles = BTreeMap::from([(0x41cc7c, "CrtRegionKind::Module".into())]);
    let main_call_bytes = crate::crt_ptd::raw(MAIN_CALL);
    let main_call_graph = crate::crt_startup_table::graph(&main_call_bytes, 0x401717)?;
    if main_call_graph.nodes.len() != 1
        || main_call_graph.nodes[&0x401717].op != Op::Call(Target::Direct(0x401280))
        || main_call_graph.end != 0x40171c
    {
        return Err("Main original CALL identity".into());
    }
    let main_call_guard = guard(0x401717, &main_call_bytes);
    let scope = crate::crt_ptd::raw(SCOPE);
    let body = crate::crt_stream_emit::emit_body_with_store(
        &g,
        |pc, t| {
            Ok(match(pc,t){(0x401647,Target::Direct(0x401913))=>"startup_caller_frame(rt,cpu,epoch,binding)?;cpu.call_activation(rt,0x40164c,0,|rt,c|startup_runtime_lock(rt,c,inputs))?;startup_caller_frame(rt,cpu,epoch,binding)?;".into(),(0x401673,Target::Direct(0x406ccc))=>"startup_caller_frame(rt,cpu,epoch,binding)?;if binding.image(rt,cpu,epoch)?.try_level!=0||rt.load(rt.process_image_pointer(inputs.image,0x41cc7c,4)?,32)?!=CrtValue::scalar(1){return Err(\"C initializer caller phase\");}cpu.call_activation(rt,0x401678,0,|rt,c|startup_c_array_observed(rt,c,inputs,Some(epoch),platform,features))?;startup_caller_frame(rt,cpu,epoch,binding)?;".into(),(0x401699,Target::Direct(0x406ca1))=>"startup_caller_frame(rt,cpu,epoch,binding)?;cpu.call_activation(rt,0x40169e,0,|rt,c|startup_cpp_array_original(rt,c,inputs))?;startup_caller_frame(rt,cpu,epoch,binding)?;".into(),(0x4016b4,Target::Direct(0x401a9c))=>"startup_caller_frame(rt,cpu,epoch,binding)?;if binding.image(rt,cpu,epoch)?.try_level!=0||rt.load(rt.process_image_pointer(inputs.image,0x41cc7c,4)?,32)?!=CrtValue::scalar(2){return Err(\"startup release caller phase\");}cpu.call_activation(rt,0x4016b9,0,|rt,c|startup_runtime_release(rt,c,inputs))?;startup_caller_frame(rt,cpu,epoch,binding)?;".into(),_=>return Err("startup caller call target".into())})
        },
        &roles,
        128,
        |_, _| Err("startup caller thread effect".into()),
        |pc, _| {
            Ok(if pc == 0x40164f {
                "if !matches!(rt.load(rt.process_image_pointer(inputs.image,0x41cc7c,4)?,32)?,CrtValue::Scalar{..}){return Err(\"startup state scalar field\");}".into()
            } else {
                String::new()
            })
        },
        |_, _| Err("startup caller unexpected return".into()),
        Some(0x4016ba),
        |pc, a, width| {
            let offset = match pc {
                0x40163d | 0x4016ae if width == 8 => Some(-25),
                0x401640 | 0x40167e if width == 32 => Some(-4),
                0x40164c if width == 8 => Some(-36),
                0x401663 | 0x4016a0 if width == 32 => None,
                _ => return Err("startup caller store shape".into()),
            };
            let target = crate::crt_stream_emit::address(a, &roles)?;
            let identity = if let Some(offset) = offset {
                format!("if p!=binding.at(rt,binding.layout.bp+({offset}))?{{return Err(\"startup caller local alias\");}}")
            } else {
                "if p!=rt.process_image_pointer(inputs.image,0x41cc7c,4)?{return Err(\"startup caller global alias\");}".into()
            };
            let transition = if pc == 0x401640 {
                format!("if rt.load(p,32)?!=CrtValue::scalar((-2i32)as u32)||v!=CrtValue::scalar(0){{return Err(\"startup caller scope transition\");}}let q=rt.process_image_pointer(inputs.image,binding.layout.scope,{})?;rt.memory.validate_immutable(q.cap,q.owner,q.address(),{}).map_err(|_|\"startup caller scope permission\")?;if binding.layout.scope!=0x41b238||rt.memory.read(q.address(),{}).map_err(|_|\"startup caller scope read\")?!=&{scope:?}{{return Err(\"startup caller scope bytes\");}}",scope.len(),scope.len(),scope.len())
            } else if pc == 0x4016a0 {
                "if rt.load(p,32)?!=CrtValue::scalar(1)||v!=CrtValue::scalar(2){return Err(\"startup initialization completion transition\");}".into()
            } else {
                String::new()
            };
            Ok(Some(format!("startup_caller_frame(rt,cpu,epoch,binding)?;let p={target};{identity}{transition}rt.store(p,{width},v)?;startup_caller_frame(rt,cpu,epoch,binding)?;")))
        },
    )?;
    out.push_str(r#"fn startup_caller_frame(rt:&CrtStreamRuntime,cpu:&CrtCpu,epoch:&NormalCallEpoch<'_>,binding:&CrtNormalBinding)->Result<(),&'static str>{binding.authority(rt,epoch)?;let image=binding.image(rt,cpu,epoch)?;epoch.validate_image(binding.id.ok_or("startup caller missing normal frame")?,&image)}"#);
    out.push_str(&format!("fn startup_post_initializer(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,epoch:&mut NormalCallEpoch<'_>,binding:&mut CrtNormalBinding)->Result<CrtValue,&'static str>{{startup_post_initializer_platform(rt,cpu,inputs,epoch,binding,None)}}fn startup_post_initializer_platform(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,epoch:&mut NormalCallEpoch<'_>,binding:&mut CrtNormalBinding,platform:Option<&CrtNativePlatform>)->Result<CrtValue,&'static str>{{startup_post_initializer_observed(rt,cpu,inputs,epoch,binding,platform,None)}}fn startup_post_initializer_observed(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,epoch:&mut NormalCallEpoch<'_>,binding:&mut CrtNormalBinding,platform:Option<&CrtNativePlatform>,features:Option<&CrtFeatureObservation>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;startup_caller_frame(rt,cpu,epoch,binding)?;let arg=binding.at(rt,binding.layout.low-4)?;if cpu.r[4]!=CrtValue::Pointer(arg)||rt.load(arg,32)?!=CrtValue::scalar(1){{return Err(\"startup caller argument/phase\");}}if binding.image(rt,cpu,epoch)?.try_level!= -2{{return Err(\"startup caller scope phase\");}}{}let _=(||->Result<CrtValue,&'static str>{{{body}}})()?;startup_caller_frame(rt,cpu,epoch,binding)?;startup_callback_cells(rt,cpu,inputs)?;startup_caller_frame(rt,cpu,epoch,binding)?;startup_main_arguments(rt,cpu,inputs,platform,epoch)?;startup_call_main(rt,cpu,inputs,epoch,binding)}}",guard(0x401632,&bytes)));
    out.push_str(&format!("fn startup_call_main(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,epoch:&mut NormalCallEpoch<'_>,parent:&mut CrtNormalBinding)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;startup_caller_frame(rt,cpu,epoch,parent)?;if parent.image(rt,cpu,epoch)?.try_level!=0||rt.load(rt.process_image_pointer(inputs.image,0x41cc7c,4)?,32)?!=CrtValue::scalar(2)||cpu.r[4]!=CrtValue::Pointer(parent.at(rt,parent.layout.low-12)?){{return Err(\"Main caller phase/argument stack\");}}{main_call_guard}cpu.call_activation(rt,0x40171c,0,|rt,c|startup_main_original(rt,c,inputs,epoch))?;Err(\"unexpected Main return\")}}"));
    out.push_str(&format!("fn startup_caller_bytes()->Vec<u8>{{vec!{bytes:?}}}fn startup_release_bytes()->Vec<u8>{{vec!{release:?}}}fn startup_runtime_lock_bytes()->Vec<u8>{{vec!{lock:?}}}fn startup_runtime_flag_bytes()->Vec<u8>{{vec!{flag:?}}}"));
    Ok(out)
}
fn guard(at: u32, bytes: &[u8]) -> String {
    format!("let p=rt.process_image_code(inputs.image,{at},{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"startup caller code read\")?!=&{bytes:?}{{return Err(\"startup caller code changed\");}}",bytes.len(),bytes.len())
}
#[test]
fn negative_stack_add_grows_without_reading_or_initializing_locals() {
    let mut extra = String::new();
    for (name, bytes) in [
        ("grow", vec![0x81, 0xc4, 0x00, 0xfd, 0xff, 0xff]),
        ("clean", vec![0x83, 0xc4, 4]),
    ] {
        let g = crate::crt_startup_table::graph(&bytes, 0x440000).unwrap();
        let body = crate::crt_stream_emit::emit_body_with_store(
            &g,
            |_, _| Err("stack fragment call".into()),
            &Default::default(),
            8,
            |_, _| Err("stack fragment FS".into()),
            |_, _| Ok(String::new()),
            |_, _| Err("stack fragment RET".into()),
            Some(g.end),
            |_, _, _| Ok(None),
        )
        .unwrap();
        extra.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{cpu.validate_active(rt)?;{body}}}"));
    }
    crate::crt_stream_callees_tests::native_bounded_stack(
        &extra,
        r#"
for mode in 0..4{
 let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0x9000,2048,CrtRegionKind::Stack,None).unwrap();let entry=rt.offset(stack,1536).unwrap();rt.store(entry,32,CrtValue::ProtectedReturn(71)).unwrap();let mut c=CrtCpu::new(entry,71).unwrap();let low=rt.offset(entry,-768).unwrap();
 if mode==1{rt.store(low,32,CrtValue::ProtectedReturn(999)).unwrap();}
 if mode<2{assert!(grow(&mut rt,&mut c).is_ok());assert_eq!(c.r[4],CrtValue::Pointer(low));assert_eq!(rt.load(low,32),Ok(if mode==1{CrtValue::ProtectedReturn(999)}else{CrtValue::Scalar{bits:0,known:0}}));assert_eq!((c.flags.cf,c.flags.zf,c.flags.of,c.flags.sf),(Some(true),Some(false),Some(false),Some(false)));}
 else{let arg=rt.offset(entry,-4).unwrap();rt.store(arg,32,if mode==3{CrtValue::ProtectedReturn(999)}else{CrtValue::scalar(5)}).unwrap();c.r[4]=CrtValue::Pointer(arg);let got=clean(&mut rt,&mut c);if mode==2{assert!(got.is_ok());assert_eq!(c.r[4],CrtValue::Pointer(entry));assert_eq!(rt.load(arg,32),Ok(CrtValue::Scalar{bits:0,known:0}));}else{assert_eq!(got,Err("CRT cleanup crosses protected word"));assert_eq!(c.r[4],CrtValue::Pointer(arg));assert_eq!(rt.load(arg,32),Ok(CrtValue::ProtectedReturn(999)));}}
 assert_eq!(rt.load(entry,32),Ok(CrtValue::ProtectedReturn(71)));assert!(!c.returned);
}
"#,
        "negative-stack-add",
    );
}
#[test]
fn original_inline_main_derives_layout_and_rejects_changed_restoration() {
    let p = crate::crt_ptd::raw(MAIN_PROLOG);
    let e = crate::crt_ptd::raw(MAIN_EPILOG);
    let (layout, guards, plan) = inline_contract(&p, &e).expect("actual inline frame shape");
    for field in [
        "low:-800",
        "bp:-4",
        "record:-20",
        "saved_sp:-28",
        "guard:-800",
    ] {
        assert!(layout.contains(field), "{field}");
    }
    assert_eq!(guards, "vec![-32]");
    assert!(plan.contains("CheckGuard{offset:-32,target:0x40154c}"));
    for i in 0..e.len() {
        let mut bad = e.clone();
        bad[i] ^= 1;
        assert!(inline_contract(&p, &bad).is_err(), "epilog mutation{i}");
    }
    for i in [6, 11, 24, 33, 40, 55] {
        let mut bad = p.clone();
        bad[i] ^= 1;
        assert!(inline_contract(&bad, &e).is_err(), "prolog mutation{i}");
    }
}
#[test]
fn original_startup_guard_reads_flag_and_rejects_unproved_thread_branch() {
    let g = lock_graph().unwrap();
    assert!(matches!(g.nodes[&0x40191d].op, Op::Reject(_)));
    assert!(matches!(
        g.nodes[&0x401914].op,
        Op::Call(Target::Direct(0x4021bf))
    ));
    source().expect("bounded original caller and zero-flag path must lower");
}
#[cfg(test)]
pub(crate) fn declared_frame_source() -> Result<String, String> {
    let bytes = crate::crt_ptd::raw(crate::crt_startup_entry::REGIONS[1].2)[..14].to_vec();
    let g = crate::crt_startup_table::graph(&bytes, 0x40161f)?;
    let body = crate::crt_stream_emit::emit_body_with_store(
        &g,
        |_, t| {
            if t != Target::Direct(0x401e60) {
                return Err("declared startup prolog target".into());
            }
            Ok("let id=(rt.generation+1)|(1u64<<63);rt.generation+=1;cpu.push(rt,CrtValue::ProtectedReturn(id))?;startup_helper(rt,cpu,id,binding.token,|rt,c,record,head|binding.install(rt,c,epoch,record,head))?;".into())
        },
        &Default::default(),
        32,
        |_, _| Err("declared prolog FS".into()),
        |_, _| Ok(String::new()),
        |_, _| Err("declared prolog RET".into()),
        Some(0x40162d),
        |_, _, _| Ok(None),
    )?;
    Ok(format!("fn declared_startup_post_frame(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,epoch:&mut NormalCallEpoch<'_>,binding:&mut CrtNormalBinding)->Result<CrtValue,&'static str>{{{}let h=rt.process_image_code(inputs.image,0x401e60,startup_helper_code().len()as u32)?;if rt.memory.read(h.address(),startup_helper_code().len()as u32).map_err(|_|\"declared helper read\")?!=startup_helper_code(){{return Err(\"declared helper bytes\");}}{body}}}",guard(0x40161f,&bytes)))
}

#[test]
fn original_result_branch_preserves_pops_failed_scope_and_unknown_truth() {
    let all = crate::crt_ptd::raw(CALLER);
    let mut graph = crate::crt_startup_table::graph(&all[0x46..0x67], 0x401678).unwrap();
    graph.nodes.insert(
        0x40177e,
        Node {
            length: 1,
            op: Op::Reject("independent original failure continuation"),
            successors: vec![],
        },
    );
    let body = crate::crt_stream_emit::emit_body_with_store(
        &graph,
        |_, _| Err("unexpected result-prefix call".into()),
        &Default::default(),
        32,
        |_, _| Err("unexpected result-prefix thread effect".into()),
        |_, _| Ok(String::new()),
        |_, _| Err("unexpected result-prefix RET".into()),
        Some(0x401699),
        |_, _, _| Ok(None),
    )
    .unwrap();
    let extra=format!("fn original_result(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu)->Result<CrtValue,&'static str>{{cpu.validate_active(rt)?;{body}}}");
    crate::crt_stream_callees_tests::native_bounded_stack(
        &extra,
        r#"
for mode in 0..8{
 let(mut rt,_)=CrtStreamRuntime::new_initializing(7,9,0x8000,65536).unwrap();let stack=rt.map_region(0x10000,2048,CrtRegionKind::Stack,None).unwrap();let entry=rt.offset(stack,1536).unwrap();rt.store(entry,32,CrtValue::ProtectedReturn(88)).unwrap();let mut c=CrtCpu::new(entry,88).unwrap();let sp=rt.offset(stack,512).unwrap();let bp=rt.offset(stack,if mode==6{1540}else{1024}).unwrap();c.r[4]=CrtValue::Pointer(sp);c.r[5]=CrtValue::Pointer(bp);let level=rt.offset(bp,-4).unwrap();if mode!=6{rt.store(level,32,CrtValue::scalar(0)).unwrap();}for(i,v)in[0x41513c,0x415158].into_iter().enumerate(){rt.store(rt.offset(sp,i as i64*4).unwrap(),32,CrtValue::scalar(v)).unwrap();}
 c.r[0]=match mode{0=>CrtValue::scalar(0),1|6=>CrtValue::scalar(9),2=>CrtValue::scalar(u32::MAX),3=>CrtValue::Scalar{bits:1,known:1},4=>CrtValue::Scalar{bits:0,known:0},5=>CrtValue::Scalar{bits:0,known:255},_=>rt.symbolic_bool(true).unwrap()};let before=c.r[0];let got=original_result(&mut rt,&mut c);assert!(!c.returned);assert_eq!(rt.load(entry,32),Ok(CrtValue::ProtectedReturn(88)));
 if mode==0{assert_eq!(got,Ok(CrtValue::scalar(0)));assert_eq!(c.r[4],CrtValue::Pointer(sp));assert_eq!(rt.load(sp,32),Ok(CrtValue::scalar(0x415130)));assert_eq!(rt.load(rt.offset(sp,4).unwrap(),32),Ok(CrtValue::scalar(0x415138)));assert_eq!(rt.load(level,32),Ok(CrtValue::scalar(0)));}
 else{assert_eq!(c.r[4],CrtValue::Pointer(rt.offset(sp,8).unwrap()));assert_eq!(rt.load(sp,32),Ok(CrtValue::Scalar{bits:0,known:0}));if matches!(mode,1..=3|7){assert_eq!(got,Err("independent original failure continuation"));assert_eq!(c.r[0],CrtValue::scalar(255));assert_eq!(rt.load(level,32),Ok(CrtValue::scalar(u32::MAX-1)));}else{assert_eq!(got,Err(if mode==6{"CRT protected saved/return overwrite"}else{"CRT unknown ZF"}));assert_eq!(c.r[0],before);if mode!=6{assert_eq!(rt.load(level,32),Ok(CrtValue::scalar(0)));}}}
}
"#,
        "original-caller-result",
    );
}
