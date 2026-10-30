//! Original locale publication and replacement under registered EH4 ownership.
use crate::crt_stream_ir::{Graph, Target};
pub(crate) const PROLOG: &str = "681022400064ff35000000008b442410896c24108d6c24102be0535657a100c041003145fc33c5508965e8ff75f88b45fcc745fcfeffffff8945f88d45f064a300000000c3";
pub(crate) const BODY: &str = "6a086800b64100e8477effff8b4508ff30e8ac1d0000598365fc008b4d0c8b41048b00ff308b01ff30e85b0200005959c745fcfeffffffe812000000";
pub(crate) const EPILOG: &str = "8b4df064890d00000000595f5e5bc9c20c00";
pub(crate) const CLEANUP: &str = "8b4510ff30e8b21d000059c3";
pub(crate) fn source() -> Result<String, String> {
    let raw = crate::crt_ptd::raw;
    let helper = raw(PROLOG);
    let p = crate::crt_exception_wrapper::PrologProof::prove(
        crate::crt_exception_wrapper::Region {
            bytes: &helper,
            origin: 0x401e60,
        },
        8,
        0x41b600,
        0x41c000,
        0x402210,
    )
    .map_err(|e| format!("locale prolog: {e}"))?;
    let eb = raw(EPILOG);
    let ep = crate::crt_exception_wrapper::EpilogProof::prove(
        crate::crt_exception_wrapper::Region {
            bytes: &eb,
            origin: 0x40a049,
        },
        &p,
    )
    .map_err(|e| format!("locale epilog: {e}"))?;
    let mut out = format!(
        "{}{}",
        p.emit("ucrt_locale_prolog")?,
        ep.emit("ucrt_locale_epilog")?
    );
    let cleanup = raw(CLEANUP);
    let cg = Graph::decode(&cleanup, 0x40a05b).map_err(|e| format!("locale cleanup: {e}"))?;
    let cb = crate::crt_stream_emit::emit_body(
        &cg,
        |pc, t| {
            if t != Target::Direct(0x40be17) {
                return Err("locale cleanup target".into());
            }
            let next = pc + cg.nodes[&pc].length;
            Ok(format!("cpu.call_activation(rt,{next},0,|rt,c|startup_second_lock(rt,c,inputs,false,held))?;"))
        },
        &Default::default(),
        64,
    )?;
    out.push_str(&format!("fn ucrt_locale_cleanup(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,held:&mut Option<CrtGlobalLock>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let q=rt.process_image_code(inputs.image,0x40a05b,{})?;if rt.memory.read(q.address(),{}).map_err(|_|\"locale cleanup code read\")?!=&{cleanup:?}{{return Err(\"locale cleanup code changed\");}}{cb}}}",cleanup.len(),cleanup.len()));
    let bytes = raw(BODY);
    let mut decoder =
        iced_x86::Decoder::with_ip(32, &bytes, 0x40a00d, iced_x86::DecoderOptions::NONE);
    let mut nodes = std::collections::BTreeMap::new();
    while decoder.can_decode() {
        let ins = decoder.decode();
        let pc = ins.ip() as u32;
        let at = (pc - 0x40a00d) as usize;
        let n = Graph::decode_instruction(&bytes[at..at + ins.len()], pc)?;
        if n.successors != [pc + n.length] {
            return Err("locale prefix nonlinear cut".into());
        }
        nodes.insert(pc, n);
    }
    let g = Graph {
        origin: 0x40a00d,
        end: 0x40a049,
        nodes,
    };
    let body = crate::crt_stream_emit::emit_body_with_exit(
        &g,
        |pc, t| {
            let next = pc + g.nodes[&pc].length;
            Ok(match t{
 Target::Direct(0x401e60)=>("let id=rt.generation.checked_add(1).filter(|n|*n<1u64<<63).ok_or(\"locale helper identity budget\")?|(1u64<<63);if rt.tags.values().any(|v|*v==CrtValue::ProtectedReturn(id)){return Err(\"locale helper identity collision\");}rt.generation=id&!(1u64<<63);cpu.push(rt,CrtValue::ProtectedReturn(id))?;ucrt_locale_prolog(rt,cpu,id,b.token,|rt,c,record,head|b.install(rt,c,epoch,record,head))?;").to_string(),
 Target::Direct(0x40bdcf)=>format!("cpu.call_activation(rt,{next},0,|rt,c|startup_second_lock(rt,c,inputs,true,&mut held))?;"),
 Target::Direct(0x40a296)=>format!("b.authority(rt,epoch)?;let lease=held.ok_or(\"locale replacement without lock\")?;rt.check_global(lease)?;cpu.call_activation(rt,{next},0,|rt,c|ucrt_locale_replace(rt,c,inputs,lease))?;"),
 Target::Direct(0x40a05b)=>format!("cpu.call_activation(rt,{next},0,|rt,c|ucrt_locale_cleanup(rt,c,inputs,&mut held))?;"),
 _=>return Err("locale helper unexpected call".into())})
        },
        &Default::default(),
        128,
        |_, _| Err("locale publication unexpected thread effect".into()),
        |pc, _| {
            Ok(if pc == 0x40a030 {
                "cpu.r[0]=CrtValue::Pointer(rt.module_word_pointer(inputs.image,cpu.r[0])?);".into()
            } else {
                String::new()
            })
        },
        |_, _| Ok(None),
        Some(0x40a049),
    )?;
    // The original normal epilog is independently proved; the body ends exactly
    // before its predecessor load, with no structural-success return bypass.
    let actual = format!("if pc=={}{{return Ok(cpu.r[0]);}}", 0x40a049u32);
    if !body.contains(&actual) {
        return Err("locale body terminal missing".into());
    }
    let body=body.replace(&actual,&format!("if pc=={}{{if held.is_some(){{return Err(\"locale epilog with held lock\");}}return ucrt_locale_epilog(rt,cpu,epoch,&mut b);}}",0x40a049u32));
    out.push_str(&format!("fn ucrt_locale_acquire(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,epoch:&mut NormalCallEpoch<'_>)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;let q=rt.process_image_code(inputs.image,0x40a00d,{})?;if rt.memory.read(q.address(),{}).map_err(|_|\"locale body code read\")?!=&{bytes:?}{{return Err(\"locale body code changed\");}}for(address,expected)in [(0x401e60u32,&{helper:?}[..]),(0x40a049,&{eb:?}[..])]{{let q=rt.process_image_code(inputs.image,address,expected.len()as u32)?;if rt.memory.read(q.address(),expected.len()as u32).map_err(|_|\"locale helper code read\")?!=expected{{return Err(\"locale helper code changed\");}}}}let mut b=CrtNormalBinding::bind_initializing(rt,cpu,epoch,ucrt_locale_epilog_layout(),inputs.init)?;let mut held=None;{body}}}",bytes.len(),bytes.len()));
    out.push_str(&replacement_source()?);
    Ok(out)
}

const REPLACE: &str = "8bff558bec568b7508837e4c007428ff764ce8482400008b464c593b0534d1410074143d78c14100740d83780c00750750e85e220000598b450c89464c5e85c0740750e8cf210000595dc3";
const REFERENCES: &str = "8bff558bec8b4508f0ff400c8b487c85c97403f0ff018b888400000085c97403f0ff018b888000000085c97403f0ff018b888c00000085c97403f0ff01566a068d48285e8179f838c2410074098b1185d27403f0ff028379f400740a8b51fc85d27403f0ff0283c11083ee0175d65effb09c000000e84b010000595dc3";
const CHILD: &str =
    "8bff558bec8b4d0885c9741681f920684100740e33c040f00fc181b0000000405dc3b8ffffff7f5dc3";
fn replacement_source() -> Result<String, String> {
    let mut out = String::new();
    for (name, hex, origin) in [
        ("ucrt_locale_replace", REPLACE, 0x40a296),
        ("ucrt_locale_references", REFERENCES, 0x40c4ad),
    ] {
        let bytes = crate::crt_ptd::raw(hex);
        let g = Graph::decode(&bytes, origin)?;
        let body = crate::crt_stream_emit::emit_body_with_hooks(
            &g,
            |pc, t| {
                let next = pc + g.nodes[&pc].length;
                Ok(match t{
   Target::Direct(0x40c4ad)=>format!("cpu.call_activation(rt,{next},0,|rt,c|ucrt_locale_references(rt,c,inputs,lease))?;"),
   Target::Direct(0x40c672)=>format!("cpu.call_activation(rt,{next},0,|rt,c|ucrt_locale_child(rt,c,inputs,lease))?;"),
   Target::Direct(0x40c6f5)|Target::Direct(0x40c52a)=>"return Err(\"locale prior-reference release/free unbound\");".into(),
   _=>return Err("locale replacement unknown call".into())})
            },
            &std::collections::BTreeMap::from([(0x41d134, "CrtRegionKind::Module".into())]),
            1024,
            |_, op| {
                let crate::crt_stream_ir::Op::LockedIncrement(crate::graph::Operand::Memory(a, 32)) =
                    op
                else {
                    return Err("locale reference effect form".into());
                };
                let address = crate::crt_stream_emit::address(a, &Default::default())?;
                Ok(format!("rt.check_global(lease)?;let p={address};cpu.increment_reference(rt,inputs.init,inputs.image,lease,p)?;"))
            },
            |_, op| {
                let mut bases = std::collections::BTreeSet::new();
                match op {
                    crate::crt_stream_ir::Op::LockedIncrement(crate::graph::Operand::Memory(
                        a,
                        32,
                    )) => {
                        if let Some(b) = a.base {
                            bases.insert(b);
                        }
                    }
                    crate::crt_stream_ir::Op::Ordinary(crate::graph::Operation::Binary(
                        _,
                        a,
                        b,
                    )) => {
                        for o in [a, b] {
                            if let crate::graph::Operand::Memory(a, _) = o {
                                if let Some(b) = a.base {
                                    bases.insert(b);
                                }
                            }
                        }
                    }
                    crate::crt_stream_ir::Op::Ordinary(crate::graph::Operation::Push(
                        crate::graph::Operand::Memory(a, _),
                    )) => {
                        if let Some(b) = a.base {
                            bases.insert(b);
                        }
                    }
                    _ => {}
                }
                Ok(bases.into_iter().filter(|r|*r!=4&&*r!=5).map(|r|format!("if !matches!(cpu.r[{r}],CrtValue::Pointer(_)){{cpu.r[{r}]=CrtValue::Pointer(rt.module_word_pointer(inputs.image,cpu.r[{r}])?);}} ")).collect())
            },
            |_, _| Ok(None),
        )?;
        let bind = if name == "ucrt_locale_replace" {
            "let sp=CrtCpu::pointer(cpu.r[4])?;let p=CrtCpu::pointer(rt.load(rt.offset(sp,4)?,32)?)?;let v=rt.heap_ptds.iter().find(|v|v.pointer==p&&v.layout==CrtPtdLayout::Ucrt).ok_or(\"locale replacement UCRT owner\")?;rt.heap_ptd_layout_view(p,v.slot,CrtPtdLayout::Ucrt)?;if rt.fls.get(&v.slot.index).map(|x|x.1)!=Some(CrtValue::Pointer(p)){return Err(\"locale replacement unpublished UCRT\");}"
        } else {
            "let sp=CrtCpu::pointer(cpu.r[4])?;let value=rt.load(rt.offset(sp,4)?,32)?;let p=rt.module_word_pointer(inputs.image,value)?;rt.store(rt.offset(sp,4)?,32,CrtValue::Pointer(p))?;"
        };
        out.push_str(&format!("fn {name}(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,lease:CrtGlobalLock)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;rt.check_global(lease)?;let p=rt.process_image_code(inputs.image,{origin},{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"locale replacement code read\")?!=&{bytes:?}{{return Err(\"locale replacement/reference code changed\");}}{bind}{body}}}",bytes.len(),bytes.len()));
    }
    out.push_str(&child_source()?);
    Ok(out)
}
fn child_source() -> Result<String, String> {
    let bytes = crate::crt_ptd::raw(CHILD);
    let mut nodes = std::collections::BTreeMap::new();
    for (start, end) in [(0usize, 20usize), (34, 41)] {
        let mut d = iced_x86::Decoder::with_ip(
            32,
            &bytes[start..end],
            0x40c672 + start as u64,
            iced_x86::DecoderOptions::NONE,
        );
        while d.can_decode() {
            let i = d.decode();
            let pc = i.ip() as u32;
            let at = (pc - 0x40c672) as usize;
            nodes.insert(pc, Graph::decode_instruction(&bytes[at..at + i.len()], pc)?);
        }
    }
    let g = Graph {
        origin: 0x40c672,
        end: 0x40c69b,
        nodes,
    };
    let body = crate::crt_stream_emit::emit_body_with_exit(
        &g,
        |_, _| Err("child unexpected call".into()),
        &Default::default(),
        32,
        |_, _| Err("child unexpected effect".into()),
        |_, _| Ok(String::new()),
        |_, _| Ok(None),
        Some(0x40c686),
    )?;
    let stop = format!("if pc=={}{{return Ok(cpu.r[0]);}}", 0x40c686u32);
    if !body.contains(&stop) {
        return Err("child dynamic cut missing".into());
    }
    let body = body.replace(
        &stop,
        &format!(
            "if pc=={}{{return Err(\"locale dynamic child XADD unbound at 0x40c686\");}}",
            0x40c686u32
        ),
    );
    Ok(format!("fn ucrt_locale_child(rt:&mut CrtStreamRuntime,cpu:&mut CrtCpu,inputs:&CrtEntropyInputs,lease:CrtGlobalLock)->Result<CrtValue,&'static str>{{inputs.validate(rt)?;cpu.validate_active(rt)?;rt.check_global(lease)?;let p=rt.process_image_code(inputs.image,0x40c672,{})?;if rt.memory.read(p.address(),{}).map_err(|_|\"locale child code read\")?!=&{bytes:?}{{return Err(\"locale child code changed\");}}{body}}}",bytes.len(),bytes.len()))
}
