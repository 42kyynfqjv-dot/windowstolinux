use super::*;
#[test]
fn emitted_activation_storage_preserves_context_and_cleanup_lifetimes() {
    let dir = std::env::temp_dir().join(format!("w2l-event-phases-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let source = format!(
        r#"
#![allow(dead_code)]
mod activation {{ {} }}
use activation::*;
fn context() -> Context {{ Context {{registers:[Some(10),Some(11),Some(12),Some(13),Some(0x8000),Some(0x8100),Some(16),Some(17)],ip:Some(0x1000),flags:Some(0x202)}} }}
fn main() {{
 let mut stack=Stack::new(3).unwrap();
 let a=stack.push(100,1,context()).unwrap();
 let b=stack.push(200,2,context()).unwrap();
 let c=stack.push(300,3,context()).unwrap();
 let mut other=Stack::new(3).unwrap();let foreign=other.push(100,1,context()).unwrap();
 let mut captured=context();stack.begin_search(captured.clone(),true).unwrap();
 captured.registers[0]=Some(99);
 assert_eq!(stack.pop_normal(c).err(),Some(Error::Phase));
 assert_eq!(stack.select_unwind(foreign),Err(Error::Identity));
 stack.select_unwind(a).unwrap();
 assert_eq!(stack.retire_cleaned(b).err(),Some(Error::Identity));
 let mut order=Vec::new();
 while let Some(frame)=stack.cleanup_frame().unwrap() {{
   // Observe original frame state while live, before retirement.
   assert_eq!(frame.saved.registers[4],Some(0x8000));
   order.push(frame.next);let id=frame.id;stack.retire_cleaned(id).unwrap();
 }}
 assert_eq!(order,vec![300,200]);assert_eq!(stack.top().unwrap().id,a);
 assert_eq!(stack.retire_cleaned(a).err(),Some(Error::Identity));
 stack.block();assert_eq!(stack.pop_normal(a).err(),Some(Error::Phase));
 let mut retry=Stack::new(1).unwrap();let mut original=context();
 retry.begin_search(original.clone(),true).unwrap();original.registers[0]=Some(99);
 assert_eq!(retry.retry_candidate().unwrap(),&context());
 assert_eq!(retry.push(0,0,context()),Err(Error::Phase));
 assert_eq!(retry.retry_candidate().err(),Some(Error::Phase));
 let mut unknown=context();unknown.registers[4]=None;
 let mut failed=Stack::new(1).unwrap();
 assert_eq!(failed.begin_search(unknown,true),Err(Error::UnknownContext));
 assert_eq!(failed.push(0,0,context()),Err(Error::Phase));
 let mut failed=Stack::new(1).unwrap();
 failed.begin_search(context(),false).unwrap();
 assert_eq!(failed.retry_candidate().err(),Some(Error::Noncontinuable));
 let mut stale=Stack::new(1).unwrap();let old=stale.push(1,1,context()).unwrap();
 stale.pop_normal(old).unwrap();let fresh=stale.push(1,1,context()).unwrap();
 assert_ne!(old,fresh);assert_eq!(stale.pop_normal(old).err(),Some(Error::Identity));
}}
"#,
        include_str!("../activation.rs")
    );
    let file = dir.join("phases.rs");
    let bin = dir.join("phases");
    std::fs::write(&file, source).unwrap();
    assert!(std::process::Command::new("rustc")
        .args(["--edition=2021"])
        .arg(&file)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap()
        .success());
    assert!(std::process::Command::new(&bin).status().unwrap().success());
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn structural_calls_do_not_grant_startup_emission_authority() {
    let graph = BTreeMap::from([
        (0, (Op::Call(10), 1)),
        (1, (Op::Ret, 2)),
        (10, (Op::Ret, 11)),
    ]);
    assert!(validate_calls(&graph, 0).is_ok());
    // The environment-specific proof still requires acquisition before helpers.
    // Removing this condition would not supply a startup/context proof.
    assert_eq!(
        prove(graph, 0).err().as_deref(),
        Some("input: internal call context")
    );
}
#[test]
fn emitted_continuations_keep_nested_state_and_terminal_effects() {
    let dir = std::env::temp_dir().join(format!("w2l-continuations-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("control.rs");
    let bin = dir.join("control");
    let source = format!(
        r#"
const MAX_ACTIVATIONS:usize=4;
struct Machine {{ r:[u32;6], stack:Vec<u32>, mode:u32 }}
{}
fn block(pc:u32,s:&mut Machine)->Flow {{ match pc {{
  0=>Flow::Call{{target:10,next:1}},
  1=>{{s.r[0]+=1;Flow::Return}},
  10=>Flow::Call{{target:20,next:11}},
  11=>{{s.r[0]+=10;Flow::Return}},
  20=>match s.mode {{
   0=>{{s.r[0]=30;Flow::Return}},
   1=>Flow::Terminal(77),
   2=>{{s.stack.pop();Flow::Return}},
   3=>{{*s.stack.last_mut().unwrap()=999;Flow::Return}},
   4=>{{s.r[3]=99;Flow::Return}},
   5=>Flow::Call{{target:20,next:11}},
   _=>unreachable!(),
  }},
  _=>panic!("unvalidated continuation"),
}} }}
fn main() {{
 for (mode,expected) in [(0,41),(1,77),(2,203),(3,203),(4,203),(5,203)] {{
  let mut s=Machine{{r:[0,0,0,7,8,9],stack:vec![0],mode}};
  assert_eq!(execute(0,&mut s),expected);
  if mode==0 {{assert_eq!(s.stack,vec![0]);assert_eq!(&s.r[3..],&[7,8,9]);}}
  if mode==1 {{assert_eq!(s.r[0],0);assert_eq!(s.stack.len(),3);}}
 }}
}}
"#,
        format_args!(
            "mod activation {{ {} }}\n{}",
            include_str!("../activation.rs"),
            include_str!("continuation.txt")
        )
    );
    std::fs::write(&file, source).unwrap();
    assert!(std::process::Command::new("rustc")
        .arg("--edition=2021")
        .arg(&file)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap()
        .success());
    assert!(std::process::Command::new(&bin).status().unwrap().success());
    std::fs::remove_dir_all(dir).unwrap();
}
fn code() -> Vec<u8> {
    // Literal compiler-form program; expectations below are not generated by the lifter.
    let text="83ec088d04246a03506808204000ff15002040008bc885c97509b8c800000083c408c383f9417609b8cb00000083c408c383f9027609b8c900000083c408c38b1424568d42d06683f809772b0fb7d283ea3083f90275198b7424068d46d06683f80977138d14920fb7c68d52e88d14508bc25e83c408c3b8ca0000005e83c408c3";
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn graph() -> Graph {
    graph_for(&code())
}
fn graph_for(program: &[u8]) -> Graph {
    graph_at(program, 0x1000)
}
fn graph_at(program: &[u8], entry: u32) -> Graph {
    let mut bytes = program.to_vec();
    bytes.resize(512, 0);
    bytes.extend(b"W\0\x32\0L\0_\0I\0N\0P\0U\0T\0\0\0");
    let c = Candidate {
        functions: Default::default(),
        bytes: &bytes,
        base: 0x400000,
        entry,
        image_size: 0x3000,
        sections: vec![
            Section {
                rva: 0x1000,
                raw: 0,
                size: program.len() as u32,
                virtual_size: program.len() as u32,
                flags: CODE,
            },
            Section {
                rva: 0x2008,
                raw: 512,
                size: 20,
                virtual_size: 20,
                flags: DATA,
            },
        ],
        metadata: vec![],
        iat: 0x2000,
        api: Api::Environment,
        pointers: [(entry + 10, 0x2008), (entry + 16, 0x2000)].into(),
    };
    decode(&c).unwrap()
}
#[test]
fn decoded_forms_and_independent_complete_path_proof() {
    let g = graph();
    assert_eq!(g.len(), 47);
    assert!(matches!(g[&0x1000].0, Op::Allocate));
    assert!(matches!(g[&0x1018].0, Op::Branch(Condition::Ne, 0x1023)));
    assert!(matches!(g[&0x1046].0, Op::Compare(0, 16, 9)));
    assert!(matches!(g[&0x1057].0, Op::Load(3, 6)));
    assert!(matches!(g[&0x106a].0, Op::Lea(2, 2, 2, 0, 0xffffffe8)));
    let p = prove(g, 0x1000).unwrap();
    assert_eq!(p.loads, [(0x103f, 0), (0x1057, 2)].into());
    let s = p.emit();
    assert!(s.contains("wrapping_mul(2)"));
    assert!(!s.contains("program_exit"));
    assert!(!s.contains("Decoder"));
}
#[test]
fn unsafe_api_guards_and_full_word_loads_reject() {
    for (at, op) in [
        (0x1006, Op::Push(2)),
        (0x1008, Op::Push(0)),
        (0x1018, Op::Branch(Condition::Ne, 0x103f)),
        (0x1034, Op::Branch(Condition::A, 0x103f)),
        (0x1055, Op::Branch(Condition::Ne, 0x1057)),
        (0x1057, Op::Load(3, 8)),
        (0x1057, Op::Load(3, 7)),
        (0x1057, Op::Load(3, 0)),
        (0x104a, Op::Branch(Condition::Be, 0x1077)),
        (0x1062, Op::Branch(Condition::Be, 0x1077)),
    ] {
        let mut g = graph();
        g.get_mut(&at).unwrap().0 = op;
        assert!(prove(g, 0x1000).is_err(), "{at:x} {op:?}");
    }
}
#[test]
fn lifetimes_saved_slots_unknown_states_and_exit_gates_reject() {
    for (at, op) in [
        (0x1003, Op::Mov(0, 0)),
        (0x1014, Op::Move(1, 2)),
        (0x1016, Op::Cleanup),
        (0x1042, Op::Push(0)),
        (0x1072, Op::Cleanup),
        (0x1073, Op::Restore),
        (0x107c, Op::Cleanup),
        (0x101a, Op::Mov(0, 256)),
        (0x1052, Op::Arithmetic(2, 0, true)),
        (0x104c, Op::Move(2, 3)),
        (0x1070, Op::Move(0, 3)),
        (0x1064, Op::Acquire),
        (0x1064, Op::Allocate),
    ] {
        let mut g = graph();
        g.get_mut(&at).unwrap().0 = op;
        assert!(prove(g, 0x1000).is_err(), "{at:x} {op:?}");
    }
}
#[test]
fn safe_program_changes_change_emission_and_determinism() {
    let g = graph();
    let a = prove(g.clone(), 0x1000).unwrap().emit();
    assert_eq!(a, prove(g.clone(), 0x1000).unwrap().emit());
    let mut changed = g;
    changed.get_mut(&0x101a).unwrap().0 = Op::Mov(0, 199);
    let b = prove(changed, 0x1000).unwrap().emit();
    assert_ne!(a, b);
    assert!(b.contains("s.r[0]=199;"));
}

fn guard_graph() -> Graph {
    let text="83ec088d04246a03506808204000ff150020400083f8417609b8cb00000083c408c383f8027609b8c900000083c408c385c07509b8c800000083c408c383f802752e8b5424028d42d06683f80977378b0c248d41d06683f809772b0fb7c18d0c800fb7c28d044805f0fdffff83c408c38b0c248d41d06683f809770a0fb7c183e83083c408c3b8ca00000083c408c3";
    let b: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    graph_for(&b)
}
#[test]
fn reordered_guard_ir_and_unsafe_paths() {
    let g = guard_graph();
    for (at, expected) in [
        (0x1014, "Compare(0, 32, 65)"),
        (0x1030, "Test(0)"),
        (0x1042, "Load(2, 2)"),
        (0x104f, "Load(1, 0)"),
        (0x105b, "ZeroExtend(0, 1)"),
        (0x105e, "Lea(1, 0, 0, 4, 0)"),
        (0x1067, "Arithmetic(0, 4294966768, false)"),
        (0x107f, "Arithmetic(0, 48, true)"),
    ] {
        assert_eq!(format!("{:?}", g[&at].0), expected);
    }
    assert_eq!(
        prove(g.clone(), 0x1000).unwrap().loads,
        [(0x1042, 2), (0x104f, 0), (0x1070, 0)].into()
    );
    for (at, op) in [
        (0x1032, Op::Branch(Condition::Be, 0x103d)),
        (0x1040, Op::Branch(Condition::Be, 0x1070)),
        (0x1042, Op::Load(2, 4)),
        (0x1049, Op::Compare(1, 16, 9)),
        (0x104d, Op::Branch(Condition::Be, 0x1086)),
        (0x1055, Op::Arithmetic(0, 1, false)),
        (0x1070, Op::Load(1, 2)),
    ] {
        let mut bad = g.clone();
        bad.get_mut(&at).unwrap().0 = op;
        assert!(prove(bad, 0x1000).is_err(), "{at:x}");
    }
}
#[test]
fn production_ir_register_permutations_and_return_adapter() {
    for (index, map) in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ]
    .into_iter()
    .enumerate()
    {
        let reg = |r: usize| if r < 3 { map[r] } else { r };
        let mut out = Graph::new();
        for (pc, (op, next)) in graph() {
            let op = match op {
                Op::Move(d, s) => Op::Move(reg(d), if pc == 0x1014 { 0 } else { reg(s) }),
                Op::Mov(d, v) => Op::Mov(reg(d), v),
                Op::Test(r) => Op::Test(reg(r)),
                Op::Compare(r, w, v) => Op::Compare(reg(r), w, v),
                Op::Load(r, o) => Op::Load(reg(r), o),
                Op::Lea(d, a, b, k, c) => Op::Lea(reg(d), reg(a), reg(b), k, c),
                Op::ZeroExtend(d, s) => Op::ZeroExtend(reg(d), reg(s)),
                Op::Arithmetic(r, v, sub) => Op::Arithmetic(reg(r), v, sub),
                Op::Binary(d, s, m) => Op::Binary(reg(d), reg(s), m),
                Op::Branch(c, t) => Op::Branch(c, t * 4),
                Op::Ret => {
                    out.insert(pc * 4, (Op::Move(0, reg(0)), pc * 4 + 1));
                    out.insert(pc * 4 + 1, (Op::Ret, pc * 4 + 2));
                    continue;
                }
                op => op,
            };
            out.insert(pc * 4, (op, next * 4));
        }
        let source = prove(out, 0x4000).unwrap().emit();
        assert!(source.contains("wrapping_mul"));
        if cfg!(target_os = "linux") {
            let dir =
                std::env::temp_dir().join(format!("w2l-scalar-{}-{index}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("permutation.rs");
            let binary = dir.join("native");
            std::fs::write(&path, source).unwrap();
            let built = std::process::Command::new("rustc")
                .arg("--edition=2021")
                .arg(&path)
                .arg("-o")
                .arg(&binary)
                .output()
                .unwrap();
            assert!(
                built.status.success(),
                "{}",
                String::from_utf8_lossy(&built.stderr)
            );
            for (value, expected) in [("7", 7), ("42", 42), ("07", 7), ("a", 202), ("", 200)] {
                let r = std::process::Command::new(&binary)
                    .env_clear()
                    .env("W2L_INPUT", value)
                    .output()
                    .unwrap();
                assert_eq!(r.status.code(), Some(expected));
                assert!(r.stdout.is_empty() && r.stderr.is_empty());
            }
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}

#[test]
fn nonlinear_decoded_paths_and_native_boundaries() {
    let hex="83ec088d04246a03506808204000ff15002040008bc885c97509b8c800000083c408c383f9417609b8cb00000083c408c383f9027609b8c900000083c408c38b14248d42d06683f809772c0fb7d283c2d00fafd283f90275188b4c24028d41d06683f80977110fb7c983c1d00fafc903d18bc283c408c3b8ca00000083c408c3";
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let g = graph_for(&bytes);
    assert!(matches!(g[&0x1051].0, Op::Binary(2, 2, true)));
    assert!(matches!(g[&0x106c].0, Op::Binary(1, 1, true)));
    assert!(matches!(g[&0x106f].0, Op::Binary(2, 1, false)));
    for (at, op) in [
        (0x1049, Op::Branch(Condition::Be, 0x1077)),
        (0x1054, Op::Compare(2, 32, 2)),
        (0x1054, Op::Arithmetic(1, 0, false)),
        (0x1059, Op::Load(1, 4)),
        (0x1064, Op::Branch(Condition::Be, 0x1077)),
        (0x1066, Op::Move(1, 3)),
        (0x106f, Op::ZeroExtend(2, 2)),
    ] {
        let mut bad = g.clone();
        bad.get_mut(&at).unwrap().0 = op;
        assert!(prove(bad, 0x1000).is_err(), "{at:x}");
    }
    let source = prove(g, 0x1000).unwrap().emit();
    assert!(source.contains("wrapping_mul"));
    if cfg!(target_os = "linux") {
        let dir = std::env::temp_dir().join(format!("w2l-nonlinear-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("n.rs");
        let bin = dir.join("native");
        std::fs::write(&file, source).unwrap();
        assert!(std::process::Command::new("rustc")
            .args(["--edition=2021"])
            .arg(&file)
            .arg("-o")
            .arg(&bin)
            .status()
            .unwrap()
            .success());
        for a in 0..10 {
            for b in 0..10 {
                let r = std::process::Command::new(&bin)
                    .env_clear()
                    .env("W2L_INPUT", format!("{a}{b}"))
                    .output()
                    .unwrap();
                assert_eq!(r.status.code(), Some(a * a + b * b));
                assert!(r.stdout.is_empty() && r.stderr.is_empty());
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn helper_actual_context_and_independent_negative_paths() {
    let hex="8b5424040fb70a8d41d06683f809772583e930837c24080275180fb752028d42d06683f809770e8d0c898bc28d49e88d0c488bc1c3b8ca000000c3cccccccccc83ec088d04246a03506808204000ff150020400085c07509b8c800000083c408c383f8417609b8cb00000083c408c383f8027609b8c900000083c408c3508d44240450e878ffffff83c40883c408c3";
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let g = graph_at(&bytes, 0x1040);
    assert!(matches!(g[&0x1083].0, Op::Call(0x1000)));
    assert!(matches!(g[&0x101a].0, Op::ReadWord(2, 2, 2)));
    let p = prove(g.clone(), 0x1040).unwrap();
    assert_eq!(p.loads, [(0x1004, 0), (0x101a, 2)].into());
    for (at, op) in [
        (0x1083, Op::Call(0x1040)),
        (0x1083, Op::Call(0x1001)),
        (0x1000, Op::Argument(2, 8)),
        (0x1000, Op::Argument(2, 0)),
        (0x1004, Op::ReadWord(1, 2, 6)),
        (0x1004, Op::Cleanup),
        (0x1004, Op::Call(0x1000)),
        (0x107e, Op::Mov(0, 0)),
        (0x1056, Op::Branch(Condition::Be, 0x1061)),
        (0x1088, Op::Ret),
    ] {
        let mut bad = g.clone();
        bad.get_mut(&at).unwrap().0 = op;
        assert!(prove(bad, 0x1040).is_err(), "{at:x}");
    }
    // Shared call-site context is conservative: a second call after volatile clobber
    // cannot inherit the prior pointer arguments or re-use a protected continuation.
    let mut bad = g.clone();
    bad.get_mut(&0x108b).unwrap().0 = Op::Call(0x1000);
    assert!(prove(bad, 0x1040).is_err());
    // A nested call without explicitly passed arguments cannot borrow the parent slots.
    let mut nested = g.clone();
    nested.get_mut(&0x1000).unwrap().0 = Op::Call(0x2000);
    nested.insert(0x2000, (Op::Argument(2, 4), 0x2001));
    nested.insert(0x2001, (Op::Ret, 0x2002));
    assert!(prove(nested, 0x1040).is_err());
    let source = p.emit();
    if cfg!(target_os = "linux") {
        let dir = std::env::temp_dir().join(format!("w2l-helper-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("h.rs");
        let bin = dir.join("native");
        std::fs::write(&file, source).unwrap();
        assert!(std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(&file)
            .arg("-o")
            .arg(&bin)
            .status()
            .unwrap()
            .success());
        for (value, expected) in [
            ("7", 7),
            ("42", 42),
            ("07", 7),
            ("99", 99),
            ("a", 202),
            ("", 200),
            ("123", 201),
            ("0/", 202),
        ] {
            let r = std::process::Command::new(&bin)
                .env_clear()
                .env("W2L_INPUT", value)
                .output()
                .unwrap();
            assert_eq!(r.status.code(), Some(expected));
            assert!(r.stdout.is_empty() && r.stderr.is_empty());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn postcall_composition_native_and_rejections() {
    let hex="83ec088d04246a03506808204000ff150020400085c07509b8c800000083c408c383f8417609b8cb00000083c408c383f8027609b8c900000083c408c3508d44240450e82800000083c4083dca000000750483c408c38d04450600000083c408c3cccccccccccccccccccccccccccccc8b4c24040fb70183e83083f809771a837c24080275180fb7510283ea3083fa0977078d0c808d044ac3b8ca000000c3";
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let g = graph_for(&bytes);
    assert!(matches!(g[&0x104b].0, Op::Compare(0, 32, 202)));
    assert!(matches!(g[&0x1056].0, Op::Scaled(0, 0, 2, 6)));
    assert!(matches!(g[&0x1070].0, Op::Argument(1, 4)));
    let source = prove(g.clone(), 0x1000).unwrap().emit();
    for (pc, op) in [
        (0x104b, Op::Test(1)),
        (0x1070, Op::Argument(1, 8)),
        (0x1086, Op::ReadWord(2, 1, 6)),
        (0x107d, Op::Branch(Condition::Be, 0x1099)),
        (0x1048, Op::Ret),
    ] {
        let mut bad = g.clone();
        bad.get_mut(&pc).unwrap().0 = op;
        assert!(prove(bad, 0x1000).is_err(), "{pc:x}");
    }
    if cfg!(target_os = "linux") {
        let dir = std::env::temp_dir().join(format!("postcall-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("p.rs");
        let bin = dir.join("native");
        std::fs::write(&file, source).unwrap();
        assert!(std::process::Command::new("rustc")
            .args(["--edition=2021"])
            .arg(file)
            .arg("-o")
            .arg(&bin)
            .status()
            .unwrap()
            .success());
        for (input, expected) in [
            ("0", 6),
            ("99", 204),
            ("98", 202),
            ("42", 90),
            ("a", 202),
            ("0/", 202),
            ("", 200),
            ("123", 201),
            ("９", 202),
        ] {
            let r = std::process::Command::new(&bin)
                .env_clear()
                .env("W2L_INPUT", input)
                .output()
                .unwrap();
            assert_eq!(r.status.code(), Some(expected));
            assert!(r.stdout.is_empty() && r.stderr.is_empty());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn normalized_operand_width_prefix_and_register_boundaries() {
    let decode_one = |bytes: &[u8]| {
        let mut d = Decoder::with_ip(32, bytes, 0x1000, DecoderOptions::NONE);
        let i = d.decode();
        if i.is_invalid() || i.len() != bytes.len() {
            return Err("invalid".to_string());
        }
        normalize(&i, bytes)
    };
    // Independent ModRM register numbering, including preserved ESI/EDI/EBP.
    for (encoding, internal) in [(0, 0), (1, 1), (2, 2), (6, 3), (7, 4), (5, 5)] {
        assert!(
            matches!(decode_one(&[0x8b,0xc0+encoding*8]).unwrap(),Op::Move(d,0) if d==internal)
        );
        assert!(
            matches!(decode_one(&[0x0f,0x46,0xc0+encoding*8]).unwrap(),Op::Select(Condition::Be,d,0) if d==internal)
        );
    }
    for (bytes, expected) in [
        (vec![0x8d, 0x45, 0xf8], "Address(0, true, -8)"),
        (vec![0x0f, 0xb7, 0x55, 0xfa], "StackRead(2, true, -6, 2)"),
        (vec![0x6b, 0xca, 0xff], "Multiply(1, 2, 4294967295)"),
        (vec![0x83, 0xec, 12], "AllocateN(12)"),
        (vec![0x74, 0xfc], "Branch(Eq, 4094)"),
    ] {
        assert_eq!(format!("{:?}", decode_one(&bytes).unwrap()), expected);
    }
    for bytes in [
        vec![0x66, 0x8b, 0xc1],
        vec![0x67, 0x8b, 0xc1],
        vec![0x64, 0x0f, 0xb7, 1],
        vec![0xf3, 0x8b, 0xc1],
        vec![0x8b, 0xe0],
        vec![0x8b, 0xd8],
        vec![0x0f, 0x46, 1],
        vec![0x83, 0xec, 16],
        vec![0xff, 0xe0],
        vec![0x8d, 4],
    ] {
        assert!(decode_one(&bytes).is_err(), "{bytes:02x?}");
    }
}

#[test]
fn control_context_cycles_and_backward_acyclic_targets() {
    let g: Graph = [
        (100, (Op::Call(10), 110)),
        (110, (Op::Ret, 111)),
        (10, (Op::Branch(Condition::Eq, 30), 20)),
        (20, (Op::Jump(5), 21)),
        (30, (Op::Jump(5), 31)),
        (5, (Op::Ret, 6)),
    ]
    .into();
    validate_calls(&g, 100).unwrap();
    let mut cycle = g.clone();
    cycle.insert(5, (Op::Jump(10), 6));
    assert!(validate_calls(&cycle, 100).is_err());
    let mut recursion = g.clone();
    recursion.insert(5, (Op::Call(100), 6));
    assert!(validate_calls(&recursion, 100).is_err());
    let mut missing = g;
    missing.remove(&5);
    assert!(validate_calls(&missing, 100).is_err());
    // A large acyclic expansion still has a finite admission budget.
    let mut large = Graph::new();
    for i in 0..14 {
        large.insert(i * 3, (Op::Branch(Condition::Eq, i * 3 + 2), i * 3 + 1));
        large.insert(i * 3 + 1, (Op::Jump(i * 3 + 3), i * 3 + 2));
        large.insert(i * 3 + 2, (Op::Jump(i * 3 + 3), i * 3 + 3));
    }
    large.insert(42, (Op::Ret, 43));
    assert!(validate_calls(&large, 0).is_err());
}
