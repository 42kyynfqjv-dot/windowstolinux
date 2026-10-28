//! Independent connected-path composition, with synthetic code/data addresses.
//! Expected state is arithmetic from this authored layout, not a Windows report.
use super::*;

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn region(va: u32, bytes: Vec<u8>) -> Region {
    Region { va, bytes }
}
fn call(code: &mut Vec<u8>, origin: u32, target: u32) {
    let next = origin + code.len() as u32 + 5;
    code.push(0xe8);
    code.extend(target.wrapping_sub(next).to_le_bytes());
}
fn store(code: &mut Vec<u8>, offset: i32, value: u32) {
    code.extend([0xc7, 0x85]);
    code.extend(offset.to_le_bytes());
    code.extend(value.to_le_bytes());
}
fn fixture(eax: u32) -> (Input, Connected) {
    let mut input = super::tests::fixture();
    let mut child = super::tests::fixture().frames.remove(0);
    child.prefix.va = 0x9000;
    child.table.va = 0x9200;
    child.prefix.bytes[6..10].copy_from_slice(&0x9200u32.to_le_bytes());
    let level = child.prefix.bytes.len() - 15;
    child.prefix.bytes[level..level + 4].copy_from_slice(&(-2i32).to_le_bytes());
    let child_call = child.prefix.va + child.prefix.bytes.len() as u32;
    let event_call = input.calls.remove(0).bytes;

    // An 800-byte allocation provides the complete 716-byte CONTEXT plus
    // separately owned outputs. EBP=entrySP-4; final ESP=EBP-832.
    let mut prefix=bytes("558bec6afe6800400000680070000064a1000000005081ec20030000535657a1106000003145f833c5508d45f064a3000000008965e8");
    store(&mut prefix, -780, 321);
    input.frames[0].prefix = region(0x1000, prefix);
    input.frames[0].table.bytes[8..12].copy_from_slice(&(-832i32).to_le_bytes());
    input.frames[0].table.bytes[24..28].copy_from_slice(&0xa000u32.to_le_bytes());
    child.table.bytes[24..28].copy_from_slice(&0xa000u32.to_le_bytes());
    input.frames.push(child);

    let init_va = 0x1000 + input.frames[0].prefix.bytes.len() as u32;
    let mut init = vec![0x68];
    init.extend(716u32.to_le_bytes());
    init.extend([0x6a, 0, 0x8d, 0x85]);
    init.extend((-768i32).to_le_bytes());
    init.push(0x50);
    call(&mut init, init_va, 0x8000);
    init.extend([0x83, 0xc4, 12, 0x6a, 0, 0xff, 0x15]);
    init.extend(0x6030u32.to_le_bytes());
    init.extend([0x89, 0x85]);
    init.extend((-792i32).to_le_bytes());
    init.extend([0xc7, 0x45, 0xfc, 0, 0, 0, 0]);
    let call_va = init_va + init.len() as u32;
    let mut outer_call = Vec::new();
    call(&mut outer_call, call_va, 0x9000);
    input.calls = vec![region(call_va, outer_call), region(child_call, event_call)];

    // Independent landing: restore the prolog-saved stack; deactivate scope;
    // write EAX/SP/BP/IP into the same owned CONTEXT; perform nonlocal Restore.
    let mut landing = bytes("8b65e8");
    store(&mut landing, -788, 1);
    landing.extend(bytes("c745fcfeffffff8d8d"));
    landing.extend((-768i32).to_le_bytes());
    landing.extend([0xc7, 0x81]);
    landing.extend(176u32.to_le_bytes());
    landing.extend(eax.to_le_bytes());
    landing.extend([0x89, 0xa1]);
    landing.extend(196u32.to_le_bytes());
    landing.extend([0x89, 0xa9]);
    landing.extend(180u32.to_le_bytes());
    landing.extend([0x8d, 0x05]);
    let address_at = landing.len();
    landing.extend([0; 4]);
    landing.extend([0x89, 0x81]);
    landing.extend(184u32.to_le_bytes());
    landing.push(0x51);
    call(&mut landing, 0xa000, input.restore.va);
    // A real unreachable sentinel write, skipped by the proved nonlocal call.
    landing.extend(bytes("830d0000a00040"));
    let target = 0xa000 + landing.len() as u32;
    landing[address_at..address_at + 4].copy_from_slice(&target.to_le_bytes());
    for (register, offset) in [(0, -800i32), (4, -804), (5, -808)] {
        landing.extend([0x89, 0x85 | (register << 3)]);
        landing.extend(offset.to_le_bytes());
    }
    input.landings = vec![region(0xa000, landing[..3].to_vec())];
    input.target = region(target, landing[(target - 0xa000) as usize..].to_vec());

    let mut guard=bytes("558bec568b7508578b7d0c8b0683f8fe740d8b4e0403cf330c38e8000000008b46088b4e0c03cf330c385f5e5de900000000");
    guard[27..31].copy_from_slice(&0xb100u32.wrapping_sub(0xb000 + 31).to_le_bytes());
    guard[46..50].copy_from_slice(&0xb100u32.wrapping_sub(0xb000 + 50).to_le_bytes());
    let mut security = bytes("3b0d106000007501c3e900000000");
    security[10..14].copy_from_slice(&0xb200u32.wrapping_sub(0xb100 + 14).to_le_bytes());
    let context=bytes("558bec813d5060000000d10000741f648b0d180000008b45088b80c40000003b410872053b410476056a0d59cd295dc3");

    let mut handler = bytes("558bec83ec1c538b5d085657c645ff00ff33c745f401000000");
    call(&mut handler, 0xc000, input.normalizer.va);
    handler.extend(bytes("89038b5d0c8b43088d731033051060000056508975f08945f8"));
    call(&mut handler, 0xc000, 0xb000);
    handler.extend([0xff, 0x75, 16]);
    call(&mut handler, 0xc000, 0xd000);
    handler.extend(bytes("8b450883c4108b7b0cf6400466755a"));
    input.installer.va = 0xc000 + handler.len() as u32;
    handler.extend(&input.installer.bytes);
    input.handler_va = 0xc000;
    for frame in &mut input.frames {
        frame.prefix.bytes[11..15].copy_from_slice(&0xc000u32.to_le_bytes());
    }
    let connected = Connected {
        initializer: region(init_va, init),
        fill_helper: region(
            0x8000,
            bytes("8b4c240c0fb64424088bd78b7c240485c9740888074783e90175f88b4424048bfac3"),
        ),
        fill_features: [0x6040, 0x6044],
        module_iat: 0x6030,
        module_base: 0x1000,
        module_size: 0x10000,
        selected_landing: region(0xa000, landing),
        handler_prefix: region(0xc000, handler),
        guard_helper: region(0xb000, guard),
        security_helper: region(0xb100, security),
        context_helper: region(0xd000, context),
        context_selector: 0x6050,
    };
    (input, connected)
}

#[test]
fn independent_connected_initialization_guards_and_restoration_execute() {
    for expected in [0u32, 77, u32::MAX] {
        let (input, connected) = fixture(expected);
        let source = prove_connected(&input, &connected).unwrap().emit();
        let harness = format!(
            r#"
fn main(){{
 let current=[9,8,7,6,0x3f8000,0x3f9000,5,4,3,0x202];
 for cookie in [0u32,0x12345678,u32::MAX]{{
  let result=run_connected(0x400000,cookie,current,0,19,0x300000,0x410000,0,0x3f0000).unwrap();
  assert_eq!(result.selected_frame,0);assert_eq!(result.selected_target,0xa000);
  assert_eq!(result.trace,19);assert_eq!(result.live,vec![true,false]);
  assert_eq!(result.restored[0],Some({expected}u32));
  assert_eq!(result.restored[4],Some(0x400000-4-832));
  assert_eq!(result.restored[5],Some(0x400000-4));
  assert_eq!(result.restored[8],Some({target}u32));
  for (offset,value) in [(-780,321u32),(-788,1),(-800,{expected}u32)]{{
   let index=result.offsets[0].iter().position(|&x|x==offset).unwrap();
   assert_eq!(result.frame_words[0][index],Some(value));
  }}
  for register in [1,2,3,6,7,9]{{assert_eq!(result.restored[register],None);}}
 }}
}}
"#,
            target = input.target.va
        );
        let dir = std::env::temp_dir().join(format!(
            "w2l-connected-review-{}-{expected}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("run.rs");
        let binary = dir.join(if cfg!(windows) { "run.exe" } else { "run" });
        std::fs::write(&file, source + &harness).unwrap();
        let compile = std::process::Command::new("rustc")
            .arg("--edition=2021")
            .arg(&file)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );
        assert!(std::process::Command::new(binary)
            .status()
            .unwrap()
            .success());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn independent_connected_uninitialized_binding_and_effect_mutations_reject() {
    let (input, mut connected) = fixture(77);
    connected.security_helper.bytes[2] ^= 4;
    assert!(prove_connected(&input, &connected).is_err());
    let (input, mut connected) = fixture(77);
    connected.fill_helper.bytes[20] = 0x06; // Store through wrong owned pointer.
    assert!(prove_connected(&input, &connected).is_err());
    let (input, mut connected) = fixture(77);
    connected.initializer.bytes[9..13].copy_from_slice(&(-20i32).to_le_bytes());
    assert!(prove_connected(&input, &connected).is_err());
    let (mut input, connected) = fixture(77);
    let at = input.frames[0]
        .prefix
        .bytes
        .windows(3)
        .position(|b| b == [0x89, 0x65, 0xe8])
        .unwrap();
    input.frames[0].prefix.bytes[at..at + 3].copy_from_slice(&[0x90, 0x90, 0x90]);
    assert!(prove_connected(&input, &connected).is_err());
}
