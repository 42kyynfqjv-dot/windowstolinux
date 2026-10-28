//! Independent one-frame instruction composition: no Windows fixture dependency.
use super::*;

const EVENT: u32 = 0xe0421122;
const COOKIE: u32 = 0x6010;
const TRACE: u32 = 0x6000;
const CUSTOM: u32 = 0x5000;
fn region(va: u32, bytes: Vec<u8>) -> Region {
    Region { va, bytes }
}

pub(super) fn fixture() -> Input {
    // Owned prolog, two initialized scalar words and four original event args.
    let mut prefix = vec![0x55, 0x8b, 0xec, 0x6a, 0xfe, 0x68];
    prefix.extend(0x4000u32.to_le_bytes());
    prefix.push(0x68);
    prefix.extend(0x7000u32.to_le_bytes());
    prefix.extend([
        0x64, 0xa1, 0, 0, 0, 0, 0x50, 0x83, 0xec, 0x20, 0x53, 0x56, 0x57, 0xa1,
    ]);
    prefix.extend(COOKIE.to_le_bytes());
    prefix.extend([
        0x31, 0x45, 0xf8, 0x33, 0xc5, 0x50, 0x8d, 0x45, 0xf0, 0x64, 0xa3, 0, 0, 0, 0,
    ]);
    prefix.extend([
        0xc7, 0x45, 0xe8, 123, 0, 0, 0, 0xc7, 0x45, 0xe4, 2, 0, 0, 0, 0xc7, 0x45, 0xfc, 0, 0, 0, 0,
    ]);
    prefix.extend([0x6a, 0, 0x6a, 0, 0x6a, 0, 0x68]);
    prefix.extend(EVENT.to_le_bytes());
    let mut table = Vec::new();
    for word in [-2i32, 0, -64, 0, -2, 0x2000, 0x2200] {
        table.extend(word.to_le_bytes());
    }
    // Read typed exception code; write two previously uninitialized frame words.
    let mut filter = vec![
        0x8b, 0x55, 0xec, 0x8b, 2, 0x8b, 8, 0x89, 0x4d, 0xd8, 0x8b, 0x55, 0xd8, 0x89, 0x55, 0xd4,
        0x33, 0xc0, 0x81, 0x7d, 0xd4,
    ];
    filter.extend(EVENT.to_le_bytes());
    filter.extend([0x0f, 0x94, 0xc0, 0xc3]);
    // Independently assembled ESI/EDI dispatcher with original scalar snapshots.
    let mut dispatch = vec![
        0x83, 0xec, 8, 0x56, 0x57, 0x8b, 0x74, 0x24, 20, 0x8b, 0x7c, 0x24, 24, 0x8b, 6, 0x83, 0xf8,
        2, 0x77, 0,
    ];
    dispatch.extend([0x8b, 0x0d]);
    dispatch.extend(TRACE.to_le_bytes());
    dispatch.extend([
        0x89, 0x4c, 0x24, 8, 0x8b, 0x0f, 0x89, 0x4c, 0x24, 12, 0x8d, 0x4c, 0x24, 8, 0x51, 0x8b, 4,
        0xc5,
    ]);
    dispatch.extend((CUSTOM + 4).to_le_bytes());
    dispatch.extend([0xff, 0xd0, 0x83, 0xc4, 4, 0x8b, 0x4c, 0x24, 8, 0x89, 0x0d]);
    dispatch.extend(TRACE.to_le_bytes());
    dispatch.extend([0x8b, 0x4c, 0x24, 12, 0x89, 0x0f, 0x8b, 6, 0x8b, 4, 0xc5]);
    dispatch.extend(CUSTOM.to_le_bytes());
    dispatch.extend([0x89, 6, 0x5f, 0x5e, 0x83, 0xc4, 8, 0xc3]);
    dispatch[19] = (dispatch.len() - 20) as u8;
    dispatch.push(0xcc);
    let mut custom = Vec::new();
    for _ in 0..3 {
        custom.extend((-1i32).to_le_bytes());
        custom.extend(0x2600u32.to_le_bytes());
    }
    let call_va = 0x1000 + prefix.len() as u32;
    let mut call = vec![0xff, 0x15];
    call.extend(0x6020u32.to_le_bytes());
    Input {
        cookie_va: COOKIE,
        handler_va: 0x7000,
        calls: vec![region(call_va, call)],
        raise_exception_iat: 0x6020,
        frames: vec![Frame {
            prefix: region(0x1000, prefix),
            table: region(0x4000, table),
            activation: None,
        }],
        filters: vec![region(0x2000, filter)],
        landings: vec![region(0x2200, vec![0x90])],
        funclets: vec![],
        cleanups: vec![region(
            0x2600,
            vec![0x8b, 0x4c, 0x24, 4, 0x83, 0x41, 4, 1, 0xc3],
        )],
        dispatcher: region(0x2400, dispatch),
        dispatch_table: region(CUSTOM, custom),
        trace_va: TRACE,
        globals: vec![],
        normalizer: region(0x2800, vec![0x55, 0x89, 0xe5, 0x8b, 0x45, 8, 0xc9, 0xc3]),
        feature_va: 0x6014,
        installer: region(
            0x3000,
            vec![
                0x89, 0x45, 0xe4, 0x8b, 0x45, 0x10, 0x89, 0x45, 0xe8, 0x8d, 0x45, 0xe4, 0x89, 0x43,
                0xfc,
            ],
        ),
        restore: region(
            0x3200,
            vec![
                0x8b, 0x4c, 0x24, 4, 0x8b, 0x81, 176, 0, 0, 0, 0x8b, 0xa1, 196, 0, 0, 0, 0x8b,
                0xa9, 180, 0, 0, 0, 0xff, 0xa1, 184, 0, 0, 0,
            ],
        ),
        target: region(0x3400, vec![0x90]),
        event_code: EVENT,
    }
}

#[test]
fn filter_writes_cannot_alias_live_initialized_frame_state() {
    let good = fixture();
    assert!(prove_fragments(&good).is_ok());
    let mut bad = fixture();
    // Store/load through original -28 scalar instead of unknown -40 scratch.
    bad.filters[0].bytes[9] = 0xe4;
    bad.filters[0].bytes[12] = 0xe4;
    assert!(
        prove_fragments(&bad).is_err(),
        "filter silently changed initialized state used by proof"
    );
}

#[test]
fn activation_cannot_silently_change_scalar_cursor_assumptions() {
    let mut bad = fixture();
    bad.frames[0].activation = Some(region(0x1800, vec![0xc7, 0x45, 0xe4, 7, 0, 0, 0]));
    assert!(
        prove_fragments(&bad).is_err(),
        "activation scalar writes bypassed state refinement"
    );
}

#[test]
fn landing_and_event_provenance_are_not_self_authorized_by_metadata() {
    let mut bad = fixture();
    bad.landings.clear();
    assert!(prove_fragments(&bad).is_err());
    let mut bad = fixture();
    bad.event_code ^= 1;
    assert!(prove_fragments(&bad).is_err());
    let mut bad = fixture();
    bad.calls[0].va += 1;
    assert!(prove_fragments(&bad).is_err());
    let mut bad = fixture();
    bad.raise_exception_iat += 4;
    assert!(prove_fragments(&bad).is_err());
}

#[test]
fn emitted_filter_scratch_and_explicit_initial_trace_are_observable() {
    let source = prove_fragments(&fixture()).unwrap().emit();
    let harness = format!(
        r#"
fn main() {{
 let saved=[77,0,0,0,0x9000,0x9100,0,0,0x3400,0x202];
 let current=[0,0,0,33,0x8000,0x8100,66,77,0x1111,0x202];
 let o=run_fragments(0xa000,0x12345678,saved,current,0,17).unwrap();
 assert_eq!(o.trace,17);assert_eq!(o.selected_frame,0);assert_eq!(o.selected_target,0x2200);
 assert_eq!(o.live,vec![true]);
 for (offset,value) in [(-40,{EVENT}u32),(-44,{EVENT}u32),(-24,123),(-28,2)] {{
  let i=o.offsets[0].iter().position(|&at|at==offset).unwrap();
  assert_eq!(o.frame_words[0][i],Some(value),"lost or changed original frame effect at {{offset}}");
 }}
 assert_eq!(o.restored[0],Some(77));assert_eq!(o.restored[8],Some(0x3400));
}}
"#
    );
    let dir = std::env::temp_dir().join(format!("w2l-frame-adapter-review-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("run.rs");
    let bin = dir.join(if cfg!(windows) { "run.exe" } else { "run" });
    std::fs::write(&file, source + &harness).unwrap();
    let result = std::process::Command::new("rustc")
        .arg("--edition=2021")
        .arg(&file)
        .arg("-o")
        .arg(&bin)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(std::process::Command::new(&bin).status().unwrap().success());
    std::fs::remove_dir_all(dir).unwrap();
}
