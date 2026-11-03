//! Independent composition regression: search side effects and unwind effects
//! share the owned frame, while selection and the custom cleanup cursor differ.
use super::*;

const EVENT: u32 = 0xe0421122;

fn funclet(va: u32) -> Region {
    // cdecl Dispatch(&frame[-28], &frame[-24]), followed by both original
    // global observations. The second cleanup must see the first one's writes.
    let mut bytes = vec![0x8d, 0x45, 0xe8, 0x50, 0x8d, 0x45, 0xe4, 0x50, 0xe8];
    bytes.extend(0x2400u32.wrapping_sub(va + 13).to_le_bytes());
    bytes.extend([0x83, 0xc4, 8, 0x8b, 0x45, 0xe8, 0xa3]);
    bytes.extend(0x6030u32.to_le_bytes());
    bytes.extend([0x8b, 0x45, 0xe4, 0xa3]);
    bytes.extend(0x6034u32.to_le_bytes());
    bytes.push(0xc3);
    Region { va, bytes }
}

fn composition() -> Input {
    let mut input = super::tests::fixture();
    let at = input.frames[0]
        .prefix
        .bytes
        .windows(3)
        .position(|bytes| bytes == [0xc7, 0x45, 0xfc])
        .unwrap();
    input.frames[0].prefix.bytes[at + 3] = 3;
    input.frames[0].table.bytes.truncate(16);
    for (parent, filter, target) in [
        (-2i32, 0x2000u32, 0x2200u32),
        (0, 0x2100, 0x2200),
        (1, 0, 0x2300),
        (2, 0, 0x2380),
    ] {
        input.frames[0].table.bytes.extend(parent.to_le_bytes());
        input.frames[0].table.bytes.extend(filter.to_le_bytes());
        input.frames[0].table.bytes.extend(target.to_le_bytes());
    }
    // Continue search after storing the event in -36 and zero in -40. The
    // eventual selecting filter overwrites -40/-44, but must retain -36.
    input.filters.push(Region {
        va: 0x2100,
        bytes: vec![
            0x8b, 0x55, 0xec, 0x8b, 2, 0x8b, 8, 0x89, 0x4d, 0xdc, 0x33, 0xc0, 0x89, 0x45, 0xd8,
            0xc3,
        ],
    });
    input.funclets = vec![funclet(0x2300), funclet(0x2380)];
    input.dispatch_table.bytes[16..20].copy_from_slice(&1i32.to_le_bytes());
    input.globals = vec![0x6030, 0x6034];
    // Independently authored cleanup: trace += 7; local += 1, modulo 2^32.
    input.cleanups[0].bytes = vec![0x8b, 0x4c, 0x24, 4, 0x83, 0x01, 7, 0x83, 0x41, 4, 1, 0xc3];
    input
}

#[test]
fn sequential_filters_and_cleanup_cursors_share_live_state() {
    let input = composition();
    let source = prove_fragments(&input).unwrap().emit();
    assert_eq!(source, prove_fragments(&input).unwrap().emit());
    let harness = format!(
        r#"
fn main() {{
 let saved=[77,0,0,0,0x9000,0x9100,0,0,0x3400,0x202];
 let current=[0,0,0,33,0x8000,0x8100,66,77,0x1111,0x202];
 for (initial,expected) in [(0,14),(17,31),(u32::MAX,13)] {{
  let o=run_fragments(0xa000,0x12345678,saved,current,0,initial).unwrap();
  assert_eq!(o.trace,expected);
  assert_eq!(o.selected_frame,0);assert_eq!(o.selected_target,0x2200);
  assert_eq!(o.live,vec![true]);assert_eq!(o.cursors,vec![Some(-1)]);
  assert_eq!(o.globals,vec![Some(125),Some(u32::MAX)]);
  for (offset,value) in [(-24,125),(-28,u32::MAX),(-36,{EVENT}u32),(-40,{EVENT}u32),(-44,{EVENT}u32)] {{
   let index=o.offsets[0].iter().position(|&at|at==offset).unwrap();
   assert_eq!(o.frame_words[0][index],Some(value),"lost effect at {{offset}}");
  }}
 }}
 // At this address the cursor/local guest words alias the two globals.
 // Real stores would corrupt the next cursor; separate Rust vectors cannot
 // confer disjoint guest ownership. The entry boundary must reject it.
 assert!(run_fragments(0x6050,0x12345678,saved,current,0,0).is_err());
}}
"#
    );
    let directory = std::env::temp_dir().join(format!(
        "w2l-sequential-filter-review-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let file = directory.join("run.rs");
    let binary = directory.join(if cfg!(windows) { "run.exe" } else { "run" });
    std::fs::write(&file, source + &harness).unwrap();
    let result = std::process::Command::new("rustc")
        .arg("--edition=2021")
        .arg(&file)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(std::process::Command::new(&binary)
        .status()
        .unwrap()
        .success());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn filter_and_cursor_aliases_or_unproved_scratch_reads_reject() {
    let mut initialized_alias = composition();
    initialized_alias.filters[1].bytes[9] = 0xe4;
    assert!(prove_fragments(&initialized_alias).is_err());
    let mut prior_filter_only = composition();
    prior_filter_only.filters[0].bytes = vec![0x8b, 0x45, 0xdc, 0xc3];
    // Cross-filter initialization is not currently modeled by the proof. It
    // must reject conservatively instead of guessing a scalar or its result.
    assert!(prove_fragments(&prior_filter_only).is_err());
    let mut role_alias = composition();
    role_alias.funclets[1].bytes[6] = 0xe8;
    assert!(prove_fragments(&role_alias).is_err());
}
