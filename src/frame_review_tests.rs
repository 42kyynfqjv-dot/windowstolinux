//! Independent entry-address adversarial tests for fragment composition.
use super::*;

#[test]
fn numeric_stack_cannot_alias_bound_image_regions() {
    let input = super::tests::fixture();
    let source = prove_fragments(&input).unwrap().emit();
    let mut starts = Vec::new();
    for frame in &input.frames {
        starts.extend([frame.prefix.va, frame.table.va]);
        if let Some(activation) = &frame.activation {
            starts.push(activation.va);
        }
    }
    starts.extend(
        input
            .calls
            .iter()
            .chain(&input.filters)
            .chain(&input.landings)
            .chain(&input.funclets)
            .chain(&input.cleanups)
            .chain([
                &input.dispatcher,
                &input.dispatch_table,
                &input.normalizer,
                &input.installer,
                &input.restore,
                &input.target,
            ])
            .map(|region| region.va),
    );
    starts.extend(input.globals.iter().copied());
    starts.extend([
        input.cookie_va,
        input.trace_va,
        input.feature_va,
        input.raise_exception_iat,
    ]);
    // Place the four-byte return word across each first region byte. This also
    // detects accidental exclusion of the return slot from the stack interval.
    let aliases: Vec<_> = starts.into_iter().map(|address| address & !3).collect();
    let harness = format!(
        r#"
fn main() {{
 let saved=[77,0,0,0,0x9000,0x9100,0,0,0x3400,0x202];
 let current=[0,0,0,33,0x8000,0x8100,66,77,0x1111,0x202];
 for entry_sp in {aliases:?} {{
  assert!(run_fragments(entry_sp,0x12345678,saved,current,0,17).is_err(),
          "stack return word overlaps bound image region at {{entry_sp:#x}}");
 }}
 // EBP=0x602c, so the ordinary scalar EBP-28 aliases cookie_va=0x6010.
 // Previously this succeeded while preserving a separate, impossible cookie.
 assert!(run_fragments(0x6030,0x12345678,saved,current,0,17).is_err());
 // Half-open ranges: the return word ending exactly at first code byte is
 // disjoint. A separate ordinary high stack also remains admitted.
 for entry_sp in [0x0ffcu32,0xa000] {{
  let result=run_fragments(entry_sp,0x12345678,saved,current,0,17).unwrap();
  assert_eq!(result.trace,17);
 }}
}}
"#
    );
    let dir = std::env::temp_dir().join(format!("w2l-frame-address-review-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("run.rs");
    let binary = dir.join(if cfg!(windows) { "run.exe" } else { "run" });
    std::fs::write(&file, source + &harness).unwrap();
    let output = std::process::Command::new("rustc")
        .arg("--edition=2021")
        .arg(&file)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(std::process::Command::new(&binary)
        .status()
        .unwrap()
        .success());
    std::fs::remove_dir_all(dir).unwrap();
}
