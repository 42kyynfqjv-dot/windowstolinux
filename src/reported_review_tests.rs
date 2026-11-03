//! Independent admission regressions for Main reporting. These are synthetic
//! instruction/component tests, not additional original-Windows observations.
use super::{frame_init, frame_memory, frame_proof};
use std::collections::BTreeSet;

fn frame() -> frame_proof::ProvenFrame {
    // An original-form EH4 prefix with 32 bytes of ordinary local storage.
    let code = [
        0x55, 0x8b, 0xec, 0x6a, 0xfe, 0x68, 0, 0x50, 0, 0, 0x68, 0, 0x60, 0, 0, 0x64, 0xa1, 0, 0,
        0, 0, 0x50, 0x83, 0xec, 0x20, 0x53, 0x56, 0x57, 0xa1, 0, 0x70, 0, 0, 0x31, 0x45, 0xf8,
        0x33, 0xc5, 0x50, 0x8d, 0x45, 0xf0, 0x64, 0xa3, 0, 0, 0, 0,
    ];
    frame_proof::prove_frame(
        &code,
        0x1000,
        0x7000,
        &BTreeSet::from([0x5000]),
        &BTreeSet::from([0x6000]),
    )
    .unwrap()
}

fn fill_helper() -> Vec<u8> {
    // cdecl byte fill with a literal counter loop and preserved EDI.
    vec![
        0x8b, 0x4c, 0x24, 12, 0x0f, 0xb6, 0x44, 0x24, 8, 0x8b, 0xd7, 0x8b, 0x7c, 0x24, 4, 0x85,
        0xc9, 0x74, 8, 0x88, 7, 0x47, 0x83, 0xe9, 1, 0x75, 0xf8, 0x8b, 0x44, 0x24, 4, 0x8b, 0xfa,
        0xc3,
    ]
}

fn initializer(origin: u32, offset: i8, count: u8) -> Vec<u8> {
    // Fill followed by an independent typed module acquisition and TryLevel.
    let mut code = vec![
        0x6a,
        count,
        0x6a,
        0x5a,
        0x8d,
        0x45,
        offset as u8,
        0x50,
        0xe8,
    ];
    code.extend(0x4000u32.wrapping_sub(origin + 13).to_le_bytes());
    code.extend([
        0x83, 0xc4, 12, 0x6a, 0, 0xff, 0x15, 0, 0x90, 0, 0, 0x89, 0x45, 0xd8, 0xc7, 0x45, 0xfc, 0,
        0, 0, 0,
    ]);
    code
}

#[test]
fn partial_fill_endpoints_do_not_grant_full_word_reporting_authority() {
    let frame = frame();
    let helper = fill_helper();
    let helper = frame_init::FillHelper {
        code: &helper,
        origin: 0x4000,
        feature_words: [0x8000, 0x8004],
    };
    // Literal byte-coverage expectations. The module word at -40 is initialized
    // separately; it is never a scalar simply because its bytes are known.
    let cases: [(i8, u8, &[i32]); 4] = [
        (-31, 3, &[-40]),
        (-31, 4, &[-40]),
        (-31, 7, &[-40, -28]),
        (-32, 8, &[-40, -32, -28]),
    ];
    let mut checks = String::new();
    for (offset, count, expected) in cases {
        let code = initializer(frame.end(), offset, count);
        let proof =
            frame_init::prove_initializer(&frame, &code, frame.end(), &helper, 0x9000).unwrap();
        assert_eq!(
            proof.initialized_words(),
            &expected.iter().copied().collect::<BTreeSet<_>>(),
            "full-word authority for fill({offset},{count})"
        );
        checks.push_str(&format!(
            "{{let mut image=prefix(0x10000,0x12345678,[None;8],\"root\").unwrap();let memory=&mut FrameMemory::new(&mut image,7,&{ordinary:?}).unwrap();let module=GuestModule{{owner:7,base:0x400000}};let result:Result<(),&'static str>=(||{{{body}}})();result.unwrap();assert_eq!(memory.read_u32(-32).ok(),{first:?});assert_eq!(memory.read_u32(-28).ok(),{second:?});assert!(memory.read_u32(-40).is_err());assert_eq!(memory.read_module(-40).unwrap(),0x400000);}}\n",
            ordinary = frame.ordinary_words().iter().copied().collect::<Vec<_>>(),
            body = proof.body(),
            first = expected.contains(&-32).then_some(0x5a5a_5a5au32),
            second = expected.contains(&-28).then_some(0x5a5a_5a5au32),
        ));
    }
    let source = format!(
        "{}\n{}\nfn prefix<P:Clone>(entry_sp:u32,cookie:u32,saved:[Option<u32>;8],predecessor:P)->Result<FrameImage<P>,&'static str>{{{}}}\nfn main(){{{checks}}}",
        frame_proof::EMITTED_TYPES,
        frame_memory::EMITTED_TYPES,
        frame.initializer_body(),
    );
    let dir = std::env::temp_dir().join(format!("w2l-report-init-review-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("run.rs");
    let binary = dir.join(if cfg!(windows) { "run.exe" } else { "run" });
    std::fs::write(&path, source).unwrap();
    let output = std::process::Command::new("rustc")
        .args(["--edition=2021", "-Awarnings"])
        .arg(&path)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = std::process::Command::new(&binary).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(dir).unwrap();
}
