//! Independent byte vectors through the complete unwind slice proof and emitter.
//! These are synthetic native checks, not original Windows observations.
use super::*;

const BASE: u32 = 0x400000;
const TARGET: u32 = 0x7000;

fn cleanup(marker: u8, increment: u8) -> Vec<u8> {
    // cdecl arg -> ECX; trace=16*trace+marker; local+=increment; RET.
    vec![
        0x8b, 0x4c, 0x24, 4, 0x8b, 1, 1, 0xc0, 1, 0xc0, 1, 0xc0, 1, 0xc0, 0x83, 0xc0, marker, 0x89,
        1, 0x83, 0x41, 4, increment, 0xc3,
    ]
}
fn blocks() -> Vec<(u32, Vec<u8>)> {
    vec![
        (0x3000, cleanup(1, 7)),
        (0x3100, cleanup(2, 11)),
        (0x3200, cleanup(3, 13)),
    ]
}
fn table() -> Vec<u8> {
    [
        (1i32, BASE + 0x3000),
        (-1, BASE + 0x3100),
        (-1, BASE + 0x3200),
    ]
    .into_iter()
    .flat_map(|(parent, target)| parent.to_le_bytes().into_iter().chain(target.to_le_bytes()))
    .collect()
}
fn restore() -> Vec<u8> {
    // Context arg in ECX; load EAX/ESP/EBP; jump through saved EIP.
    vec![
        0x8b, 0x4c, 0x24, 4, 0x8b, 0x81, 0xb0, 0, 0, 0, 0x8b, 0xa1, 0xc4, 0, 0, 0, 0x8b, 0xa9,
        0xb4, 0, 0, 0, 0xff, 0xa1, 0xb8, 0, 0, 0,
    ]
}
fn compile(
    table: &[u8],
    blocks: &[(u32, Vec<u8>)],
    restore: &[u8],
    active: &[i32],
) -> Result<Proven, String> {
    prove(
        table,
        BASE,
        0x2000,
        blocks,
        restore,
        0x5000,
        TARGET,
        &[0x90],
        active,
        0,
    )
}

#[test]
fn original_cleanup_order_live_frame_state_and_restore_projection_execute_natively() {
    let source = compile(&table(), &blocks(), &restore(), &[-1, 2, 0])
        .unwrap()
        .emit();
    assert_eq!(
        source,
        compile(&table(), &blocks(), &restore(), &[-1, 2, 0])
            .unwrap()
            .emit()
    );
    let single = compile(&table(), &blocks(), &restore(), &[-1])
        .unwrap()
        .emit();
    let suffix = r#"
fn main() {
 let saved=[77,601,602,603,32768,33024,606,607,28672,514];
 let current=[10,11,12,13,28672,28928,16,17,4369,582];
 let a=unwind(&[300,200,100],saved,current,0).unwrap();
 assert_eq!(a.trace,0x123);
 assert_eq!(a.locals,vec![Some(300),Some(213),Some(118)]);
 assert_eq!(a.live,vec![true,false,false]);
 assert_eq!(a.restored,[Some(77),None,None,Some(13),Some(32768),Some(33024),Some(16),Some(17),Some(28672),None]);
 // Distinct input values, arithmetic wrap and selected/current register values
 // prevent a fixed expected result or accidentally shared snapshot from passing.
 let mut alternate=saved;alternate[0]=99;alternate[4]=0x9000;alternate[5]=0x9100;
 let b=unwind(&[400,u32::MAX,u32::MAX],alternate,current,u32::MAX).unwrap();
 assert_eq!(b.trace,0xfffff123);
 assert_eq!(b.locals,vec![Some(400),Some(12),Some(17)]);
 assert_eq!(b.restored[0],Some(99));assert_eq!(b.restored[4],Some(0x9000));assert_eq!(b.restored[5],Some(0x9100));
 assert_eq!(b.restored[3],Some(13));assert_eq!(b.restored[6],Some(16));assert_eq!(b.restored[7],Some(17));
 assert_eq!(b.restored[1],None);assert_eq!(b.restored[2],None);assert_eq!(b.restored[9],None);
 let mut wrong=saved;wrong[8]+=1;
 assert!(unwind(&[300,200,100],wrong,current,0).is_err());
 assert!(unwind(&[300,200],saved,current,0).is_err());
 // Selecting the only/innermost frame does not replace the current register
 // state with its distinct saved restore snapshot.
 let single=one::unwind(&[300],saved,current,0x89).unwrap();
 assert_eq!(single.trace,0x89);assert_eq!(single.locals,vec![Some(300)]);assert_eq!(single.live,vec![true]);
 assert_eq!(single.restored,[Some(77),None,None,Some(13),Some(32768),Some(33024),Some(16),Some(17),Some(28672),None]);
}
"#;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("w2l-unwind-native-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("program.rs");
    let executable = directory.join(if cfg!(windows) {
        "program.exe"
    } else {
        "program"
    });
    std::fs::write(&path, source + "\nmod one {\n" + &single + "\n}\n" + suffix).unwrap();
    let compiler = std::process::Command::new("rustc")
        .arg("--edition=2021")
        .arg(&path)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        compiler.status.success(),
        "{}",
        String::from_utf8_lossy(&compiler.stderr)
    );
    let result = std::process::Command::new(&executable).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn scope_cycles_aliases_unbound_targets_and_bad_ownership_reject_before_emission() {
    for (offset, value) in [(0, 0u32), (0, 3), (0, u32::MAX - 1), (4, BASE + 0x3333)] {
        let mut bad = table();
        bad[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        assert!(compile(&bad, &blocks(), &restore(), &[-1, 2, 0]).is_err());
    }
    assert!(compile(&table()[..23], &blocks(), &restore(), &[-1, 2, 0]).is_err());
    for active in [&[-1, 0, 0][..], &[-1, 2, 99], &[-1, 2, -2]] {
        assert!(compile(&table(), &blocks(), &restore(), active).is_err());
    }
    for table_rva in [0x3000, 0x5000, TARGET] {
        assert!(prove(
            &table(),
            BASE,
            table_rva,
            &blocks(),
            &restore(),
            0x5000,
            TARGET,
            &[0x90],
            &[-1, 2, 0],
            0
        )
        .is_err());
    }
    let mut duplicate = blocks();
    duplicate.push(duplicate[0].clone());
    assert!(compile(&table(), &duplicate, &restore(), &[-1, 2, 0]).is_err());
}

#[test]
fn complete_proof_rejects_faulting_unbound_or_pointer_cleanup_effects() {
    for bad in [
        vec![0xe8, 0, 0, 0, 0, 0xc3],                   // Unbound call.
        vec![0x0f, 0x0b, 0xc3],                         // Deliberate fault.
        vec![0x8b, 0x4c, 0x24, 4, 0x8b, 0x41, 8, 0xc3], // Outside both owned words.
        vec![0x8b, 0x4c, 0x24, 4, 0x8b, 0x41, 1, 0xc3], // Partial/misaligned word.
        vec![0x8b, 0x4c, 0x24, 4, 0x89, 9, 0xc3],       // Pointer escape to scalar cell.
        vec![0x8b, 1, 0xc3],                            // Uninitialized owner.
        vec![0x89, 0xc3, 0xc3],                         // Unpreserved nonvolatile EBX.
    ] {
        let mut body = blocks();
        body[1].1 = bad;
        assert!(compile(&table(), &body, &restore(), &[-1, 2, 0]).is_err());
    }
}

#[test]
fn restoration_field_binding_prefixes_and_target_boundaries_reject() {
    for index in [3, 6, 12, 18, 24] {
        let mut bad = restore();
        bad[index] ^= 1;
        assert!(compile(&table(), &blocks(), &bad, &[-1, 2, 0]).is_err());
    }
    let mut prefix = vec![0x64];
    prefix.extend(restore());
    assert!(compile(&table(), &blocks(), &prefix, &[-1, 2, 0]).is_err());
    let mut far = restore();
    far[23] = 0xa9; // FF /5 far indirect transfer.
    assert!(compile(&table(), &blocks(), &far, &[-1, 2, 0]).is_err());
    for target_bytes in [&[][..], &[0x0f]] {
        assert!(prove(
            &table(),
            BASE,
            0x2000,
            &blocks(),
            &restore(),
            0x5000,
            TARGET,
            target_bytes,
            &[-1, 2, 0],
            0
        )
        .is_err());
    }
    assert!(prove(
        &table(),
        u32::MAX - 1,
        0x2000,
        &blocks(),
        &restore(),
        0x5000,
        TARGET,
        &[0x90],
        &[-1, 2, 0],
        0
    )
    .is_err());
}
