//! Independent component-layout regressions. These are admission negatives,
//! not original Windows runs or whole-executable translation evidence.
use super::crt_stream_bundle::validate_layout;

fn original_regions() -> Vec<(u32, usize)> {
    vec![(0x40dc26, 219), (0x4146e0, 43), (0x40154c, 14)]
}
fn original_cells() -> Vec<u32> {
    vec![0x41c000, 0x41cf08, 0x415080, 0x415044]
}

#[test]
fn relocated_original_writer_cannot_overlap_its_owned_scratch_or_other_live_regions() {
    let mut regions = original_regions();
    let cells = original_cells();
    assert!(validate_layout(&regions, &cells, 16384).is_ok());
    // Independent prior false-admission reproduction: original writer moved to
    // 0x1ec00, with only direct CALL displacements repaired, emitted and wrote
    // 5,000 'A' bytes from scratch [0x1dbf8,0x1eff8). That range overwrites its
    // own original instruction bytes although the old Rust graph kept running.
    regions[0].0 = 0x1ec00;
    assert!(validate_layout(&regions, &cells, 16384).is_err());
    // Code/readonly words cannot acquire numeric aliases of any live object.
    for (start, size) in [
        (0x2000, 56u32),
        (0x10000, 65536),
        (0x30000, 16384),
        (0x40000, 40),
        (0x50000, 56),
    ] {
        for region in [(start, 1), (start - 1, 2), (start + size - 1, 2)] {
            assert!(
                validate_layout(&[region], &[], 16384).is_err(),
                "{region:?}"
            );
        }
        for cell in [start, start + size - 4] {
            assert!(validate_layout(&[], &[cell], 16384).is_err(), "{cell:#x}");
        }
    }
}

#[test]
fn code_table_and_iat_cells_have_complete_disjoint_nonwrapping_ranges() {
    for (regions, cells) in [
        (vec![(0x60000, 12), (0x60008, 8)], vec![]),
        (vec![(0x60000, 12), (0x60000, 12)], vec![]),
        (vec![(0x60002, 8)], vec![0x60000]),
        (vec![(0x60000, 8)], vec![0x60004]),
        (vec![], vec![0x60000, 0x60000]),
        (vec![], vec![0x60001]),
        (vec![(u32::MAX - 3, 8)], vec![]),
        (vec![], vec![u32::MAX - 3]),
        (vec![(0x60000, usize::MAX)], vec![]),
        (vec![(0, 4)], vec![]),
        (vec![(0x60000, 0)], vec![]),
    ] {
        assert!(
            validate_layout(&regions, &cells, 16384).is_err(),
            "{regions:?}/{cells:?}"
        );
    }
    assert!(validate_layout(&original_regions(), &original_cells(), 0).is_err());
    assert!(validate_layout(&original_regions(), &original_cells(), 16385).is_err());
}

#[test]
fn exact_adjacent_layout_boundaries_remain_admissible() {
    // A half-open range may touch, but never overlap, the protected extent.
    for (start, size) in [
        (0x2000, 56u32),
        (0x10000, 65536),
        (0x30000, 16384),
        (0x40000, 40),
        (0x50000, 56),
    ] {
        assert!(validate_layout(&[(start - 4, 4), (start + size, 4)], &[], 16384).is_ok());
        assert!(validate_layout(&[], &[start - 4, start + size], 16384).is_ok());
    }
    assert!(validate_layout(&[(0x60000, 8), (0x60008, 8)], &[0x5fffc, 0x60010], 1).is_ok());
    assert!(validate_layout(&[(0x30001, 3)], &[], 1).is_ok());
    assert!(validate_layout(&[(0x30001, 3)], &[], 4).is_err());
}
