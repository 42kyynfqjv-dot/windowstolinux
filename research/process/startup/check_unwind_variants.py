"""Independent original-instruction unwind cut checks, not Windows comparisons.

Literal expected traces/locals establish metadata-driven action ordering. These
are authored orchestration-cut inputs, not recovered MSVC exception metadata.
"""
from contextlib import nullcontext
from pathlib import Path
import argparse
import copy
import json
import struct
import subprocess
import tempfile


BASE = 0x400000
TABLE = 0x2000
RESTORE = 0x3000
TARGET = 0x4000
RESTORE_BYTES = bytes.fromhex("8b4c24048b81b00000008ba1c40000008ba9b4000000ffa1b8000000")
SAVED = [77, 11, 12, 13, 32768, 33024, 16, 17, TARGET, 514]
CURRENT = [10, 21, 22, 23, 36864, 37120, 26, 27, 0x5000, 514]
EXPECTED_RESTORED = "[Some(77),None,None,Some(23),Some(32768),Some(33024),Some(26),Some(27),Some(16384),None]"


def cleanup(digit, delta):
    # MOV ECX,[ESP+4]; MOV EAX,[ECX]; four ADD EAX,EAX;
    # ADD EAX,imm32; MOV [ECX],EAX; ADD DWORD [ECX+4],imm32; RET.
    return (bytes.fromhex("8b4c24048b0101c001c001c001c005") + struct.pack("<I", digit)
            + bytes.fromhex("8901814104") + struct.pack("<I", delta) + b"\xc3")


def baseline():
    return {
        "blocks": [(0x1000, cleanup(1, 7)), (0x1100, cleanup(2, 11)), (0x1200, cleanup(3, 13))],
        "rows": [(1, BASE + 0x1000), (-1, BASE + 0x1100), (-1, BASE + 0x1200)],
        "active": [-1, 2, 0], "locals": [300, 200, 100], "trace": 0,
        "expected_trace": 291, "expected_locals": [300, 213, 118],
        "expected_live": [True, False, False], "restore": RESTORE_BYTES,
        "target_bytes": b"\x90", "table_rva": TABLE, "restore_rva": RESTORE,
    }


def cases():
    items = [("nested_original_order", baseline())]
    changed = baseline(); changed["blocks"].reverse()
    items.append(("binding_list_reordered", changed))
    changed = baseline()
    changed["rows"] = [(1, BASE + 0x1200), (-1, BASE + 0x1100), (-1, BASE + 0x1000)]
    changed.update(expected_trace=801, expected_locals=[300, 207, 124])
    items.append(("metadata_target_permutation", changed))
    changed = baseline()
    changed.update(active=[-1, 0, 2], expected_trace=786, expected_locals=[300, 218, 113])
    items.append(("frame_active_scopes_permuted", changed))
    changed = baseline()
    changed.update(active=[-1, 0], locals=[300, 100], expected_trace=18,
                   expected_locals=[300, 118], expected_live=[True, False])
    items.append(("two_scopes_in_one_abandoned_frame", changed))
    changed = baseline()
    changed.update(active=[2, 0], locals=[300, 100], expected_trace=291,
                   expected_locals=[313, 118], expected_live=[True, False])
    items.append(("selected_frame_cleanup_preserves_its_lifetime", changed))
    changed = baseline()
    changed.update(active=[-1, -1], locals=[77, 88], trace=9, expected_trace=9,
                   expected_locals=[77, 88], expected_live=[True, False])
    items.append(("empty_cleanup_retirement", changed))
    changed = baseline()
    changed.update(blocks=[(0x1000, cleanup(3, 255)), (0x1100, cleanup(7, 1)), (0x1200, cleanup(9, 4294967295))],
                   locals=[300, 0, 4294967295], trace=4294967295,
                   expected_trace=4294964089, expected_locals=[300, 4294967295, 255])
    items.append(("independent_trace_and_local_wraparound", changed))
    return items


def negatives():
    items = []
    changed = baseline(); changed["rows"][1] = (0, BASE + 0x1100)
    items.append(("scope_cycle", changed))
    changed = baseline(); changed["rows"][2] = (2, BASE + 0x1200); changed["active"] = [-1, 0]
    items.append(("unreached_scope_cycle", changed))
    changed = baseline(); changed["rows"][0] = (-2, BASE + 0x1000)
    items.append(("invalid_parent", changed))
    changed = baseline(); changed["rows"][0] = (1, BASE + 0x1500)
    items.append(("unbound_callback", changed))
    changed = baseline(); changed["rows"][0] = (1, BASE - 1)
    items.append(("callback_below_image", changed))
    changed = baseline(); changed["active"] = [-1, 0, 0]
    items.append(("active_scope_alias", changed))
    changed = baseline(); changed["active"] = [-1, 2, 3]
    items.append(("active_scope_out_of_range", changed))
    changed = baseline(); changed["blocks"].append(changed["blocks"][0])
    items.append(("duplicate_callback_mapping", changed))
    changed = baseline(); changed["table_rva"] = 0x1000
    items.append(("table_code_overlap", changed))
    changed = baseline(); changed["restore_rva"] = TARGET
    items.append(("restore_target_overlap", changed))
    changed = baseline(); changed["blocks"][0] = (0x1000, bytes.fromhex("8b4c240483410801c3"))
    items.append(("cleanup_crosses_owned_cells", changed))
    changed = baseline(); changed["blocks"][0] = (0x1000, bytes.fromhex("8b4c24048909c3"))
    items.append(("cleanup_owner_escape", changed))
    changed = baseline(); changed["blocks"][0] = (0x1000, bytes.fromhex("8b4c24048901c3"))
    items.append(("cleanup_unknown_register_read", changed))
    changed = baseline(); changed["blocks"][0] = (0x1000, bytes.fromhex("bb01000000c3"))
    items.append(("cleanup_nonvolatile_clobber", changed))
    changed = baseline(); changed["blocks"][0] = (0x1000, bytes.fromhex("eb00c3"))
    items.append(("cleanup_unproved_branch", changed))
    changed = baseline(); changed["restore"] = RESTORE_BYTES.replace(bytes.fromhex("b0000000"), bytes.fromhex("ac000000"))
    items.append(("restore_wrong_saved_field", changed))
    changed = baseline(); changed["restore"] = RESTORE_BYTES[:-6]
    items.append(("restore_missing_transfer", changed))
    changed = baseline(); changed["restore"] = RESTORE_BYTES + b"\x90"
    items.append(("restore_trailing_effect", changed))
    changed = baseline(); changed["target_bytes"] = b"\x0f"
    items.append(("malformed_target_instruction", changed))
    return items


def check(compiler, root):
    root.mkdir(parents=True, exist_ok=True)

    def run(command, name, timeout):
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            (root / (name + ".stdout")).write_bytes(error.stdout or b"")
            (root / (name + ".stderr")).write_bytes(error.stderr or b"")
            raise
        (root / (name + ".stdout")).write_bytes(result.stdout)
        (root / (name + ".stderr")).write_bytes(result.stderr)
        return result

    def convert(name, case):
        directory = root / name; directory.mkdir(exist_ok=True)
        listing = []
        for index, (rva, code) in enumerate(case["blocks"]):
            filename = "cleanup" + str(index) + ".bin"
            (directory / filename).write_bytes(code)
            listing.append(str(rva) + " " + filename)
        (directory / "cleanup.list").write_text("\n".join(listing) + "\n")
        (directory / "scope.bin").write_bytes(b"".join(struct.pack("<iI", *row) for row in case["rows"]))
        (directory / "active.txt").write_text(" ".join(map(str, case["active"])) + "\n")
        (directory / "restore.bin").write_bytes(case["restore"])
        (directory / "target.bin").write_bytes(case["target_bytes"])
        source = directory / "generated.rs"; source.unlink(missing_ok=True)
        result = run([str(compiler), str(directory), str(BASE), str(case["table_rva"]),
                      str(case["restore_rva"]), str(TARGET), str(source)], name, 20)
        return result, source

    modules = []; assertions = []
    accepted = cases()
    for index, (name, case) in enumerate(accepted):
        result, source = convert(name, case)
        if result.returncode:
            raise AssertionError(name + ": " + result.stderr.decode(errors="replace"))
        generated = source.read_bytes()
        repeated, repeated_source = convert(name + ".repeat", copy.deepcopy(case))
        if repeated.returncode or repeated_source.read_bytes() != generated:
            raise AssertionError(name + ": nondeterministic source")
        modules.append("mod v" + str(index) + " {\n" + generated.decode() + "\n}")
        expected_locals = "[" + ",".join("Some(" + str(value) + ")" for value in case["expected_locals"]) + "]"
        expected_live = repr(case["expected_live"]).lower()
        call = "v" + str(index) + "::unwind"
        assertions.append("""
        {let saved=SAVED;let current=CURRENT;let local=LOCALS;
        let result=CALL(&local,saved,current,TRACE).unwrap();
        assert_eq!(result.trace,EXPECTED_TRACE,"NAME trace");
        assert_eq!(result.locals,EXPECTED_LOCALS,"NAME locals");
        assert_eq!(result.live,EXPECTED_LIVE,"NAME lifetime");
        assert_eq!(result.restored,EXPECTED_RESTORED,"NAME restored defined fields");
        let mut invalid=saved;invalid[8]+=1;
        assert!(CALL(&local,invalid,current,TRACE).is_err(),"NAME wrong target");
        assert!(CALL(&local[..local.len()-1],saved,current,TRACE).is_err(),"NAME wrong frame count");}
        """.replace("EXPECTED_RESTORED", EXPECTED_RESTORED)
            .replace("EXPECTED_LOCALS", expected_locals).replace("EXPECTED_LIVE", expected_live)
            .replace("EXPECTED_TRACE", str(case["expected_trace"]))
            .replace("SAVED", repr(SAVED)).replace("CURRENT", repr(CURRENT))
            .replace("LOCALS", repr(case["locals"])).replace("TRACE", str(case["trace"]))
            .replace("CALL", call).replace("NAME", name))
    rejected = []
    for name, case in negatives():
        result, source = convert(name, case)
        if result.returncode == 0 or source.exists():
            raise AssertionError(name + ": expected rejection without emitted source")
        rejected.append({"name": name, "diagnostic": result.stderr.decode(errors="replace").strip()})
    source = root / "all-native.rs"
    source.write_text("\n".join(modules) + "\nfn main(){\n" + "\n".join(assertions) + "\n}\n")
    native = root / "all-native"
    result = run(["rustc", "--edition=2021", str(source), "-o", str(native)], "rustc", 60)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors="replace"))
    result = run([str(native)], "native", 20)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors="replace"))
    report = {
        "kind": "independent native authored unwind-cut vectors; zero Windows or whole-PE comparisons",
        "compiled_variants": len(accepted), "native_outcome_vectors": len(accepted),
        "native_input_rejections": 2 * len(accepted), "deterministic_reconversions": len(accepted),
        "compiler_rejections": rejected,
    }
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compiler", type=Path)
    parser.add_argument("--output", type=Path, help="Retain reproduced inputs and failure logs")
    args = parser.parse_args()
    manager = nullcontext(args.output) if args.output else tempfile.TemporaryDirectory(prefix="w2l-unwind-vectors-")
    with manager as root:
        check(args.compiler.resolve(), Path(root).resolve())


if __name__ == "__main__":
    main()
