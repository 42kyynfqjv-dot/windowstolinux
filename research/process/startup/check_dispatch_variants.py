"""Independent native dispatcher-cut vectors; no new Windows comparisons.

The baseline byte sequence is pinned to an authored retained PE. Synthetic
address/code/metadata variants below exercise semantics and are never described
as unchanged original Windows artifacts. Outcomes are literal independent values.
"""
from contextlib import nullcontext
from pathlib import Path
import argparse
import copy
import hashlib
import json
import struct
import subprocess
import tempfile


PE_SHA256 = "55a2435e8800b54f81c20b55373b56206c24bdeeeadc9580bb39b80bf5e04ce5"
DISPATCH = bytes.fromhex(
    "83ec08538b5c2410578b3b83ff027744a148c94100568b74241c8944240c8b0689442410"
    "8d44240c508b04fd84514100ffd08b44241083c404a348c941008b44241089068b04fd"
    "805141005e5f89035b83c408c36a5bff1504504100"
)
RESTORE_BYTES = bytes.fromhex("8b4c24048b81b00000008ba1c40000008ba9b4000000ffa1b8000000")
CLEANUPS = [bytes.fromhex(value) for value in [
    "8b4c24048b0103c003c003c003c083c001890183410407c3",
    "8b4c24048b0103c003c003c003c083c00289018341040bc3",
    "8b4c24048b0103c003c003c003c083c00389018341040dc3",
]]


def baseline():
    return dict(base=0x400000, table=0x15180, trace_rva=0x1c948,
                dispatch_rva=0x1060, restore_rva=0x3000, target=0x4000,
                dispatch=DISPATCH, blocks=list(zip([0x1000, 0x1020, 0x1040], CLEANUPS)),
                parents=[1, -1, -1], callbacks=[0x1000, 0x1020, 0x1040], active=[-1, 2, 0],
                locals=[300, 200, 100], trace=0,
                expected_trace=291, expected_locals=[300, 213, 118])


def rebind(case):
    code = bytearray(case["dispatch"])
    for offset in [17, 58]:
        struct.pack_into("<I", code, offset, case["base"] + case["trace_rva"])
    struct.pack_into("<I", code, 44, case["base"] + case["table"] + 4)
    struct.pack_into("<I", code, 71, case["base"] + case["table"])
    case["dispatch"] = bytes(code)


def accepted_cases():
    cases = [("pinned_dispatch_bytes", baseline())]
    case = baseline(); case["blocks"].reverse()
    cases.append(("callback_binding_order_independent", case))
    case = baseline()
    case.update(base=0x600000, table=0x22000, trace_rva=0x25000, dispatch_rva=0x1800)
    rebind(case)
    cases.append(("rebound_image_table_trace_and_code_addresses", case))
    case = baseline()
    case.update(callbacks=[0x1000, 0x1000, 0x1040], expected_trace=275,
                expected_locals=[300, 213, 114])
    cases.append(("shared_callback_two_distinct_scopes", case))
    case = baseline()
    case.update(active=[-1, 0, 2], expected_trace=786, expected_locals=[300, 218, 113])
    cases.append(("different_active_frame_order", case))
    case = baseline()
    case.update(locals=[300, 4294967295, 4294967289], trace=4294967295,
                expected_trace=4294963491, expected_locals=[300, 12, 11])
    cases.append(("dynamic_trace_and_local_wraparound", case))
    case = baseline()
    blocks = copy.deepcopy(case["blocks"])
    for index, delta in enumerate([255, 128, 0]):
        rva, raw = blocks[index]; code = bytearray(raw); code[22] = delta
        blocks[index] = (rva, bytes(code))
    case.update(blocks=blocks, locals=[300, 200, 128], expected_locals=[300, 200, 4294967295])
    cases.append(("signed_cleanup_immediates", case))
    case = baseline(); code = bytearray(case["dispatch"]); code[85] = 90; case["dispatch"] = bytes(code)
    cases.append(("unreachable_exit_argument_is_not_a_template_key", case))
    return cases


def negative_cases():
    cases = []
    # Every offset is an independently identified instruction field in DISPATCH.
    mutations = [
        ("unsigned_guard_inverted", 14, 0x72),
        ("guard_rejects_live_scope_two", 14, 0x73),
        ("guard_bound_too_small", 13, 1),
        ("wrong_cursor_argument_slot", 7, 0x14),
        ("wrong_local_argument_slot", 25, 0x20),
        ("temporary_buffer_crosses_stack_extent", 39, 0x10),
        ("indirect_callback_unknown_register", 49, 0xd1),
        ("postcall_read_uninitialized_stack", 53, 0x40),
        ("cursor_write_targets_local_instead", 78, 0x06),
        ("cleanup_caller_stack_unbalanced", 56, 8),
    ]
    for name, offset, value in mutations:
        case = baseline(); code = bytearray(case["dispatch"]); code[offset] = value; case["dispatch"] = bytes(code)
        cases.append((name, case))
    case = baseline(); code = bytearray(case["dispatch"])
    struct.pack_into("<I", code, 44, case["base"] + case["table"])
    case["dispatch"] = bytes(code); cases.append(("call_uses_parent_field", case))
    case = baseline(); code = bytearray(case["dispatch"])
    struct.pack_into("<I", code, 71, case["base"] + case["table"] + 4)
    case["dispatch"] = bytes(code); cases.append(("cursor_uses_callback_field", case))
    case = baseline(); case["trace_rva"] = case["table"]; rebind(case)
    cases.append(("trace_aliases_scope_metadata", case))
    case = baseline(); case["trace_rva"] = 0x1000; rebind(case)
    cases.append(("trace_aliases_cleanup_code", case))
    case = baseline(); case["dispatch_rva"] = 0x1000
    cases.append(("dispatch_aliases_cleanup_code", case))
    case = baseline(); case["active"] = [-1, 2, 3]
    cases.append(("runtime_cursor_outside_table_contract", case))
    return cases


def check(compiler, root, original=None):
    root.mkdir(parents=True, exist_ok=True)
    if original:
        from inventory import mapped_bytes
        pe = (original / "unwind.exe").read_bytes()
        if hashlib.sha256(pe).hexdigest() != PE_SHA256:
            raise AssertionError("retained original PE hash changed")
        if mapped_bytes(pe, 0x401060, 92) != DISPATCH:
            raise AssertionError("baseline dispatcher differs from retained original bytes")
        for rva, raw in baseline()["blocks"]:
            if mapped_bytes(pe, 0x400000 + rva, len(raw)) != raw:
                raise AssertionError("baseline cleanup differs from retained original bytes")

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
            (directory / filename).write_bytes(code); listing.append(str(rva) + " " + filename)
        (directory / "cleanup.list").write_text("\n".join(listing) + "\n")
        (directory / "scope.bin").write_bytes(b"".join(struct.pack("<iI", parent, case["base"] + rva)
                                                       for parent, rva in zip(case["parents"], case["callbacks"])))
        (directory / "active.txt").write_text(" ".join(map(str, case["active"])) + "\n")
        (directory / "restore.bin").write_bytes(RESTORE_BYTES)
        (directory / "target.bin").write_bytes(b"\x90")
        (directory / "dispatch.bin").write_bytes(case["dispatch"])
        (directory / "dispatch.bind").write_text(str(case["dispatch_rva"]) + " " + str(case["trace_rva"]) + "\n")
        source = directory / "generated.rs"; source.unlink(missing_ok=True)
        result = run([str(compiler), str(directory), str(case["base"]), str(case["table"]),
                      str(case["restore_rva"]), str(case["target"]), str(source)], name, 20)
        return result, source

    modules = []; assertions = []; accepted = accepted_cases()
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
        assertions.append("""{
        let saved=[77,11,12,13,32768,33024,16,17,16384,514];
        let current=[10,21,22,23,36864,37120,26,27,20480,514];
        let result=CALL(&LOCALS,saved,current,TRACE).unwrap();
        assert_eq!(result.trace,EXPECTED_TRACE,"NAME trace");
        assert_eq!(result.locals,EXPECTED_LOCALS,"NAME locals");
        assert_eq!(result.live,[true,false,false],"NAME lifetime");
        assert_eq!(result.restored,[Some(77),None,None,Some(23),Some(32768),Some(33024),Some(26),Some(27),Some(16384),None],"NAME restore");
        }""".replace("EXPECTED_LOCALS", expected_locals).replace("EXPECTED_TRACE", str(case["expected_trace"]))
            .replace("LOCALS", repr(case["locals"])).replace("TRACE", str(case["trace"]))
            .replace("CALL", "v" + str(index) + "::unwind").replace("NAME", name))
    rejected = []
    for name, case in negative_cases():
        result, source = convert(name, case)
        if result.returncode == 0 or source.exists():
            raise AssertionError(name + ": expected rejection without newly emitted source")
        rejected.append({"name": name, "diagnostic": result.stderr.decode(errors="replace").strip()})
    native_source = root / "all-native.rs"; native = root / "all-native"
    native_source.write_text("\n".join(modules) + "\nfn main(){\n" + "\n".join(assertions) + "\n}\n")
    result = run(["rustc", "--edition=2021", str(native_source), "-o", str(native)], "rustc", 60)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors="replace"))
    result = run([str(native)], "native", 20)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors="replace"))
    report = dict(kind="independent dispatcher-cut native vectors; zero Windows or whole-PE comparisons",
                  retained_pe_binding_checked=bool(original), baseline_pe_sha256=PE_SHA256,
                  native_outcome_vectors=len(accepted), deterministic_reconversions=len(accepted),
                  compiler_rejections=rejected)
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compiler", type=Path)
    parser.add_argument("--original", type=Path, help="Read-only retained original artifact binding check")
    parser.add_argument("--output", type=Path, help="Retain reproduced inputs and failure logs")
    args = parser.parse_args()
    manager = nullcontext(args.output) if args.output else tempfile.TemporaryDirectory(prefix="w2l-dispatch-vectors-")
    with manager as root:
        check(args.compiler.resolve(), Path(root).resolve(), args.original)


if __name__ == "__main__":
    main()
