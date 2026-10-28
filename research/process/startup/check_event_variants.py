"""Independent native event-slice vectors; no Windows or whole-PE comparisons.

Handwritten instruction bytes and literal expected register vectors are fixed
here, independently of the compiler's decoder, proof and fixture generator.
Each admitted body runs under all 64 combinations of six arithmetic status bits.
"""
from contextlib import nullcontext
from pathlib import Path
import argparse
import json
import subprocess
import tempfile


INITIAL = [10, 11, 12, 13, 32768, 33024, 16, 17, 4096, 514]
COPY_EAX_TO_EDX = "0f0b89c2c3"
# name, original handler bytes, original event bytes, expected context at RET.
CASES = [
    ("zero_ecx_owner", "8b4c240c8381b800000002c781b00000000000000031c0c3", COPY_EAX_TO_EDX,
     [0, 11, 0, 13, 32768, 33024, 16, 17, 4100, 514]),
    ("255_edx_owner", "8b54240c8382b800000002c782b0000000ff00000031c0c3", COPY_EAX_TO_EDX,
     [255, 11, 255, 13, 32768, 33024, 16, 17, 4100, 514]),
    ("max_aliased_owner", "8b4c240c89ca8382b800000002c782b0000000ffffffff31c0c3", COPY_EAX_TO_EDX,
     [4294967295, 11, 4294967295, 13, 32768, 33024, 16, 17, 4100, 514]),
    ("copy_saved_ecx", "8b4c240c8b91ac0000008991b00000008381b80000000231c0c3", COPY_EAX_TO_EDX,
     [11, 11, 11, 13, 32768, 33024, 16, 17, 4100, 514]),
    ("saved_eax_wrap_up", "8b4c240cc781b0000000ffffffff8381b0000000018381b80000000231c0c3", COPY_EAX_TO_EDX,
     [0, 11, 0, 13, 32768, 33024, 16, 17, 4100, 514]),
    ("saved_eax_wrap_down", "8b4c240cc781b00000000000000083a9b0000000018381b80000000231c0c3", COPY_EAX_TO_EDX,
     [4294967295, 11, 4294967295, 13, 32768, 33024, 16, 17, 4100, 514]),
    ("restore_saved_ebx", "8b4c240cc781a40000004d0000008381b80000000231c0c3", "0f0b89d9c3",
     [10, 77, 12, 77, 32768, 33024, 16, 17, 4100, 514]),
    ("ordered_continuation_moves", "8b4c240c8381b800000002c781b00000002a00000031c0c3", "0f0b89c289c8c3",
     [11, 11, 42, 13, 32768, 33024, 16, 17, 4102, 514]),
    ("eax_owner_alias", "8b44240c89c28382b800000002c782b00000001100000031c0c3", COPY_EAX_TO_EDX,
     [17, 11, 17, 13, 32768, 33024, 16, 17, 4100, 514]),
    ("continuation_immediate", "8b4c240c8381b800000002c781b00000002a00000031c0c3", "0f0bb9ffffffffc3",
     [42, 4294967295, 12, 13, 32768, 33024, 16, 17, 4103, 514]),
]

# Each mutation has a separately stated reason; none is expected to be accepted.
BASE = CASES[7][1]
NEGATIVES = [
    ("working_ebx_clobber", "bb01000000" + BASE, COPY_EAX_TO_EDX, 8192, 4096),
    ("working_esi_clobber", "be01000000" + BASE, COPY_EAX_TO_EDX, 8192, 4096),
    ("wrong_context_argument", BASE.replace("8b4c240c", "8b4c2408"), COPY_EAX_TO_EDX, 8192, 4096),
    ("escaped_context_owner", BASE.replace("8381b8", "31c98381b8"), COPY_EAX_TO_EDX, 8192, 4096),
    ("saved_esp_write", BASE.replace("c781b0", "c781c4"), COPY_EAX_TO_EDX, 8192, 4096),
    ("saved_flags_write", BASE.replace("c781b0", "c781c0"), COPY_EAX_TO_EDX, 8192, 4096),
    ("resume_mid_instruction", BASE.replace("b800000002", "b800000003"), COPY_EAX_TO_EDX, 8192, 4096),
    ("search_escapes_handler", BASE.replace("31c0c3", "b801000000c3"), COPY_EAX_TO_EDX, 8192, 4096),
    ("event_without_ud2", BASE, "909089c2c3", 8192, 4096),
    ("overlapping_code", BASE, COPY_EAX_TO_EDX, 4096, 4096),
    ("event_extent_wrap", BASE, COPY_EAX_TO_EDX, 8192, 4294967294),
    ("continuation_memory", BASE, "0f0b8910c3", 8192, 4096),
    ("continuation_partial_width", BASE, "0f0b88c2c3", 8192, 4096),
    ("continuation_changes_flags", BASE, "0f0b01c2c3", 8192, 4096),
    ("continuation_branch", BASE, "0f0beb00c3", 8192, 4096),
    ("trailing_continuation_bytes", BASE, "0f0b89c2c390", 8192, 4096),
    ("truncated_handler", BASE[:-2], COPY_EAX_TO_EDX, 8192, 4096),
]


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

    def convert(name, handler_hex, event_hex, handler_origin=8192, event_origin=4096):
        handler = root / (name + ".handler")
        event = root / (name + ".event")
        generated = root / (name + ".rs")
        handler.write_bytes(bytes.fromhex(handler_hex))
        event.write_bytes(bytes.fromhex(event_hex))
        # Avoid stale output confusing a rejection with newly admitted code.
        generated.unlink(missing_ok=True)
        result = run([str(compiler), str(handler), str(handler_origin), str(event),
                      str(event_origin), str(generated)], name + ".convert", 20)
        return result, generated

    modules = []
    assertions = []
    for index, (name, handler_hex, event_hex, expected) in enumerate(CASES):
        result, generated = convert(name, handler_hex, event_hex)
        if result.returncode:
            raise AssertionError(name + ": " + result.stderr.decode(errors="replace"))
        source = generated.read_bytes()
        repeated, duplicate = convert(name + ".repeat", handler_hex, event_hex)
        if repeated.returncode or duplicate.read_bytes() != source:
            raise AssertionError(name + ": non-deterministic generated source")
        modules.append("mod v" + str(index) + " {\n" + source.decode() + "\n}")
        assertions.append("""
        for status in 0u32..64 {
            let mut flags=0x202u32;
            for (index, bit) in [1u32,4,16,64,128,2048].into_iter().enumerate() {
                if status & (1<<index)!=0 {flags|=bit;}
            }
            let mut input=INITIAL; input[9]=flags;
            let mut expected=EXPECTED; expected[9]=flags;
            assert_eq!(CALL(input),Ok(expected),"NAME status {status}");
        }
        for invalid_ip in [0u32,4095,4097,4098,u32::MAX] {
            let mut input=INITIAL; input[8]=invalid_ip;
            assert!(CALL(input).is_err(),"NAME IP {invalid_ip}");
        }
        for bit in [8u32,32,256,1024,4096,8192,16384,32768,65536,131072,262144,524288,1048576,2097152,4194304,0x80000000] {
            let mut input=INITIAL; input[9]|=bit;
            assert!(CALL(input).is_err(),"NAME mode/reserved {bit}");
        }
        for flags in [0u32,2,512] {
            let mut input=INITIAL; input[9]=flags;
            assert!(CALL(input).is_err(),"NAME missing fixed flags {flags}");
        }
        """.replace("INITIAL", repr(INITIAL)).replace("EXPECTED", repr(expected))
            .replace("CALL", "v" + str(index) + "::event").replace("NAME", name))

    rejected = []
    for name, handler_hex, event_hex, handler_origin, event_origin in NEGATIVES:
        result, generated = convert(name, handler_hex, event_hex, handler_origin, event_origin)
        if result.returncode == 0 or generated.exists():
            raise AssertionError(name + ": expected rejection without newly emitted source")
        rejected.append({"name": name, "diagnostic": result.stderr.decode(errors="replace").strip()})

    native_source = root / "all-native.rs"
    native_source.write_text("\n".join(modules) + "\nfn main(){\n" + "\n".join(assertions) + "\n}\n")
    native = root / "all-native"
    result = run(["rustc", "--edition=2021", str(native_source), "-o", str(native)], "rustc", 60)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors="replace"))
    result = run([str(native)], "native", 20)
    if result.returncode:
        raise AssertionError(result.stderr.decode(errors="replace"))
    report = {
        "kind": "independent native instruction-slice vectors; zero Windows or whole-PE comparisons",
        "compiled_variants": len(CASES),
        "native_status_combinations": len(CASES) * 64,
        "native_precondition_rejections": len(CASES) * (5 + 16 + 3),
        "compiler_rejections": rejected,
        "deterministic_reconversions": len(CASES),
    }
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("compiler", type=Path)
    parser.add_argument("--output", type=Path, help="Retain reproduction and failure logs")
    args = parser.parse_args()
    manager = nullcontext(args.output) if args.output else tempfile.TemporaryDirectory(prefix="w2l-event-vectors-")
    with manager as root:
        check(args.compiler.resolve(), Path(root).resolve())


if __name__ == "__main__":
    main()
