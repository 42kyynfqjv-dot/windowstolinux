//! Original CRT instruction components. This is not a whole-PE entry point.
//! Structural inventory grants no effect, ownership, or emission authority.
#[allow(dead_code)]
#[path = "../src/crt_buffer.rs"]
mod crt_buffer;
#[allow(dead_code)]
#[path = "../src/crt_error_map.rs"]
mod crt_error_map;
#[allow(dead_code)]
#[path = "../src/crt_exception_wrapper.rs"]
mod crt_exception_wrapper;
#[allow(dead_code)]
#[path = "../src/crt_formatter.rs"]
mod crt_formatter;
#[cfg(test)]
#[path = "../src/crt_formatter_ir_tests.rs"]
mod crt_formatter_ir_tests;
#[allow(dead_code)]
#[path = "../src/crt_stream_bundle.rs"]
mod crt_stream_bundle;
#[allow(dead_code)]
#[path = "../src/crt_stream_bundle_worker.rs"]
mod crt_stream_bundle_worker;
#[allow(dead_code)]
#[path = "../src/crt_stream_callees.rs"]
mod crt_stream_callees;
#[cfg(test)]
#[path = "../src/crt_stream_callees_tests.rs"]
mod crt_stream_callees_tests;
#[allow(dead_code)]
#[path = "../src/crt_stream_cpu.rs"]
mod crt_stream_cpu;
#[allow(dead_code)]
#[path = "../src/crt_stream_emit.rs"]
mod crt_stream_emit;
#[allow(dead_code)]
#[path = "../src/crt_stream_ir.rs"]
mod crt_stream_ir;
#[cfg(test)]
#[path = "../src/crt_stream_layout_tests.rs"]
mod crt_stream_layout_tests;
#[allow(dead_code)]
#[path = "../src/crt_stream_lifecycle.rs"]
mod crt_stream_lifecycle;
#[allow(dead_code)]
#[path = "../src/crt_stream_proof.rs"]
mod crt_stream_proof;
#[cfg(test)]
#[path = "../src/crt_stream_review_tests.rs"]
mod crt_stream_review_tests;
#[allow(dead_code)]
#[path = "../src/crt_stream_runtime.rs"]
mod crt_stream_runtime;
#[allow(dead_code)]
#[path = "../src/crt_stream_worker.rs"]
mod crt_stream_worker;
#[allow(dead_code)]
#[path = "../src/stream/graph.rs"]
mod graph;

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 4 && matches!(args[1].as_str(), "--emit-text" | "--emit-worker") {
        use std::collections::BTreeMap;
        let root = std::path::Path::new(&args[2]);
        let manifest =
            std::fs::read_to_string(root.join("stdio.manifest")).map_err(|e| e.to_string())?;
        if manifest.len() > 16384 {
            return Err("CRT manifest budget".into());
        }
        let mut regions = BTreeMap::new();
        let mut bindings = BTreeMap::new();
        for line in manifest.lines() {
            let row: Vec<_> = line.split_whitespace().collect();
            match row.as_slice() {
                ["region", name, origin, file] => {
                    if !file
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
                        || file.contains("..")
                    {
                        return Err("CRT manifest filename".into());
                    }
                    let path = root.join(file);
                    if std::fs::metadata(&path).map_err(|e| e.to_string())?.len() > 16384 {
                        return Err("CRT region budget".into());
                    }
                    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
                    let origin = origin.parse::<u32>().map_err(|_| "CRT manifest address")?;
                    if regions.insert(name.to_string(), (origin, bytes)).is_some() {
                        return Err("duplicate CRT region".into());
                    }
                }
                ["binding", name, value] => {
                    if bindings
                        .insert(
                            name.to_string(),
                            value.parse::<u32>().map_err(|_| "CRT binding integer")?,
                        )
                        .is_some()
                    {
                        return Err("duplicate CRT binding".into());
                    }
                }
                [] => {}
                _ => return Err("unknown CRT manifest row".into()),
            }
        }
        let region = |name: &str| -> Result<crt_stream_bundle::Region<'_>, String> {
            let (origin, bytes) = regions.get(name).ok_or("missing CRT original region")?;
            Ok(crt_stream_bundle::Region {
                origin: *origin,
                bytes,
            })
        };
        let value = |name: &str| {
            bindings
                .get(name)
                .copied()
                .ok_or_else(|| "missing CRT binding".to_string())
        };
        let mut source = crt_stream_bundle::emit(crt_stream_bundle::Input {
            writer: region("text_writer")?,
            stack_probe: region("stack_probe")?,
            security: region("security_check")?,
            cookie: value("cookie")?,
            descriptor_table: value("descriptor_table")?,
            write_iat: value("write_iat")?,
            error_iat: value("error_iat")?,
            max_input: 16384,
        })?;
        if args[1] == "--emit-worker" {
            let r = |name: &str| -> Result<crt_stream_bundle_worker::Region<'_>, String> {
                let v = region(name)?;
                Ok(crt_stream_bundle_worker::Region {
                    origin: v.origin,
                    bytes: v.bytes,
                })
            };
            source += &crt_stream_bundle_worker::emit(crt_stream_bundle_worker::Input {
                selector: r("write_selector")?,
                console: r("console_selector")?,
                isatty: r("isatty")?,
                mapper: r("errno_mapper")?,
                search: r("errno_search")?,
                updater: r("errno_update")?,
                error_table: r("errno_table")?,
                descriptor_table: value("descriptor_table")?,
                descriptor_limit_address: value("descriptor_limit_address")?,
                descriptor_limit: value("descriptor_limit")?,
                text_writer: r("text_writer")?,
                stack_probe: r("stack_probe")?,
                security: r("security_check")?,
                write_iat: value("write_iat")?,
                error_iat: value("error_iat")?,
                cookie: value("cookie")?,
                max_input: 16384,
                module: (value("module_begin")?, value("module_end")?),
            })?;
        }
        std::fs::write(&args[3], source).map_err(|e| e.to_string())?;
        return Ok(());
    }
    if args.len() != 4 || args[1] != "--inventory" {
        return Err(
            "crt_stream --inventory ORIGINAL_REGION.bin DECIMAL_ORIGIN (no emission)".into(),
        );
    }
    let path = std::path::Path::new(&args[2]);
    if std::fs::metadata(path).map_err(|e| e.to_string())?.len() > 16384 {
        return Err("CRT original region byte budget".into());
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let origin = args[3].parse().map_err(|_| "CRT origin integer")?;
    let graph = crt_stream_ir::Graph::decode(&bytes, origin)?;
    println!(
        "origin={} instructions={} calls={} emission_allowed=false",
        graph.origin,
        graph.nodes.len(),
        graph.calls().len()
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[allow(dead_code)]
#[path = "../src/handler_context.rs"]
mod handler_context;

#[allow(dead_code)]
#[path = "../src/handler_bridge.rs"]
mod handler_bridge;

#[allow(dead_code)]
#[path = "../src/selection.rs"]
mod selection;

#[allow(dead_code)]
#[path = "../src/frame_memory.rs"]
mod frame_memory;
#[allow(dead_code)]
#[path = "../src/frame_proof.rs"]
mod frame_proof;
#[allow(dead_code)]
#[path = "../src/handler_guard.rs"]
mod handler_guard;

#[allow(dead_code)]
#[path = "../src/handler_checks.rs"]
mod handler_checks;

#[allow(dead_code)]
#[path = "../src/unwind_bridges.rs"]
mod unwind_bridges;

#[allow(dead_code)]
#[path = "../src/crt_owned_frame.rs"]
mod crt_owned_frame;

#[cfg(test)]
#[path = "../src/crt_owned_search.rs"]
mod crt_owned_search;
#[cfg(test)]
#[allow(dead_code)]
#[path = "../src/handler_dispatch.rs"]
mod handler_dispatch;

#[cfg(test)]
#[allow(dead_code)]
#[path = "../src/local_unwind.rs"]
mod local_unwind;

#[cfg(test)]
#[path = "../src/dispatch.rs"]
mod dispatch;
#[cfg(test)]
#[path = "../src/funclet.rs"]
mod funclet;

#[cfg(test)]
#[path = "../src/crt_finally_fields.rs"]
mod crt_finally_fields;

#[cfg(test)]
#[path = "../src/crt_finally_tests.rs"]
mod crt_finally_tests;

#[allow(dead_code)]
#[path = "../src/restore_instruction.rs"]
mod restore_instruction;

#[allow(dead_code)]
#[path = "../src/crt_main_completion.rs"]
mod crt_main_completion;
#[allow(dead_code)]
#[path = "../src/crt_printf.rs"]
mod crt_printf;
#[allow(dead_code)]
#[path = "../src/frame_init.rs"]
mod frame_init;
#[allow(dead_code)]
#[path = "../src/main_completion.rs"]
mod main_completion;
#[allow(dead_code)]
#[path = "../src/raise_call.rs"]
mod raise_call;
#[allow(dead_code)]
#[path = "../src/stdio_effect.rs"]
mod stdio_effect;

#[cfg(test)]
#[path = "../src/crt_standard_handles_tests.rs"]
mod crt_standard_handles_tests;

#[cfg(test)]
#[path = "../src/crt_global_lock.rs"]
mod crt_global_lock;

#[cfg(test)]
#[path = "../src/crt_ptd.rs"]
mod crt_ptd;

#[cfg(test)]
#[path = "../src/crt_cxx_record.rs"]
mod crt_cxx_record;
