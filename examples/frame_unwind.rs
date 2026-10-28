//! Original fragment composition with explicit startup/handler cuts.
#[path = "../src/unwind.rs"]
pub mod unwind;
use std::path::Path;
use unwind::frame_unwind::{Frame, Input, Region};

fn number(value: &str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| "invalid decimal manifest value".into())
}
fn bytes(root: &Path, name: &str) -> Result<Vec<u8>, String> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("manifest filename policy".into());
    }
    let path = root.join(name);
    if std::fs::metadata(&path).map_err(|e| e.to_string())?.len() > 1_048_576 {
        return Err("manifest file budget".into());
    }
    std::fs::read(path).map_err(|e| e.to_string())
}
fn region(root: &Path, address: &str, name: &str) -> Result<Region, String> {
    Ok(Region {
        va: number(address)?,
        bytes: bytes(root, name)?,
    })
}
fn set<T>(slot: &mut Option<T>, value: T) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err("duplicate manifest singleton".into());
    }
    Ok(())
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("frame_unwind DIRECTORY OUTPUT.rs".into());
    }
    let root = Path::new(&args[1]);
    let manifest = String::from_utf8(bytes(root, "frame.manifest")?).map_err(|e| e.to_string())?;
    let (mut cookie, mut handler, mut trace, mut feature, mut event) =
        (None, None, None, None, None);
    let (
        mut dispatcher,
        mut dispatch_table,
        mut normalizer,
        mut installer,
        mut restore,
        mut target,
    ) = (None, None, None, None, None, None);
    let (mut frames, mut filters, mut funclets, mut cleanups, mut globals, mut landings) = (
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    if manifest.lines().count() > 256 {
        return Err("manifest row budget".into());
    }
    for line in manifest.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        match parts.as_slice() {
            [] => {}
            ["cookie", value] => set(&mut cookie, number(value)?)?,
            ["handler", value] => set(&mut handler, number(value)?)?,
            ["trace", value] => set(&mut trace, number(value)?)?,
            ["feature", value] => set(&mut feature, number(value)?)?,
            ["event", value] => set(&mut event, number(value)?)?,
            ["global", value] => globals.push(number(value)?),
            ["frame", prefix_va, prefix, table_va, table, activation_va, activation] => {
                let activation = match (*activation_va, *activation) {
                    ("-", "-") => None,
                    ("-", _) | (_, "-") => return Err("incomplete activation fragment".into()),
                    _ => Some(region(root, activation_va, activation)?),
                };
                frames.push(Frame {
                    prefix: region(root, prefix_va, prefix)?,
                    table: region(root, table_va, table)?,
                    activation,
                });
            }
            [kind, va, file] => {
                let item = region(root, va, file)?;
                match *kind {
                    "filter" => filters.push(item),
                    "landing" => landings.push(item),
                    "funclet" => funclets.push(item),
                    "cleanup" => cleanups.push(item),
                    "dispatcher" => set(&mut dispatcher, item)?,
                    "dispatch-table" => set(&mut dispatch_table, item)?,
                    "normalizer" => set(&mut normalizer, item)?,
                    "installer" => set(&mut installer, item)?,
                    "restore" => set(&mut restore, item)?,
                    "target" => set(&mut target, item)?,
                    _ => return Err("unknown manifest region kind".into()),
                }
            }
            _ => return Err("invalid manifest row".into()),
        }
    }
    let input = Input {
        cookie_va: cookie.ok_or("missing cookie")?,
        handler_va: handler.ok_or("missing handler")?,
        frames,
        filters,
        landings,
        funclets,
        cleanups,
        dispatcher: dispatcher.ok_or("missing dispatcher")?,
        dispatch_table: dispatch_table.ok_or("missing dispatch table")?,
        trace_va: trace.ok_or("missing trace")?,
        globals,
        normalizer: normalizer.ok_or("missing normalizer")?,
        feature_va: feature.ok_or("missing feature")?,
        installer: installer.ok_or("missing installer")?,
        restore: restore.ok_or("missing restore")?,
        target: target.ok_or("missing target")?,
        event_code: event.ok_or("missing event")?,
    };
    let proof = unwind::frame_unwind::prove_fragments(&input)?;
    std::fs::write(&args[2], proof.emit()).map_err(|e| e.to_string())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
