//! Test-only native support probe. No PE decoding or mechanical translation.
#[allow(dead_code)]
#[path = "decoder-eval/src/output_design.rs"]
mod output_design;
use std::fs::File;
use std::os::fd::AsFd;
fn main() {
    let result = (|| -> Result<(), &'static str> {
        // Borrow through std, duplicate ownership, then use unbuffered File writes.
        // The stdout handle is never used for buffered writes.
        let stdout = std::io::stdout();
        let mut output = File::from(
            stdout
                .as_fd()
                .try_clone_to_owned()
                .map_err(|_| "stdout unavailable")?,
        );
        if !output.metadata().map_err(|_| "stdout metadata")?.is_file() {
            return Err("stdout must be a regular file");
        }
        let words = [
            output_design::Word::Protected,
            output_design::Word::Data { owner: 0, value: 5 },
            output_design::Word::Data {
                owner: 0,
                value: 0x402000,
            },
            output_design::Word::Data { owner: 0, value: 1 },
        ];
        let bytes = output_design::prepare(&words, 0, 0x402000, b"Hello")?;
        let (eax, flags) = output_design::invoke(&mut output, bytes)?;
        if eax != 5 || flags != [None; 4] {
            return Err("contract mismatch");
        }
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("w2l: unsupported output environment: {error}");
        std::process::exit(125);
    }
}
