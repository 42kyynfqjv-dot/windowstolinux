//! Component exerciser, NOT mechanically translated application logic.
#[path = "../src/stream/effects.rs"]
pub mod effects;
#[path = "../src/stream/memory.rs"]
pub mod memory;
use effects::{Backend, Kind, Native};
use memory::{Error, Memory};
use std::io::{Read, Write};

// Independent authored consumer of the memory/API effect component. Kept separate
// from production so these comparisons cannot silently grant PE admission.
pub fn component<B: Backend>(backend: &mut B, kind: Kind) -> Result<u8, Error> {
    let mut m = Memory::default();
    let buf = m.allocate(256, false)?;
    let count = m.allocate(4, false)?;
    let written = m.allocate(4, false)?;
    let result = loop {
        let read = effects::read_file(&mut m, backend, kind, true, buf, 256, count)?;
        if !read.success {
            break if read.last_error == Some(effects::BROKEN_PIPE) {
                0
            } else {
                11
            };
        }
        let n = m.word(count)? as usize;
        if n == 0 {
            break 0;
        }
        for i in 0..n {
            let p = buf.offset(i)?;
            let byte = m.read(p, 1)?[0];
            if byte.is_ascii_lowercase() {
                m.write(p, &[byte - 32])?;
            }
        }
        let mut sent = 0;
        while sent < n {
            let w =
                effects::write_file(&mut m, backend, true, buf.offset(sent)?, n - sent, written)?;
            if !w.success {
                return Ok(12);
            }
            let k = m.word(written)? as usize;
            if k == 0 {
                return Ok(13);
            }
            sent += k;
        }
    };
    m.release(written)?;
    m.release(count)?;
    m.release(buf)?;
    Ok(result)
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let (input, kind): (Box<dyn Read>, Kind) = match args.get(1).map(String::as_str) {
        Some("file") => (
            Box::new(std::fs::File::open(&args[2]).expect("component input")),
            Kind::File,
        ),
        Some("read-failure") => (
            Box::new(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&args[2])
                    .expect("component write-only input"),
            ),
            Kind::File,
        ),
        Some("write-failure") => (
            Box::new(std::fs::File::open(&args[2]).expect("component input")),
            Kind::File,
        ),
        Some("pipe") => (Box::new(std::io::stdin().lock()), Kind::Pipe),
        _ => panic!("component exerciser: file|pipe|read-failure|write-failure [path]"),
    };
    let output: Box<dyn Write> = if args[1] == "write-failure" {
        Box::new(std::fs::File::open(&args[2]).expect("component read-only output"))
    } else {
        Box::new(std::io::stdout().lock())
    };
    let mut backend = Native { input, output };
    match component(&mut backend, kind) {
        Ok(code) => std::process::exit(i32::from(code)),
        Err(e) => {
            eprintln!("component contract failure: {e:?}");
            std::process::exit(125);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Short {
        input: Vec<u8>,
        at: usize,
        output: Vec<u8>,
        read_max: usize,
        write_max: usize,
        fail_after: Option<usize>,
    }
    impl Backend for Short {
        fn read(&mut self, b: &mut [u8]) -> Result<usize, u32> {
            let n = b.len().min(self.read_max).min(self.input.len() - self.at);
            b[..n].copy_from_slice(&self.input[self.at..self.at + n]);
            self.at += n;
            Ok(n)
        }
        fn write(&mut self, b: &[u8]) -> Result<usize, u32> {
            if self.fail_after.is_some_and(|n| self.output.len() >= n) {
                return Err(5);
            }
            let n = b.len().min(self.write_max);
            self.output.extend_from_slice(&b[..n]);
            Ok(n)
        }
    }
    #[test]
    fn arbitrary_binary_short_io_and_multiple_chunks() {
        for (r, w) in [(1, 1), (3, 2), (255, 1), (256, 17), (257, 300)] {
            let input: Vec<u8> = (0..65537).map(|i| (i * 73 + 19) as u8).collect();
            let expected: Vec<u8> = input
                .iter()
                .map(|&b| if (97..=122).contains(&b) { b - 32 } else { b })
                .collect();
            let mut b = Short {
                input,
                at: 0,
                output: vec![],
                read_max: r,
                write_max: w,
                fail_after: None,
            };
            assert_eq!(component(&mut b, Kind::Pipe), Ok(0));
            assert_eq!(b.output, expected);
        }
    }
    #[test]
    fn failure_preserves_written_prefix_and_zero_progress_does_not_loop() {
        let mut b = Short {
            input: b"abcdef".to_vec(),
            at: 0,
            output: vec![],
            read_max: 6,
            write_max: 2,
            fail_after: Some(2),
        };
        assert_eq!(component(&mut b, Kind::File), Ok(12));
        assert_eq!(b.output, b"AB");
        b.at = 0;
        b.output.clear();
        b.fail_after = None;
        b.write_max = 0;
        assert_eq!(component(&mut b, Kind::File), Ok(13));
        assert!(b.output.is_empty());
    }
}
