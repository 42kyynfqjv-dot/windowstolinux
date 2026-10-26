//! Independent test-only SUB-511 contract model, not a PE parser or translator.
use std::io::Write;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Word {
    Protected,
    Data { owner: u32, value: u32 },
}

pub fn prepare<'a>(
    words: &[Word],
    owner: u32,
    data_va: u32,
    data: &'a [u8],
) -> Result<&'a [u8], &'static str> {
    let args = words
        .get(words.len().checked_sub(3).ok_or("arguments")?..)
        .ok_or("arguments")?;
    let mut values = [0; 3];
    for (i, word) in args.iter().enumerate() {
        match *word {
            Word::Data {
                owner: actual,
                value,
            } if actual == owner => values[i] = value,
            _ => return Err("ownership"),
        }
    }
    let [count, address, fd] = values;
    if fd != 1 || !(1..=64).contains(&count) {
        return Err("fd/count");
    }
    address.checked_add(count - 1).ok_or("VA overflow")?;
    let start = address.checked_sub(data_va).ok_or("VA provenance")? as usize;
    let end = start.checked_add(count as usize).ok_or("range")?;
    let bytes = data.get(start..end).ok_or("buffer bounds")?;
    if !bytes.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
        return Err("text mode domain");
    }
    Ok(bytes)
}

// Full success yields EAX=count and unknown arithmetic flags. Caller words stay.
// Any error/short write is a converter runtime failure, not simulated errno.
pub fn invoke(
    writer: &mut impl Write,
    bytes: &[u8],
) -> Result<(u32, [Option<bool>; 4]), &'static str> {
    match writer.write(bytes) {
        Ok(n) if n == bytes.len() => Ok((n as u32, [None; 4])),
        _ => Err("unsupported output failure"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    fn args(count: u32, address: u32, fd: u32) -> Vec<Word> {
        vec![
            Word::Protected,
            Word::Data {
                owner: 7,
                value: count,
            },
            Word::Data {
                owner: 7,
                value: address,
            },
            Word::Data {
                owner: 7,
                value: fd,
            },
        ]
    }
    #[test]
    fn arguments_provenance_and_complete_bounds() {
        let words = args(5, 0x402000, 1);
        let saved = words.clone();
        assert_eq!(prepare(&words, 7, 0x402000, b"Hello"), Ok(&b"Hello"[..]));
        assert_eq!(words, saved);
        assert_eq!(
            prepare(&args(1, 0x402004, 1), 7, 0x402000, b"Hello"),
            Ok(&b"o"[..])
        );
        for (count, address, fd) in [
            (0, 0x402000, 1),
            (65, 0x402000, 1),
            (6, 0x402000, 1),
            (1, 0x401fff, 1),
            (2, 0x402004, 1),
            (1, 0x402005, 1),
            (5, 0x402000, 2),
            (2, u32::MAX, 1),
        ] {
            assert!(prepare(&args(count, address, fd), 7, 0x402000, b"Hello").is_err());
        }
        assert!(prepare(&words, 8, 0x402000, b"Hello").is_err());
        for index in 1..4 {
            let mut invalid = words.clone();
            invalid[index] = Word::Protected;
            assert!(prepare(&invalid, 7, 0x402000, b"Hello").is_err());
        }
        for size in 0..3 {
            assert!(prepare(&words[..size], 7, 0x402000, b"Hello").is_err());
        }
    }
    #[test]
    fn exact_text_domain_and_length_boundaries() {
        for byte in 0..=255u8 {
            assert_eq!(
                prepare(&args(1, 100, 1), 7, 100, &[byte]).is_ok(),
                (0x20..=0x7e).contains(&byte)
            );
        }
        assert_eq!(
            prepare(&args(64, 100, 1), 7, 100, &[b'A'; 64])
                .unwrap()
                .len(),
            64
        );
        // Same address in a different image must resolve that image's bytes.
        assert_eq!(
            prepare(&args(5, 100, 1), 7, 100, b"World"),
            Ok(&b"World"[..])
        );
    }
    struct Scripted {
        outcome: Option<usize>,
        calls: usize,
        observed: Vec<u8>,
    }
    impl Write for Scripted {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            match self.outcome {
                Some(n) => {
                    self.observed.extend_from_slice(&bytes[..n]);
                    Ok(n)
                }
                None => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("unbuffered contract")
        }
    }
    #[test]
    fn exact_success_return_and_unknown_flags() {
        let mut writer = Scripted {
            outcome: Some(5),
            calls: 0,
            observed: vec![],
        };
        assert_eq!(invoke(&mut writer, b"Hello"), Ok((5, [None; 4])));
        assert_eq!(writer.observed, b"Hello");
        assert_eq!(writer.calls, 1);
    }
    #[test]
    fn partial_zero_and_error_are_not_fabricated_success_or_retried() {
        for outcome in [None, Some(0), Some(1), Some(2), Some(3), Some(4)] {
            let mut writer = Scripted {
                outcome,
                calls: 0,
                observed: vec![],
            };
            assert!(invoke(&mut writer, b"Hello").is_err());
            assert_eq!(writer.calls, 1);
            assert_eq!(writer.observed, &b"Hello"[..outcome.unwrap_or(0)]);
        }
    }
}
