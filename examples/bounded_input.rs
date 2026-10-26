//! Isolated acquisition component. No converter eligibility or host pointer access.
use std::io::{self, Read};
const MAX_BYTES: usize = 65_536;
const MAX_ENTRIES: usize = 256;
const MAX_ENTRY: usize = 4096;
const MAX_READS: usize = 1024;
const KEY: &[u8] = b"W2L_INPUT";

#[derive(Debug, PartialEq, Eq)]
enum Error {
    Unavailable,
    Io,
    ReadBudget,
    SnapshotLimit,
    EntryLimit,
    Unterminated,
    Malformed,
    Alias,
    Duplicate,
    Encoding,
    ValueLimit,
}
#[derive(Debug, PartialEq, Eq)]
struct Value {
    present: bool,
    units: [u16; 64],
    len: usize,
}
#[derive(Debug, PartialEq, Eq)]
struct ApiResult {
    returned: u32,
    bytes: [Option<u8>; 6],
}
impl Value {
    fn project(&self) -> ApiResult {
        let mut result = ApiResult {
            returned: 0,
            bytes: [None; 6],
        };
        if !self.present || self.len == 0 {
            return result;
        }
        if self.len > 2 {
            result.returned = (self.len + 1) as u32;
            return result;
        }
        result.returned = self.len as u32;
        for i in 0..=self.len {
            let word = if i == self.len { 0 } else { self.units[i] };
            let pair = word.to_le_bytes();
            result.bytes[2 * i] = Some(pair[0]);
            result.bytes[2 * i + 1] = Some(pair[1]);
        }
        result
    }
}
impl ApiResult {
    fn program_exit(&self) -> i32 {
        if self.returned == 0 {
            return 200;
        }
        if self.returned > 2 {
            return 201;
        }
        let mut number = 0;
        for i in 0..self.returned as usize {
            let word = u16::from_le_bytes([
                self.bytes[2 * i].expect("private success initialization"),
                self.bytes[2 * i + 1].expect("private success initialization"),
            ]);
            if !(48..=57).contains(&word) {
                return 202;
            }
            number = number * 10 + i32::from(word - 48);
        }
        number
    }
}
fn parse(snapshot: &[u8]) -> Result<Value, Error> {
    if snapshot.len() > MAX_BYTES {
        return Err(Error::SnapshotLimit);
    }
    if !snapshot.is_empty() && snapshot.last() != Some(&0) {
        return Err(Error::Unterminated);
    }
    let mut value = Value {
        present: false,
        units: [0; 64],
        len: 0,
    };
    if snapshot.is_empty() {
        return Ok(value);
    }
    for (index, entry) in snapshot[..snapshot.len() - 1]
        .split(|b| *b == 0)
        .enumerate()
    {
        if index >= MAX_ENTRIES || entry.len() > MAX_ENTRY {
            return Err(Error::EntryLimit);
        }
        let split = entry
            .iter()
            .position(|b| *b == b'=')
            .ok_or(Error::Malformed)?;
        if split == 0 {
            return Err(Error::Malformed);
        }
        let name = &entry[..split];
        if !name.is_ascii() {
            return Err(Error::Malformed);
        }
        if name.eq_ignore_ascii_case(KEY) {
            if name != KEY {
                return Err(Error::Alias);
            }
            if value.present {
                return Err(Error::Duplicate);
            }
            let text = std::str::from_utf8(&entry[split + 1..]).map_err(|_| Error::Encoding)?;
            for (i, unit) in text.encode_utf16().enumerate() {
                if i == 64 {
                    return Err(Error::ValueLimit);
                }
                value.units[i] = unit;
                value.len = i + 1;
            }
            value.present = true;
        }
    }
    Ok(value)
}
fn read_snapshot(mut reader: impl Read) -> Result<Value, Error> {
    let mut storage = [0u8; MAX_BYTES + 1];
    let mut used = 0;
    for _ in 0..MAX_READS {
        match reader.read(&mut storage[used..]) {
            Ok(0) => return parse(&storage[..used]),
            Ok(n) if n <= storage.len() - used => {
                used += n;
                if used > MAX_BYTES {
                    return Err(Error::SnapshotLimit);
                }
            }
            Ok(_) => return Err(Error::Io),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Io),
        }
    }
    Err(Error::ReadBudget)
}
fn acquire() -> Result<Value, Error> {
    if !cfg!(target_os = "linux") {
        return Err(Error::Unavailable);
    }
    let file = std::fs::File::open("/proc/self/environ").map_err(|_| Error::Unavailable)?;
    read_snapshot(file)
}
fn main() {
    let exit = match acquire() {
        Ok(value) => value.project().program_exit(),
        Err(_) => 203,
    };
    std::process::exit(exit);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn value(s: &str) -> Value {
        parse(format!("W2L_INPUT={s}\0").as_bytes()).unwrap()
    }
    #[test]
    fn missing_empty_and_initialized_ranges() {
        assert_eq!(
            parse(b"").unwrap().project(),
            ApiResult {
                returned: 0,
                bytes: [None; 6]
            }
        );
        assert_eq!(value("").project().returned, 0);
        assert_eq!(
            value("7").project().bytes,
            [Some(55), Some(0), Some(0), Some(0), None, None]
        );
        assert_eq!(
            value("42").project().bytes,
            [Some(52), Some(0), Some(50), Some(0), Some(0), Some(0)]
        );
    }
    #[test]
    fn utf16_and_required_capacity() {
        assert_eq!(value("😀").project().returned, 2);
        assert_eq!(value("😀").project().program_exit(), 202);
        assert_eq!(
            value("😀7").project(),
            ApiResult {
                returned: 4,
                bytes: [None; 6]
            }
        );
        assert_eq!(value(&"é".repeat(64)).project().returned, 65);
        assert_eq!(
            parse(format!("W2L_INPUT={}\0", "7".repeat(65)).as_bytes()),
            Err(Error::ValueLimit)
        );
    }
    #[test]
    fn encoding_and_alias_failures() {
        for raw in [&b"W2L_INPUT=\xff\0"[..], &b"W2L_INPUT=\xed\xa0\x80\0"[..]] {
            assert_eq!(parse(raw), Err(Error::Encoding));
        }
        assert_eq!(parse("W2L_ıNPUT=7\0".as_bytes()), Err(Error::Malformed));
        assert_eq!(parse(b"w2l_input=7\0"), Err(Error::Alias));
        assert_eq!(parse(b"W2L_INPUT=7\0W2L_INPUT=7\0"), Err(Error::Duplicate));
        assert_eq!(parse(b"W2L_INPUT=7\0w2l_input=7\0"), Err(Error::Alias));
    }
    #[test]
    fn complete_snapshot_validation() {
        assert_eq!(parse(b"W2L_INPUT=7"), Err(Error::Unterminated));
        assert_eq!(parse(b"W2L_INPUT=7\0bad\0"), Err(Error::Malformed));
        assert_eq!(parse(b"=7\0"), Err(Error::Malformed));
        assert_eq!(parse(b"\0"), Err(Error::Malformed));
        assert_eq!(
            parse(b"OTHER=\xff\0W2L_INPUT=42\0")
                .unwrap()
                .project()
                .program_exit(),
            42
        );
    }
    #[test]
    fn entry_and_total_caps() {
        assert!(parse(&b"A=\0".repeat(256)).is_ok());
        assert_eq!(parse(&b"A=\0".repeat(257)), Err(Error::EntryLimit));
        let entry = format!("A={}\0", "x".repeat(4094));
        assert!(parse(entry.as_bytes()).is_ok());
        assert_eq!(
            parse(format!("A={}\0", "x".repeat(4095)).as_bytes()),
            Err(Error::EntryLimit)
        );
        let exact = format!("A={}\0", "x".repeat(4093)).repeat(16);
        assert_eq!(exact.len(), MAX_BYTES);
        assert!(read_snapshot(exact.as_bytes()).is_ok());
        assert_eq!(
            read_snapshot([exact.as_bytes(), b"x"].concat().as_slice()),
            Err(Error::SnapshotLimit)
        );
    }
    #[test]
    fn short_reads_and_errors() {
        struct Small<'a>(&'a [u8]);
        impl Read for Small<'_> {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.0.read(&mut b[..1])
            }
        }
        assert_eq!(
            read_snapshot(Small(b"W2L_INPUT=7\0"))
                .unwrap()
                .project()
                .program_exit(),
            7
        );
        struct Failed;
        impl Read for Failed {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
        assert_eq!(read_snapshot(Failed), Err(Error::Io));
    }
    #[test]
    fn interrupted_budget_and_bad_reader() {
        struct Interrupted;
        impl Read for Interrupted {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::Interrupted.into())
            }
        }
        assert_eq!(read_snapshot(Interrupted), Err(Error::ReadBudget));
        struct Invalid;
        impl Read for Invalid {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                Ok(b.len() + 1)
            }
        }
        assert_eq!(read_snapshot(Invalid), Err(Error::Io));
    }
    #[test]
    fn owned_result_survives_source_and_projection() {
        let mut bytes = b"W2L_INPUT=42\0".to_vec();
        let result = parse(&bytes).unwrap();
        bytes.fill(0);
        assert_eq!(result.project().program_exit(), 42);
        assert_eq!(value("99").project().program_exit(), 99);
        assert_eq!(value(" 7").project().program_exit(), 202);
    }
}
