// Shared bounded acquisition/API effect; no application logic or admission authority.
use std::io::{self, Read};
const MAX_BYTES: usize = 65_536;
const MAX_ENTRIES: usize = 256;
const MAX_ENTRY: usize = 4096;
const MAX_READS: usize = 1024;
const KEY: &[u8] = b"W2L_INPUT";

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
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
    Capacity,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Value {
    present: bool,
    units: [u16; 64],
    len: usize,
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ApiResult {
    pub(crate) returned: u32,
    pub(crate) bytes: [Option<u8>; 6],
}
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct WideApiResult {
    pub(crate) returned: u32,
    pub(crate) bytes: [Option<u8>; 10],
}
impl Value {
    pub(crate) fn project_capacity(&self, capacity: u32) -> Result<WideApiResult, Error> {
        if !matches!(capacity, 3 | 5) {
            return Err(Error::Capacity);
        }
        let mut out = WideApiResult {
            returned: 0,
            bytes: [None; 10],
        };
        if !self.present || self.len == 0 {
            return Ok(out);
        }
        if self.len >= capacity as usize {
            out.returned = (self.len + 1) as u32;
            return Ok(out);
        }
        out.returned = self.len as u32;
        for i in 0..=self.len {
            let v = if i == self.len { 0 } else { self.units[i] };
            let b = v.to_le_bytes();
            out.bytes[2 * i] = Some(b[0]);
            out.bytes[2 * i + 1] = Some(b[1]);
        }
        Ok(out)
    }

    pub(crate) fn project(&self) -> ApiResult {
        let wide = self.project_capacity(3).expect("fixed reviewed capacity");
        ApiResult {
            returned: wide.returned,
            bytes: std::array::from_fn(|i| wide.bytes[i]),
        }
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
pub(crate) fn acquire() -> Result<Value, Error> {
    if !cfg!(target_os = "linux") {
        return Err(Error::Unavailable);
    }
    let file = std::fs::File::open("/proc/self/environ").map_err(|_| Error::Unavailable)?;
    read_snapshot(file)
}
