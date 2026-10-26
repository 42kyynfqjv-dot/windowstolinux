// Independent native contract prototype; this is not emitted by the converter.
fn main() {
    let code = match std::env::var("W2L_INPUT") {
        Err(std::env::VarError::NotPresent) => 200,
        Err(std::env::VarError::NotUnicode(_)) => 203,
        Ok(s) if s.is_empty() => 200,
        Ok(s) if s.encode_utf16().count() > 2 => 201,
        Ok(s) if !s.bytes().all(|b| b.is_ascii_digit()) => 202,
        Ok(s) => s.parse::<i32>().expect("one or two decimal digits"),
    };
    std::process::exit(code);
}
