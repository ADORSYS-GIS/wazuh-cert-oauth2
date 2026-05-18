pub fn constant_time_eq(a: &str, b: &str) -> bool {
    // Constant-time comparison over bytes, independent of early differences.
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let max = ab.len().max(bb.len());
    let mut diff: u8 = (ab.len() ^ bb.len()) as u8;
    for i in 0..max {
        let av = *ab.get(i).unwrap_or(&0);
        let bv = *bb.get(i).unwrap_or(&0);
        diff |= av ^ bv;
    }
    diff == 0
}

/// Parse a single `KEY=VALUE` pair for use with `--webhook-custom-headers`.
pub fn parse_key_val(s: &str) -> Result<(String, String), String> {
    let pos = s
        .find('=')
        .ok_or_else(|| format!("expected KEY=VALUE, got '{s}'"))?;
    Ok((s[..pos].to_string(), s[pos + 1..].to_string()))
}
