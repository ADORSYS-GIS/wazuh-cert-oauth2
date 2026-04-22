pub(super) fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes {
                    if let Some('"') = chars.peek() {
                        cur.push('"');
                        let _ = chars.next();
                    } else {
                        in_quotes = false;
                    }
                } else {
                    in_quotes = true;
                }
            }
            ',' if !in_quotes => {
                fields.push(cur);
                cur = String::new();
            }
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    fields
}

pub(super) fn escape_csv_field(s: &str) -> String {
    let needs_quotes = s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r');
    if needs_quotes {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for ch in s.chars() {
            if ch == '"' {
                out.push('"');
                out.push('"');
            } else {
                out.push(ch);
            }
        }
        out.push('"');
        out
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{escape_csv_field, split_csv_line, unescape_csv_field};

    #[test]
    fn split_csv_line_respects_quoted_commas() {
        let line = "plain,\"a,b\",tail";
        let fields = split_csv_line(line);
        assert_eq!(fields, vec!["plain", "a,b", "tail"]);
    }

    #[test]
    fn split_csv_line_handles_escaped_quotes() {
        let line = "\"hello \"\"quoted\"\" value\",x";
        let fields = split_csv_line(line);
        assert_eq!(fields, vec!["hello \"quoted\" value", "x"]);
    }

    #[test]
    fn escape_and_unescape_round_trip_special_characters() {
        let original = "alpha,\"beta\",gamma\nline2";
        let escaped = escape_csv_field(original);
        assert!(escaped.starts_with('"') && escaped.ends_with('"'));

        let unescaped = unescape_csv_field(&escaped);
        assert_eq!(unescaped, original);
    }

    #[test]
    fn escape_keeps_plain_strings_unchanged() {
        let original = "simple-value";
        assert_eq!(escape_csv_field(original), original);
    }
}

pub(super) fn unescape_csv_field(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        let inner = &s[1..s.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '"' {
                if let Some('"') = chars.peek() {
                    let _ = chars.next();
                    out.push('"');
                }
            } else {
                out.push(c);
            }
        }
        out
    } else {
        s.to_string()
    }
}
