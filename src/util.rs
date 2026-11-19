use once_cell::sync::Lazy;
use regex::Regex;

use std::borrow::Cow;

macro_rules! regex {
    ($re:expr) => {
        ::regex::Regex::new($re).unwrap()
    };
}

static ESC_A: Lazy<Regex> = Lazy::new(|| regex!(r"\b(r\d*|p\d*)\."));
#[allow(dead_code)]
static ESC_G: Lazy<Regex> = Lazy::new(|| {
    regex!(r"\b(g\d*)\(((?:\s*[r|p]\d*\.\w+\s*,\s*){1,2}\s*[r|p]\d*\.\w+\s*)\)")
});
static ESC_C: Lazy<Regex> = Lazy::new(|| regex!(r#"(\s*"[^"]*"?|\s*[^,]*)"#));

#[inline]
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Returns the byte index right after the string literal that starts at
/// `start` (which must point at a `'` or `"`). Backslash escapes are
/// honored. If the literal is not terminated, the length of the input is
/// returned so callers keep the offending text untouched and the
/// expression compiler can report the real position of the failure.
fn skip_string_literal(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let mut i = start + 1;
    while i < bytes.len() && bytes[i] != quote {
        if bytes[i] == b'\\' {
            i += 1;
        }
        i += 1;
    }
    (i + 1).min(bytes.len())
}

/// Returns `Some(end)` with `end` being the byte index right after
/// `keyword` if `keyword` occurs at `start` as a standalone identifier
/// (i.e. bounded by non-identifier bytes on both sides).
fn match_keyword(bytes: &[u8], start: usize, keyword: &str) -> Option<usize> {
    let kw = keyword.as_bytes();
    if start > 0 && is_ident_byte(bytes[start - 1]) {
        return None;
    }
    let end = start.checked_add(kw.len())?;
    if bytes.len() < end || &bytes[start..end] != kw {
        return None;
    }
    if end < bytes.len() && is_ident_byte(bytes[end]) {
        return None;
    }
    Some(end)
}

/// Finds the byte index of the close paren matching the open paren at
/// `open`, honoring nested parens and string literals. Returns `None`
/// when the parens are unbalanced.
fn match_paren(s: &str, open: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'"' | b'\'' => {
                i = skip_string_literal(bytes, i);
                continue;
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Finds the first occurrence of `keyword` used as a standalone identifier
/// outside of string literals, followed by optional whitespace and a
/// balanced `(...)` group. Returns the byte index of the keyword, the
/// index right after the keyword, and the index of the matching close
/// paren. Malformed occurrences (no balanced parens) are skipped so the
/// original text reaches the expression compiler unchanged.
fn find_keyword_call(
    s: &str,
    keyword: &str,
    from: usize,
) -> Option<(usize, usize, usize)> {
    let bytes = s.as_bytes();
    let mut i = from;
    while i < bytes.len() {
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            i = skip_string_literal(bytes, i);
            continue;
        }
        if let Some(after) = match_keyword(bytes, i, keyword) {
            let mut open = after;
            while open < bytes.len() && bytes[open].is_ascii_whitespace() {
                open += 1;
            }
            if open < bytes.len() && bytes[open] == b'(' {
                if let Some(close) = match_paren(s, open) {
                    return Some((i, after, close));
                }
            }
            i = after;
            continue;
        }
        i += 1;
    }
    None
}

/// Returns the byte index of the first byte satisfying `pred` that lies
/// outside of string literals.
pub(crate) fn find_outside_strings(
    s: &str,
    pred: impl Fn(u8) -> bool,
) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            i = skip_string_literal(bytes, i);
            continue;
        }
        if pred(bytes[i]) {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn escape_assertion(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut res = String::with_capacity(s.len());
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        let quote = bytes[i];
        if quote != b'"' && quote != b'\'' {
            i += 1;
            continue;
        }
        let mut end = i + 1;
        while end < bytes.len() && bytes[end] != quote {
            if bytes[end] == b'\\' {
                end += 1;
            }
            end += 1;
        }
        let end = (end + 1).min(bytes.len());
        res.push_str(&ESC_A.replace_all(&s[start..i], "${1}_"));
        if quote == b'\'' && end - i >= 2 && bytes[end - 1] == quote {
            res.push('"');
            let mut escaped = false;
            for c in s[i + 1..end - 1].chars() {
                if c == '"' && !escaped {
                    res.push('\\');
                }
                escaped = c == '\\' && !escaped;
                res.push(c);
            }
            res.push('"');
        } else {
            res.push_str(&s[i..end]);
        }
        start = end;
        i = end;
    }
    res.push_str(&ESC_A.replace_all(&s[start..], "${1}_"));
    res
}

pub fn escape_in_operator(m: &str) -> Cow<'_, str> {
    let mut res = String::new();
    let mut start = 0;
    while let Some((kw, _, close)) = find_keyword_call(m, "in", start) {
        let open = m[kw..].find('(').map(|i| kw + i).unwrap_or(close);
        res.push_str(&m[start..open]);
        res.push('[');
        res.push_str(&m[open + 1..close]);
        res.push(']');
        start = close + 1;
    }
    if start == 0 {
        Cow::Borrowed(m)
    } else {
        res.push_str(&m[start..]);
        Cow::Owned(res)
    }
}

pub fn remove_comment(s: &str) -> String {
    let s = if let Some(idx) = find_outside_strings(s, |b| b == b'#') {
        &s[..idx]
    } else {
        s
    };

    s.trim_end().to_owned()
}

pub fn escape_eval(m: &str) -> Cow<'_, str> {
    let mut res = String::new();
    let mut start = 0;
    while let Some((kw, after, close)) = find_keyword_call(m, "eval", start) {
        let open = m[after..].find('(').map(|i| after + i).unwrap_or(close);
        let inner = escape_eval(&m[open + 1..close]);
        res.push_str(&m[start..kw]);
        res.push_str("eval(escape_assertion(");
        res.push_str(&inner);
        res.push_str("))");
        start = close + 1;
    }
    if start == 0 {
        Cow::Borrowed(m)
    } else {
        res.push_str(&m[start..]);
        Cow::Owned(res)
    }
}

pub fn parse_csv_line<'a, S: AsRef<str> + 'a>(line: S) -> Option<Vec<String>> {
    let line = line.as_ref().trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let mut res = vec![];
    for col in ESC_C.find_iter(line).map(|m| m.as_str().trim()) {
        res.push({
            if col.len() >= 2 && col.starts_with('"') && col.ends_with('"') {
                col[1..col.len() - 1].to_owned()
            } else {
                col.to_owned()
            }
        })
    }
    if res.is_empty() {
        None
    } else {
        Some(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_comment() {
        assert!(remove_comment("#").is_empty());
        assert_eq!(
            r#"g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.sub == "root""#,
            remove_comment(
                r#"g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.sub == "root" # root is the super user"#
            )
        );
    }

    #[test]
    fn test_remove_comment_respects_strings() {
        // A `#` inside a string literal must not truncate the expression.
        assert_eq!(
            r#"!(r.sub == "mallory#admin") && r.obj == p.obj"#,
            remove_comment(r#"!(r.sub == "mallory#admin") && r.obj == p.obj"#)
        );
        assert_eq!(
            "r.sub == 'a#b' && r.act == p.act",
            remove_comment("r.sub == 'a#b' && r.act == p.act")
        );
        // Escaped quotes must not confuse the string boundary tracking.
        assert_eq!(
            r##"r.sub == "a\"#b" && r.act == p.act"##,
            remove_comment(r##"r.sub == "a\"#b" && r.act == p.act"##)
        );
        // A real comment after the strings is still stripped.
        assert_eq!(
            r##"r.sub == "a#b" && r.act == p.act"##,
            remove_comment(r##"r.sub == "a#b" && r.act == p.act # deny root"##)
        );
    }

    #[test]
    fn test_escape_in_operator() {
        assert_eq!(
            r#"r_sub in ["alice", "bob"]"#,
            escape_in_operator(r#"r_sub in ("alice", "bob")"#)
        );
        // `in` inside a string literal must be left alone.
        assert_eq!(
            r#"r_sub == "drop in (prod)" || r_obj == p_obj"#,
            escape_in_operator(
                r#"r_sub == "drop in (prod)" || r_obj == p_obj"#
            )
        );
        // Nested parens and strings containing parens are matched correctly.
        assert_eq!(
            r#"r_sub in [f(p_sub), "a)b"] && r_act == p_act"#,
            escape_in_operator(
                r#"r_sub in (f(p_sub), "a)b") && r_act == p_act"#
            )
        );
        // Already-bracketed sets and identifiers containing `in` pass through.
        assert_eq!(
            r#"r_sub in ["data2"] && login(p_sub)"#,
            escape_in_operator(r#"r_sub in ["data2"] && login(p_sub)"#)
        );
        // Unbalanced parens are left untouched so the compiler reports
        // the real token position instead of a rewritten expression.
        assert_eq!(
            "r_sub in (p_sub && r_act == p_act",
            escape_in_operator("r_sub in (p_sub && r_act == p_act")
        );
    }

    #[test]
    fn test_escape_eval() {
        assert_eq!(
            "eval(escape_assertion(p.sub_rule)) && r_obj == p_obj",
            escape_eval("eval(p.sub_rule) && r_obj == p_obj")
        );
        // `eval` inside a string literal must be left alone.
        assert_eq!(
            r#"r_sub == "eval(p.sub)" && r_obj == p_obj"#,
            escape_eval(r#"r_sub == "eval(p.sub)" && r_obj == p_obj"#)
        );
        // Nested parens inside eval are matched correctly.
        assert_eq!(
            "eval(escape_assertion(g(r_sub, p_sub) && f(p_act))) || r_obj == p_obj",
            escape_eval("eval(g(r_sub, p_sub) && f(p_act)) || r_obj == p_obj")
        );
        // Identifiers that merely contain `eval` are not rewritten.
        assert_eq!(
            "myeval(p_sub) && r_obj == p_obj",
            escape_eval("myeval(p_sub) && r_obj == p_obj")
        );
        // Unbalanced parens pass through unchanged for fail-closed compile.
        assert_eq!(
            "eval(p_sub && r_obj == p_obj",
            escape_eval("eval(p_sub && r_obj == p_obj")
        );
    }

    #[test]
    fn test_escape_assertion() {
        let s = "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act";
        let exp = "g(r_sub, p_sub) && r_obj == p_obj && r_act == p_act";

        assert_eq!(exp, escape_assertion(s));

        let s1 = "g(r2.sub, p2.sub) && r2.obj == p2.obj && r2.act == p2.act";
        let exp1 = "g(r2_sub, p2_sub) && r2_obj == p2_obj && r2_act == p2_act";

        assert_eq!(exp1, escape_assertion(s1));

        assert_eq!(
            r#"r_sub == p_sub && r_obj == "https://p.example.com""#,
            escape_assertion(
                r#"r.sub == p.sub && r.obj == "https://p.example.com""#
            )
        );
        assert_eq!(
            r#"r_obj == "a\"p.b" || p_obj == "r""#,
            escape_assertion(r#"r.obj == "a\"p.b" || p.obj == 'r'"#)
        );
    }

    #[test]
    fn test_csv_parse_1() {
        assert_eq!(
            parse_csv_line("alice, domain1, data1, action1"),
            Some(vec![
                "alice".to_owned(),
                "domain1".to_owned(),
                "data1".to_owned(),
                "action1".to_owned()
            ])
        )
    }

    #[test]
    fn test_csv_parse_2() {
        assert_eq!(
            parse_csv_line("alice, \"domain1, domain2\", data1 , action1"),
            Some(vec![
                "alice".to_owned(),
                "domain1, domain2".to_owned(),
                "data1".to_owned(),
                "action1".to_owned()
            ])
        )
    }

    #[test]
    fn test_csv_parse_3() {
        assert_eq!(
            parse_csv_line(","),
            Some(vec!["".to_owned(), "".to_owned(),])
        )
    }

    #[test]
    fn test_csv_parse_4() {
        assert_eq!(parse_csv_line(" "), None);
        assert_eq!(parse_csv_line("#"), None);
        assert_eq!(parse_csv_line(" #"), None);
    }

    #[test]
    fn test_csv_parse_5() {
        assert_eq!(
            parse_csv_line(
                "alice, \"domain1, domain2\", \"data1, data2\", action1"
            ),
            Some(vec![
                "alice".to_owned(),
                "domain1, domain2".to_owned(),
                "data1, data2".to_owned(),
                "action1".to_owned()
            ])
        )
    }

    #[test]
    fn test_csv_parse_6() {
        assert_eq!(parse_csv_line("\" "), Some(vec!["\"".to_owned()]))
    }

    #[test]
    fn test_csv_parse_7() {
        assert_eq!(
            parse_csv_line("\" alice"),
            Some(vec!["\" alice".to_owned()])
        )
    }

    #[test]
    fn test_csv_parse_8() {
        assert_eq!(
            parse_csv_line("alice, \"domain1, domain2"),
            Some(vec!["alice".to_owned(), "\"domain1, domain2".to_owned(),])
        )
    }

    #[test]
    fn test_csv_parse_9() {
        assert_eq!(parse_csv_line("\"\""), Some(vec!["".to_owned()]));
    }

    #[test]
    fn test_csv_parse_10() {
        assert_eq!(
            parse_csv_line("r.sub.Status == \"ACTIVE\", /data1, read"),
            Some(vec![
                "r.sub.Status == \"ACTIVE\"".to_owned(),
                "/data1".to_owned(),
                "read".to_owned()
            ])
        );
    }
}
