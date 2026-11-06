//! Argument discovery from the contract's own JSON errors.
//!
//! Bytecode has no argument names, but near-sdk contracts say exactly what is
//! wrong with the input: serde_json errors like
//!   missing field `holding_account_id` at line 1 column 810
//!   invalid type: string "", expected u64 at line 1 column 42
//!   unknown variant `x`, expected one of `Active`, `Paused` at line 1 column 7
//! The column points into the JSON we sent, so we can tell which object lacks
//! a field or which value has the wrong type, fix it and call again. Everything
//! happens in the local sim; nothing is sent anywhere.

use serde_json::{Map, Value, json};

/// One JSON value of the serialised args and where it sits (byte offsets).
struct Span {
    path: Vec<PathPart>,
    start: usize,
    /// Exclusive end.
    end: usize,
    is_object: bool,
}

#[derive(Clone, Debug)]
enum PathPart {
    Key(String),
    Index(usize),
}

/// Compact serialisation identical to `serde_json::to_string`, recording every value's span.
fn write(v: &Value, path: &mut Vec<PathPart>, out: &mut String, spans: &mut Vec<Span>) {
    let start = out.len();
    match v {
        Value::Object(m) => {
            out.push('{');
            for (i, (k, child)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap());
                out.push(':');
                path.push(PathPart::Key(k.clone()));
                write(child, path, out, spans);
                path.pop();
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, child) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                path.push(PathPart::Index(i));
                write(child, path, out, spans);
                path.pop();
            }
            out.push(']');
        }
        _ => out.push_str(&serde_json::to_string(v).unwrap()),
    }
    spans.push(Span { path: path.clone(), start, end: out.len(), is_object: v.is_object() });
}

fn get_mut<'a>(root: &'a mut Value, path: &[PathPart]) -> Option<&'a mut Value> {
    let mut cur = root;
    for p in path {
        cur = match p {
            PathPart::Key(k) => cur.get_mut(k.as_str())?,
            PathPart::Index(i) => cur.get_mut(*i)?,
        };
    }
    Some(cur)
}

/// Plausible first value for a field we only know the name of; type errors refine it later.
fn guess_for(name: &str, who: &str) -> Value {
    let n = name.to_lowercase();
    if n.contains("metadata") || n.ends_with("_config") || n == "config" || n.ends_with("_settings") {
        json!({})
    } else if n.ends_with("_id") || ["owner", "admin", "account", "receiver", "recipient", "oracle", "operator", "manager", "treasury", "beneficiary"].iter().any(|w| n.contains(w)) {
        json!(who)
    } else if ["supply", "amount", "balance", "deposit", "fee", "price", "cap", "limit"].iter().any(|w| n.contains(w)) {
        json!("1000000000000000000000000")
    } else if n.starts_with("is_") || n.starts_with("enable") || n.contains("paused") || n.ends_with("_enabled") {
        json!(false)
    } else {
        json!("")
    }
}

/// A value of the type serde says it expected (`expected u64`, `expected a string`, ...).
fn value_for_expected(expected: &str, name: &str, who: &str) -> Option<Value> {
    let e = expected.trim();
    // unknown variant `x`, expected one of `A`, `B`  /  expected `A` or `B`
    if let Some(first) = e.split('`').nth(1).filter(|_| e.contains('`')) {
        return Some(json!(first));
    }
    let e = e.to_lowercase();
    Some(if e.contains("string") || e.contains("account id") || e.contains("str") {
        if name.ends_with("_id") || name.contains("account") || name.contains("owner") { json!(who) } else { json!("1") }
    } else if e.contains("bool") {
        json!(false)
    } else if ["u8", "u16", "u32", "u64", "u128", "i8", "i16", "i32", "i64", "i128", "usize", "isize", "integer", "number"].iter().any(|t| e.contains(t)) {
        json!(1)
    } else if e.contains("f32") || e.contains("f64") || e.contains("float") {
        json!(1.0)
    } else if e.contains("sequence") || e.contains("tuple") || e.contains("array") || e.contains("vec") {
        json!([])
    } else if e.contains("struct") || e.contains("map") || e.contains("object") {
        json!({})
    } else if e.contains("unit") || e.contains("null") {
        Value::Null
    } else {
        return None;
    })
}

fn after<'a>(s: &'a str, pat: &str) -> Option<&'a str> {
    s.find(pat).map(|i| &s[i + pat.len()..])
}

/// The column serde reports, as a byte offset into the serialised args.
fn column(err: &str) -> Option<usize> {
    let rest = after(err, " at line 1 column ")?;
    rest.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok()
}

/// Given the contract's error for `args`, the corrected args, or None when the
/// error is not a JSON input problem we can locate and fix.
pub fn repair(err: &str, args: &Value, who: &str) -> Option<Value> {
    if !err.contains("deserialize") && !err.contains("missing field") && !err.contains("invalid type") && !err.contains("unknown variant") {
        return None;
    }
    let col = column(err)?;
    let mut text = String::new();
    let mut spans = Vec::new();
    write(args, &mut Vec::new(), &mut text, &mut spans);
    if text != serde_json::to_string(args).ok()? {
        return None; // our offsets would not match what the contract parsed
    }
    let idx = col.checked_sub(1)?; // 1-based column → byte index
    // Deepest span containing the reported position.
    let deepest = |want_object: bool| {
        spans
            .iter()
            .filter(|s| s.start <= idx && idx < s.end && (!want_object || s.is_object))
            .max_by_key(|s| s.path.len())
    };
    let mut fixed = args.clone();

    if let Some(rest) = after(err, "missing field `") {
        let field = rest.split('`').next()?.to_string();
        let obj_path = deepest(true).map(|s| s.path.clone()).unwrap_or_default();
        let obj = get_mut(&mut fixed, &obj_path)?;
        let map: &mut Map<String, Value> = obj.as_object_mut()?;
        if map.contains_key(&field) {
            return None;
        }
        map.insert(field.clone(), guess_for(&field, who));
        return Some(fixed);
    }

    let expected = after(err, ", expected ")?;
    let expected = expected.split(" at line ").next()?;
    let span = deepest(false)?;
    let name = match span.path.last() {
        Some(PathPart::Key(k)) => k.clone(),
        _ => String::new(),
    };
    let new = value_for_expected(expected, &name, who)?;
    let slot = get_mut(&mut fixed, &span.path)?;
    if *slot == new {
        return None;
    }
    *slot = new;
    Some(fixed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_missing_top_level_field() {
        let args = json!({"owner_id": "owner.near"});
        let col = serde_json::to_string(&args).unwrap().len(); // closing brace
        let err = format!("Failed to deserialize input from JSON. Error: `missing field `holding_account_id` at line 1 column {col}`");
        let got = repair(&err, &args, "owner.near").unwrap();
        assert_eq!(got, json!({"owner_id": "owner.near", "holding_account_id": "owner.near"}));
    }

    #[test]
    fn adds_missing_nested_field() {
        let args = json!({"metadata": {}, "owner_id": "o.near"});
        // `{"metadata":{}` → the nested object's closing brace is at byte 13, column 14
        let err = "missing field `spec` at line 1 column 14";
        let got = repair(err, &args, "o.near").unwrap();
        assert_eq!(got["metadata"]["spec"], json!(""));
    }

    #[test]
    fn fixes_wrong_type_and_enum() {
        let args = json!({"a": "x", "decimals": ""});
        let s = serde_json::to_string(&args).unwrap();
        let col = s.find(r#""decimals":"""#).unwrap() + r#""decimals":"""#.len();
        let got = repair(&format!("invalid type: string \"\", expected u8 at line 1 column {col}"), &args, "o.near").unwrap();
        assert_eq!(got["decimals"], json!(1));
        let col_a = s.find(r#""a":"x""#).unwrap() + r#""a":"x""#.len();
        let got = repair(&format!("unknown variant `x`, expected one of `Active`, `Paused` at line 1 column {col_a}"), &args, "o.near").unwrap();
        assert_eq!(got["a"], json!("Active"));
    }

    #[test]
    fn gives_up_on_non_json_errors() {
        assert!(repair("ERR_BORSH_DESERIALIZE", &json!({}), "o.near").is_none());
        assert!(repair("only the owner can call this", &json!({}), "o.near").is_none());
    }
}
