//! Minimal JSON serialisation for artefacts this CLI emits.
//!
//! The CLI only ever *writes* JSON; the `nostr-bridge` TypeScript workspace is
//! what reads it. A writer is a few dozen auditable lines, whereas a full serde
//! dependency tree would be pulled in purely to format artefacts that already
//! have a fixed shape. Keeping the dependency surface small is a deliberate
//! posture for a tool that handles ceremony output.

/// A JSON value restricted to the shapes this CLI emits.
pub enum Json {
    /// A JSON string, escaped on render.
    Str(String),
    /// A JSON number rendered from an unsigned integer.
    Num(u64),
    /// A JSON array.
    Arr(Vec<Json>),
    /// A JSON object, rendered in insertion order.
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// Builds a string value.
    pub fn s(value: impl Into<String>) -> Self {
        Self::Str(value.into())
    }

    /// Builds an object from key-value pairs.
    pub fn obj(fields: Vec<(&str, Json)>) -> Self {
        Self::Obj(
            fields
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    /// Renders the value as indented JSON text.
    pub fn render(&self, indent: usize) -> String {
        let pad = "  ".repeat(indent);
        let inner_pad = "  ".repeat(indent + 1);
        match self {
            Self::Str(value) => format!("\"{}\"", escape(value)),
            Self::Num(value) => value.to_string(),
            Self::Arr(items) if items.is_empty() => "[]".to_owned(),
            Self::Arr(items) => {
                let body = items
                    .iter()
                    .map(|item| format!("{inner_pad}{}", item.render(indent + 1)))
                    .collect::<Vec<_>>()
                    .join(",\n");
                format!("[\n{body}\n{pad}]")
            }
            Self::Obj(fields) if fields.is_empty() => "{}".to_owned(),
            Self::Obj(fields) => {
                let body = fields
                    .iter()
                    .map(|(key, value)| {
                        format!("{inner_pad}\"{}\": {}", escape(key), value.render(indent + 1))
                    })
                    .collect::<Vec<_>>()
                    .join(",\n");
                format!("{{\n{body}\n{pad}}}")
            }
        }
    }
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_control_and_quote_characters() {
        let value = Json::s("a\"b\\c\nd\u{1}");
        assert_eq!(value.render(0), "\"a\\\"b\\\\c\\nd\\u0001\"");
    }

    #[test]
    fn renders_nested_objects_in_insertion_order() {
        let value = Json::obj(vec![
            ("b", Json::Num(2)),
            ("a", Json::Arr(vec![Json::s("x")])),
        ]);
        let rendered = value.render(0);
        assert!(rendered.find("\"b\"").unwrap() < rendered.find("\"a\"").unwrap());
        assert!(rendered.contains("\"x\""));
    }
}
