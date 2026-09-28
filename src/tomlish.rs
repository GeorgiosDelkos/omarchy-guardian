//! A deliberately restricted TOML reader.
//!
//! Guardian only needs two things from TOML: the `name`/`version`/`source`
//! strings of machine-generated lockfiles (`Cargo.lock`, `poetry.lock`) and
//! whether a manifest (`Cargo.toml`, `pyproject.toml`) declares any
//! dependencies. So this reader splits a document into `key = value` entries,
//! tracks which table each belongs to, and keeps every value as source text
//! with comments removed. It understands all four string forms, arrays and
//! inline tables well enough to find where a value ends, and fails on anything
//! it cannot delimit rather than guessing.

use std::fmt;

/// One `key = value` line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Counts table headers seen so far, so entries of different
    /// `[[array-table]]` items can be told apart. The root table is 0.
    pub section: usize,
    pub table: Vec<String>,
    pub array_table: bool,
    pub key: Vec<String>,
    /// The value's source text, trimmed, with comments removed.
    pub value: String,
}

impl Entry {
    /// The table path followed by the key path.
    pub fn full_path(&self) -> Vec<&str> {
        self.table
            .iter()
            .chain(&self.key)
            .map(String::as_str)
            .collect()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError {
    line: usize,
    message: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} on line {}", self.message, self.line)
    }
}

impl std::error::Error for ParseError {}

pub fn entries(text: &str) -> Result<Vec<Entry>, ParseError> {
    let mut reader = Reader {
        bytes: text.as_bytes(),
        position: 0,
    };
    let mut entries = Vec::new();
    let mut table = Vec::new();
    let mut array_table = false;
    let mut section = 0;

    loop {
        reader.skip_blank_lines();
        match reader.peek() {
            None => return Ok(entries),
            Some(b'[') => {
                reader.position += 1;
                array_table = reader.eat(b'[');
                table = reader.key_path()?;
                reader.expect(b']', "expected ']' to close the table header")?;
                if array_table {
                    reader.expect(b']', "expected ']]' to close the array table header")?;
                }
                reader.end_of_line()?;
                section += 1;
            }
            Some(_) => {
                let key = reader.key_path()?;
                reader.expect(b'=', "expected '=' after key")?;
                let value = reader.value()?;
                reader.end_of_line()?;
                entries.push(Entry {
                    section,
                    table: table.clone(),
                    array_table,
                    key,
                    value,
                });
            }
        }
    }
}

/// Groups the entries of every `[[name]]` item, in document order.
pub fn array_table_items<'e>(entries: &'e [Entry], name: &str) -> Vec<Vec<&'e Entry>> {
    let mut items: Vec<Vec<&Entry>> = Vec::new();
    let mut current_section = None;

    for entry in entries {
        if !entry.array_table || entry.table.len() != 1 || entry.table[0] != name {
            continue;
        }
        if current_section != Some(entry.section) {
            items.push(Vec::new());
            current_section = Some(entry.section);
        }
        if let Some(item) = items.last_mut() {
            item.push(entry);
        }
    }
    items
}

/// The decoded string value of a single-segment key in an array-table item.
pub fn string_field(item: &[&Entry], key: &str) -> Option<String> {
    item.iter()
        .find(|entry| entry.key.len() == 1 && entry.key[0] == key)
        .and_then(|entry| string_value(&entry.value))
}

/// Decodes a single-line basic (`"..."`) or literal (`'...'`) string value.
pub fn string_value(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let (decoded, consumed) = match bytes.first() {
        Some(b'"') if !raw.starts_with("\"\"\"") => decode_basic(&bytes[1..])?,
        Some(b'\'') if !raw.starts_with("'''") => decode_literal(&bytes[1..])?,
        _ => return None,
    };
    (consumed + 1 == bytes.len()).then_some(decoded)
}

/// Whether the value is an array or inline table with no elements.
pub fn is_empty_container(raw: &str) -> bool {
    let inner = raw
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| {
            raw.strip_prefix('{')
                .and_then(|rest| rest.strip_suffix('}'))
        });
    inner.is_some_and(|inner| {
        inner
            .chars()
            .all(|character| character.is_whitespace() || character == ',')
    })
}

/// Decodes a basic string body (after the opening quote). Returns the text and
/// the bytes consumed, including the closing quote.
fn decode_basic(bytes: &[u8]) -> Option<(String, usize)> {
    let mut output = Vec::new();
    let mut index = 0;

    while let Some(&byte) = bytes.get(index) {
        index += 1;
        match byte {
            b'"' => return String::from_utf8(output).ok().map(|text| (text, index)),
            b'\\' => {
                let escape = *bytes.get(index)?;
                index += 1;
                let character = match escape {
                    b'b' => '\u{8}',
                    b't' => '\t',
                    b'n' => '\n',
                    b'f' => '\u{c}',
                    b'r' => '\r',
                    b'"' => '"',
                    b'\\' => '\\',
                    b'u' | b'U' => {
                        let digits = if escape == b'u' { 4 } else { 8 };
                        let hex = std::str::from_utf8(bytes.get(index..index + digits)?).ok()?;
                        index += digits;
                        char::from_u32(u32::from_str_radix(hex, 16).ok()?)?
                    }
                    _ => return None,
                };
                let mut encoded = [0_u8; 4];
                output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
            }
            b'\n' | b'\r' => return None,
            other => output.push(other),
        }
    }
    None
}

fn decode_literal(bytes: &[u8]) -> Option<(String, usize)> {
    let end = bytes
        .iter()
        .position(|byte| matches!(byte, b'\'' | b'\n' | b'\r'))?;
    if bytes[end] != b'\'' {
        return None;
    }
    let text = std::str::from_utf8(&bytes[..end]).ok()?;
    Some((text.to_string(), end + 1))
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Reader<'_> {
    fn error(&self, message: &'static str) -> ParseError {
        // Splitting on newlines yields one piece per line up to the error.
        let line = self.bytes[..self.position.min(self.bytes.len())]
            .split(|byte| *byte == b'\n')
            .count();
        ParseError { line, message }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn rest(&self) -> &[u8] {
        &self.bytes[self.position..]
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, byte: u8, message: &'static str) -> Result<(), ParseError> {
        self.skip_spaces();
        if self.eat(byte) {
            Ok(())
        } else {
            Err(self.error(message))
        }
    }

    fn skip_spaces(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.position += 1;
        }
    }

    fn skip_comment(&mut self) {
        if self.peek() == Some(b'#') {
            while !matches!(self.peek(), None | Some(b'\n')) {
                self.position += 1;
            }
        }
    }

    fn skip_blank_lines(&mut self) {
        loop {
            self.skip_spaces();
            self.skip_comment();
            match self.peek() {
                Some(b'\n' | b'\r') => self.position += 1,
                _ => return,
            }
        }
    }

    fn end_of_line(&mut self) -> Result<(), ParseError> {
        self.skip_spaces();
        self.skip_comment();
        match self.peek() {
            None => Ok(()),
            Some(b'\n') => {
                self.position += 1;
                Ok(())
            }
            Some(b'\r') if self.rest().starts_with(b"\r\n") => {
                self.position += 2;
                Ok(())
            }
            Some(_) => Err(self.error("unexpected text after value")),
        }
    }

    fn key_path(&mut self) -> Result<Vec<String>, ParseError> {
        let mut path = Vec::new();
        loop {
            self.skip_spaces();
            path.push(self.key_segment()?);
            self.skip_spaces();
            if !self.eat(b'.') {
                return Ok(path);
            }
        }
    }

    fn key_segment(&mut self) -> Result<String, ParseError> {
        let decoded = match self.peek() {
            Some(b'"') => decode_basic(&self.rest()[1..]),
            Some(b'\'') => decode_literal(&self.rest()[1..]),
            _ => None,
        };
        if let Some((key, consumed)) = decoded {
            self.position += consumed + 1;
            return Ok(key);
        }

        let start = self.position;
        while matches!(
            self.peek(),
            Some(b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-')
        ) {
            self.position += 1;
        }
        if self.position == start {
            return Err(self.error("invalid key"));
        }
        Ok(String::from_utf8_lossy(&self.bytes[start..self.position]).into_owned())
    }

    /// Captures a value up to the end of its line, following arrays and
    /// inline tables across lines and removing comments.
    fn value(&mut self) -> Result<String, ParseError> {
        self.skip_spaces();
        let mut output = Vec::new();
        let mut depth = 0_usize;

        loop {
            match self.peek() {
                None | Some(b'\n' | b'\r') if depth == 0 => break,
                None => return Err(self.error("unterminated array or inline table")),
                Some(b'#') => self.skip_comment(),
                Some(b'"' | b'\'') => self.copy_string(&mut output)?,
                Some(byte @ (b'[' | b'{')) => {
                    depth += 1;
                    output.push(byte);
                    self.position += 1;
                }
                Some(byte @ (b']' | b'}')) => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or_else(|| self.error("unbalanced bracket in value"))?;
                    output.push(byte);
                    self.position += 1;
                }
                Some(byte) => {
                    output.push(byte);
                    self.position += 1;
                }
            }
        }

        let value = String::from_utf8(output).map_err(|_| self.error("invalid UTF-8"))?;
        let value = value.trim();
        if value.is_empty() {
            return Err(self.error("missing value"));
        }
        Ok(value.to_string())
    }

    fn copy_string(&mut self, output: &mut Vec<u8>) -> Result<(), ParseError> {
        let rest = self.rest();
        let (delimiter, multiline): (&[u8], bool) = if rest.starts_with(b"\"\"\"") {
            (b"\"\"\"", true)
        } else if rest.starts_with(b"'''") {
            (b"'''", true)
        } else if rest.starts_with(b"\"") {
            (b"\"", false)
        } else {
            (b"'", false)
        };
        let escapes = delimiter[0] == b'"';

        let mut index = delimiter.len();
        loop {
            let Some(&byte) = rest.get(index) else {
                return Err(self.error("unterminated string"));
            };
            if escapes && byte == b'\\' {
                index += 2;
                continue;
            }
            if !multiline && matches!(byte, b'\n' | b'\r') {
                return Err(self.error("unterminated string"));
            }
            if rest[index..].starts_with(delimiter) {
                index += delimiter.len();
                break;
            }
            index += 1;
        }

        output.extend_from_slice(&rest[..index]);
        self.position += index;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{array_table_items, entries, is_empty_container, string_field, string_value};

    #[test]
    fn reads_tables_array_tables_and_multiline_values() {
        let document = r#"
# comment
title = "demo" # trailing comment

[dependencies]
serde = { version = "1", features = ["derive"] }
"quoted.key" = 'literal # not a comment'

[[package]]
name = "first"
list = [
    "a", # inside an array
    "b]",
]

[[package]]
name = "second"
text = """
multi "line" ]
"""
"#;
        let parsed = entries(document).unwrap();

        assert_eq!(parsed[0].key, ["title"]);
        assert_eq!(string_value(&parsed[0].value).as_deref(), Some("demo"));
        assert_eq!(parsed[1].full_path(), ["dependencies", "serde"]);
        assert_eq!(
            parsed[1].value,
            r#"{ version = "1", features = ["derive"] }"#
        );
        assert_eq!(parsed[2].key, ["quoted.key"]);
        assert_eq!(
            string_value(&parsed[2].value).as_deref(),
            Some("literal # not a comment")
        );

        let packages = array_table_items(&parsed, "package");
        assert_eq!(packages.len(), 2);
        assert_eq!(string_field(&packages[0], "name").as_deref(), Some("first"));
        assert_eq!(
            string_field(&packages[1], "name").as_deref(),
            Some("second")
        );
        assert!(packages[0][1].value.starts_with('['));
        assert!(!is_empty_container(&packages[0][1].value));
    }

    #[test]
    fn decodes_escapes_and_detects_empty_containers() {
        assert_eq!(
            string_value(r#""a\"b\\cé""#).as_deref(),
            Some("a\"b\\c\u{e9}")
        );
        assert_eq!(string_value(r#""unterminated"#), None);
        assert_eq!(string_value(r#""a" "b""#), None);

        assert!(is_empty_container("[]"));
        assert!(is_empty_container("[ , ]"));
        assert!(is_empty_container("{ }"));
        assert!(!is_empty_container(r#"["requests"]"#));
        assert!(!is_empty_container("\"[]\""));
    }

    #[test]
    fn rejects_documents_it_cannot_delimit() {
        for bad in [
            "key = \"unterminated\n",
            "key = [1, 2\n",
            "[table\n",
            "[table] junk\n",
            "= 1\n",
            "key =\n",
            "key = ]\n",
        ] {
            assert!(entries(bad).is_err(), "accepted {bad:?}");
        }
    }
}
