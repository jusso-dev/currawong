//! Staff directory, used to spot mail that borrows a colleague's name.
//! Starts with a CSV import: one `email,name[,vip]` row per person.
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub email: String,
    pub name: String,
    /// Executives and finance staff whose names are most often impersonated.
    pub vip: bool,
}

pub trait Directory: Send + Sync {
    /// People whose display name matches `name` (normalised), in any tenant.
    fn by_name(&self, name: &str) -> Vec<&Person>;
}

/// Invisible format characters that can be slipped inside a word.
fn is_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
    )
}

/// Fold text for matching: drop invisible format characters, map each
/// non-ASCII letter to its UTS 39 confusable skeleton (so Cyrillic `а`, fullwidth `Ｊ`
/// and accented `é` compare equal to `a`, `j` and `e`), keep ASCII digits as
/// they are, lower-case, and turn every run of other characters into one space.
pub fn fold(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut space = true;
    let mut push = |c: char, out: &mut String| {
        if c.is_alphanumeric() {
            out.extend(c.to_lowercase());
            space = false;
        } else if !space {
            out.push(' ');
            space = true;
        }
    };
    let mut buf = [0u8; 4];
    for c in text.chars().filter(|c| !is_format(*c)) {
        // ASCII is kept as it is (skeletons would turn `m` into `rn`); only
        // non-ASCII letters are mapped to their confusable skeleton.
        if c.is_ascii() || c.is_whitespace() {
            push(c, &mut out);
            continue;
        }
        // Lower-case first: skeletons are case-sensitive (`M` and `m` differ).
        for lower in c.to_lowercase() {
            for folded in unicode_security::skeleton(lower.encode_utf8(&mut buf)) {
                for lower in folded.to_lowercase() {
                    push(lower, &mut out);
                }
            }
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// Titles and roles that may decorate a display name.
const TITLES: &[&str] = &[
    "mr",
    "mrs",
    "ms",
    "miss",
    "dr",
    "prof",
    "professor",
    "sir",
    "ceo",
    "cfo",
    "coo",
    "cto",
    "cio",
    "md",
    "gm",
    "director",
    "manager",
    "president",
    "chair",
    "chairman",
    "head",
    "of",
    "finance",
    "accounts",
    "the",
    "office",
];

/// The words of a name worth matching: folded, without titles or initials.
pub fn name_words(name: &str) -> Vec<String> {
    let mut words: Vec<String> = fold(name)
        .split(' ')
        .filter(|w| w.chars().count() > 1 && !TITLES.contains(w))
        .map(str::to_string)
        .collect();
    words.sort();
    words.dedup();
    words
}

/// Order-independent key of a name's words.
pub fn name_key(name: &str) -> String {
    name_words(name).join(" ")
}

#[derive(Debug, Clone, Default)]
pub struct CsvDirectory {
    people: Vec<Person>,
    /// Folded name word -> people whose name contains it.
    by_word: std::collections::HashMap<String, Vec<usize>>,
    words: Vec<Vec<String>>,
}

#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    #[error("{path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("line {line}: {message}")]
    Row { line: usize, message: String },
}

impl CsvDirectory {
    pub fn load(path: &Path) -> Result<Self, DirectoryError> {
        let text = std::fs::read_to_string(path).map_err(|source| DirectoryError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&text)
    }

    /// Blank lines and `#` comments are skipped; a header row starting with
    /// `email` is allowed. Names may be quoted to contain commas.
    pub fn parse(text: &str) -> Result<Self, DirectoryError> {
        let mut people = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields = split_csv(line);
            if index == 0
                && fields
                    .first()
                    .is_some_and(|f| f.eq_ignore_ascii_case("email"))
            {
                continue;
            }
            let row = |message: &str| DirectoryError::Row {
                line: index + 1,
                message: message.into(),
            };
            let email = fields
                .first()
                .map(|f| f.trim().to_ascii_lowercase())
                .unwrap_or_default();
            let name = fields
                .get(1)
                .map(|f| f.trim().to_string())
                .unwrap_or_default();
            if !email.contains('@') {
                return Err(row("email is missing"));
            }
            if name_key(&name).is_empty() {
                return Err(row("name is missing"));
            }
            let vip = match fields.get(2).map(|f| f.trim().to_ascii_lowercase()) {
                None => false,
                Some(v) if v.is_empty() || v == "false" || v == "no" || v == "0" => false,
                Some(v) if v == "true" || v == "yes" || v == "1" || v == "vip" => true,
                Some(_) => return Err(row("vip must be true or false")),
            };
            people.push(Person { email, name, vip });
        }
        let mut directory = Self {
            people,
            ..Self::default()
        };
        for (index, person) in directory.people.iter().enumerate() {
            let words = name_words(&person.name);
            for word in &words {
                directory
                    .by_word
                    .entry(word.clone())
                    .or_default()
                    .push(index);
            }
            directory.words.push(words);
        }
        Ok(directory)
    }

    pub fn people(&self) -> &[Person] {
        &self.people
    }
}

impl Directory for CsvDirectory {
    /// People whose name words (at least two, ignoring titles and initials)
    /// all appear in `name`, so `Dr Jane A. Smith - CEO` matches `Jane Smith`.
    fn by_name(&self, name: &str) -> Vec<&Person> {
        let shown = name_words(name);
        let mut found: Vec<usize> = shown
            .iter()
            .filter_map(|word| self.by_word.get(word))
            .flatten()
            .copied()
            .filter(|index| {
                let words = &self.words[*index];
                words.len() >= 2 && words.iter().all(|w| shown.contains(w))
            })
            .collect();
        found.sort_unstable();
        found.dedup();
        found.into_iter().map(|index| &self.people[index]).collect()
    }
}

fn split_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    fields.push(current);
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_directory_matches_names_in_any_order() {
        let directory = CsvDirectory::parse(
            "email,name,vip\n# staff\njane.smith@acme.test,\"Smith, Jane\",true\nbob@acme.test,Bob Jones\n",
        )
        .unwrap();
        assert_eq!(directory.people().len(), 2);
        assert_eq!(
            directory.by_name("Jane Smith")[0].email,
            "jane.smith@acme.test"
        );
        assert_eq!(directory.by_name("jane SMITH (CEO)").len(), 1);
        assert!(directory.by_name("Janet Smith").is_empty());
        for disguised in [
            "Jane Smith - CEO",
            "Jane Smith, CEO",
            "Jane A. Smith",
            "Dr Jane Smith",
            "J\u{0430}ne Smith",
            "\u{FF2A}ane Smith",
            "Jan\u{00E9} Smith",
            "Ja\u{200B}ne Smith",
        ] {
            assert_eq!(directory.by_name(disguised).len(), 1, "{disguised}");
        }
        // One shared word is not enough.
        assert!(directory.by_name("Jane Doe").is_empty());
        assert!(directory.by_name("").is_empty());
        assert!(directory.people()[0].vip && !directory.people()[1].vip);
        assert!(CsvDirectory::parse("no-at-sign,Name\n").is_err());
        assert!(CsvDirectory::parse("a@b.test,\n").is_err());
        assert!(CsvDirectory::parse("a@b.test,A,maybe\n").is_err());
    }
}
