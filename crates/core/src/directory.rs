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

/// Lower case, letters and digits only, single spaces: `"Smith, Jane (CEO)"`
/// and `"jane smith"` normalise differently, so names are also compared
/// with their words sorted (see `name_key`).
pub fn normalise_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect();
    cleaned.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Order-independent key, so `Smith, Jane` matches `Jane Smith`. Words in
/// brackets such as a title are dropped first.
pub fn name_key(name: &str) -> String {
    let mut depth = 0usize;
    let without_brackets: String = name
        .chars()
        .filter(|c| match c {
            '(' | '[' => {
                depth += 1;
                false
            }
            ')' | ']' => {
                depth = depth.saturating_sub(1);
                false
            }
            _ => depth == 0,
        })
        .collect();
    let mut words: Vec<String> = normalise_name(&without_brackets)
        .split(' ')
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect();
    words.sort();
    words.join(" ")
}

#[derive(Debug, Clone, Default)]
pub struct CsvDirectory {
    people: Vec<Person>,
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
        Ok(Self { people })
    }

    pub fn people(&self) -> &[Person] {
        &self.people
    }
}

impl Directory for CsvDirectory {
    fn by_name(&self, name: &str) -> Vec<&Person> {
        let key = name_key(name);
        if key.is_empty() {
            return Vec::new();
        }
        self.people
            .iter()
            .filter(|person| name_key(&person.name) == key)
            .collect()
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
        assert!(directory.by_name("").is_empty());
        assert!(directory.people()[0].vip && !directory.people()[1].vip);
        assert!(CsvDirectory::parse("no-at-sign,Name\n").is_err());
        assert!(CsvDirectory::parse("a@b.test,\n").is_err());
        assert!(CsvDirectory::parse("a@b.test,A,maybe\n").is_err());
    }
}
