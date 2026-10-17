//! On-disk quarantine. Release and digests are M2.
use std::{fs, io::Write, path::PathBuf};

#[derive(Debug, Clone)]
pub struct QuarantineStore {
    root: PathBuf,
}

impl QuarantineStore {
    pub fn open(root: impl Into<PathBuf>) -> std::io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn hold(&self, id: &str, reason: &str, raw: &[u8]) -> std::io::Result<PathBuf> {
        if id.len() != 26
            || !id
                .chars()
                .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unsafe quarantine id",
            ));
        }
        let dir = self.root.join(id);
        fs::create_dir_all(&dir)?;
        let eml = dir.join("message.eml");
        let mut file = fs::File::create(&eml)?;
        file.write_all(raw)?;
        file.sync_all()?;
        fs::write(dir.join("reason.txt"), reason)?;
        Ok(eml)
    }

    pub fn reason(&self, id: &str) -> std::io::Result<String> {
        fs::read_to_string(self.root.join(id).join("reason.txt"))
    }
}

#[cfg(test)]
mod tests {
    use super::QuarantineStore;

    #[test]
    fn hold_writes_the_message_and_reason() {
        let dir = tempfile::tempdir().unwrap();
        let store = QuarantineStore::open(dir.path()).unwrap();
        let id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        store
            .hold(id, "malware", b"From: a@example.test\r\n\r\n")
            .unwrap();
        assert_eq!(store.reason(id).unwrap(), "malware");
    }
}
