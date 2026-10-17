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
        check_id(id)?;
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

    /// BIMI logo and VMC status for the quarantine UI, as JSON.
    pub fn set_bimi(&self, id: &str, json: &str) -> std::io::Result<()> {
        check_id(id)?;
        let dir = self.root.join(id);
        let tmp = dir.join("bimi.json.tmp");
        fs::write(&tmp, json)?;
        fs::rename(tmp, dir.join("bimi.json"))
    }

    pub fn bimi(&self, id: &str) -> std::io::Result<Option<String>> {
        check_id(id)?;
        match fs::read_to_string(self.root.join(id).join("bimi.json")) {
            Ok(json) => Ok(Some(json)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }
}

fn check_id(id: &str) -> std::io::Result<()> {
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
    Ok(())
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
        assert_eq!(store.bimi(id).unwrap(), None);
        store.set_bimi(id, "{}").unwrap();
        assert_eq!(store.bimi(id).unwrap().as_deref(), Some("{}"));
        assert!(store.set_bimi("../../etc/passwd", "{}").is_err());
    }
}
