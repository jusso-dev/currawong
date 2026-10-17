//! Writing the config and certificate. Files are created 0640 and handed to
//! the `currawong` group before they are renamed into place, so a key or
//! config is never world-readable, not even briefly.
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const CONFIG_FILE: &str = "currawong.toml";
pub const CERT_FILE: &str = "cert.pem";
pub const KEY_FILE: &str = "key.pem";
const MODE: u32 = 0o640;
const CERT_DAYS: i64 = 825;

/// gid of `name` from an `/etc/group`-format file.
pub fn group_id(group_file: &Path, name: &str) -> Option<u32> {
    let text = fs::read_to_string(group_file).ok()?;
    text.lines().find_map(|line| {
        let mut parts = line.split(':');
        if parts.next()? != name {
            return None;
        }
        parts.nth(1)?.parse().ok()
    })
}

/// Write `bytes` to a hidden temporary file next to `dest`, mode 0640,
/// fsynced, group `gid`. Returns the temporary path.
fn stage(dest: &Path, bytes: &[u8], gid: Option<u32>) -> Result<PathBuf, String> {
    let dir = dest.parent().ok_or("destination has no directory")?;
    let name = dest.file_name().ok_or("destination has no file name")?;
    let tmp = dir.join(format!(".{}.tmp", name.to_string_lossy()));
    let _ = fs::remove_file(&tmp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(MODE)
        .open(&tmp)
        .map_err(|err| format!("{}: {err}", tmp.display()))?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(MODE))?;
        if let Some(gid) = gid {
            std::os::unix::fs::chown(&tmp, None, Some(gid))?;
        }
        Ok::<_, std::io::Error>(())
    })();
    if let Err(err) = result {
        let _ = fs::remove_file(&tmp);
        return Err(format!("{}: {err}", tmp.display()));
    }
    Ok(tmp)
}

fn commit(tmp: &Path, dest: &Path) -> Result<(), String> {
    fs::rename(tmp, dest).map_err(|err| format!("{}: {err}", dest.display()))?;
    if let Some(dir) = dest.parent() {
        if let Ok(dir) = fs::File::open(dir) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Run `currawongd --config PATH --check-config`.
pub fn check_config(currawongd: &Path, path: &Path) -> Result<(), String> {
    let output = Command::new(currawongd)
        .arg("--config")
        .arg(path)
        .arg("--check-config")
        .output()
        .map_err(|err| format!("{}: {err}", currawongd.display()))?;
    if output.status.success() {
        return Ok(());
    }
    let mut text = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if text.is_empty() {
        text = format!("check-config exited with {}", output.status);
    }
    Err(text)
}

/// Stage the config, check it with currawongd, then move it into place.
/// A rejected config leaves the existing file untouched.
pub fn install_config(
    conf_dir: &Path,
    toml: &str,
    gid: Option<u32>,
    currawongd: &Path,
) -> Result<PathBuf, String> {
    let dest = conf_dir.join(CONFIG_FILE);
    let tmp = stage(&dest, toml.as_bytes(), gid)?;
    if let Err(err) = check_config(currawongd, &tmp) {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    commit(&tmp, &dest)?;
    Ok(dest)
}

pub fn cert_exists(conf_dir: &Path) -> bool {
    conf_dir.join(CERT_FILE).exists() || conf_dir.join(KEY_FILE).exists()
}

/// Self-signed P-256 certificate for `hostname`, valid for 825 days, so the
/// STARTTLS listeners start. Replace it with a CA-issued certificate.
pub fn write_self_signed(conf_dir: &Path, hostname: &str, gid: Option<u32>) -> Result<(), String> {
    let key = rcgen::KeyPair::generate().map_err(|err| err.to_string())?;
    let mut params =
        rcgen::CertificateParams::new(vec![hostname.to_string()]).map_err(|err| err.to_string())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, hostname);
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(CERT_DAYS);
    let cert = params.self_signed(&key).map_err(|err| err.to_string())?;
    let key_dest = conf_dir.join(KEY_FILE);
    let cert_dest = conf_dir.join(CERT_FILE);
    let key_tmp = stage(&key_dest, key.serialize_pem().as_bytes(), gid)?;
    let cert_tmp = match stage(&cert_dest, cert.pem().as_bytes(), gid) {
        Ok(tmp) => tmp,
        Err(err) => {
            let _ = fs::remove_file(&key_tmp);
            return Err(err);
        }
    };
    commit(&key_tmp, &key_dest)?;
    commit(&cert_tmp, &cert_dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn group_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("group");
        fs::write(&file, "root:x:0:\ncurrawong:x:998:\nmail:x:8:\n").unwrap();
        assert_eq!(group_id(&file, "currawong"), Some(998));
        assert_eq!(group_id(&file, "nobody"), None);
    }

    #[test]
    fn installs_config_0640_when_check_passes() {
        let dir = tempfile::tempdir().unwrap();
        let path = install_config(dir.path(), "a = 1\n", None, Path::new("/usr/bin/true")).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "a = 1\n");
        assert_eq!(mode(&path), 0o640);
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no temp file left"
        );
    }

    #[test]
    fn rejected_config_leaves_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join(CONFIG_FILE);
        fs::write(&dest, "old\n").unwrap();
        let err = install_config(dir.path(), "new\n", None, Path::new("/usr/bin/false"));
        assert!(err.is_err());
        assert_eq!(fs::read_to_string(&dest).unwrap(), "old\n");
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no temp file left"
        );
    }

    #[test]
    fn missing_currawongd_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = install_config(
            dir.path(),
            "x\n",
            None,
            Path::new("/nonexistent/currawongd"),
        )
        .unwrap_err();
        assert!(err.contains("/nonexistent/currawongd"));
    }

    #[test]
    fn certificate_is_private_and_loads_in_the_daemon() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!cert_exists(dir.path()));
        write_self_signed(dir.path(), "gw.example.test", None).unwrap();
        assert!(cert_exists(dir.path()));
        let key = dir.path().join(KEY_FILE);
        let cert = dir.path().join(CERT_FILE);
        assert_eq!(mode(&key), 0o640);
        assert_eq!(mode(&cert), 0o640);
        assert!(fs::read_to_string(&key).unwrap().contains("PRIVATE KEY"));
        currawong_smtp::tls::TlsManager::load(&cert, &key).unwrap();
    }
}
