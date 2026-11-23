//! Files that hold secrets: private to their owner, checked when read.

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use nostr_sdk::{Keys, ToBech32};

use crate::error::{Error, Result};

/// Read a file that must be private to its owner; `None` if it does not
/// exist. Permissions are read from the open handle, so the file that is
/// checked is the file that is read.
pub fn read_private(path: &Path) -> Result<Option<String>> {
    match fs::File::open(path) {
        Ok(mut file) => {
            if file.metadata()?.permissions().mode() & 0o077 != 0 {
                return Err(Error::Config(format!(
                    "{} is accessible by other users; run: chmod 600 {}",
                    path.display(),
                    path.display()
                )));
            }
            let mut text = String::new();
            file.read_to_string(&mut text)?;
            Ok(Some(text))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Create an owner-only file holding `content`; refuses to replace one.
/// Synced to disk, so a secret survives a crash right after it is made.
pub fn create_private(path: &Path, content: &str) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

/// Load the server identity, creating it on first start. The file must be
/// private to the owner; a key readable by others is refused.
pub fn load_or_create_keys(path: &Path) -> Result<Keys> {
    if let Some(text) = read_private(path)? {
        return Keys::parse(text.trim())
            .map_err(|_| Error::Config(format!("{} does not contain a nostr secret key", path.display())));
    }
    let keys = Keys::generate();
    let nsec = keys
        .secret_key()
        .to_bech32()
        .expect("a valid secret key always encodes as bech32");
    create_private(path, &nsec)?;
    Ok(keys)
}

/// Create a directory if needed and make it private to the owner.
pub fn open_dir(dir: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .and_then(|()| fs::set_permissions(dir, fs::Permissions::from_mode(0o700)))
        .map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_private_file_is_created_once_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        assert_eq!(read_private(&path).unwrap(), None);
        create_private(&path, "words").unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(read_private(&path).unwrap().as_deref(), Some("words"));
        // It is never replaced.
        assert!(matches!(create_private(&path, "other"), Err(Error::Io(_))));
        assert_eq!(read_private(&path).unwrap().as_deref(), Some("words"));
    }

    #[test]
    fn a_file_others_can_read_is_refused_with_the_fix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        create_private(&path, "words").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let e = read_private(&path).unwrap_err();
        assert_eq!(
            e.to_string(),
            format!(
                "invalid configuration: {} is accessible by other users; run: chmod 600 {}",
                path.display(),
                path.display()
            )
        );
        // Something that cannot be opened as a file, or is not text, is an io error.
        assert!(matches!(read_private(&dir.path().join("secret/x")), Err(Error::Io(_))));
        let raw = dir.path().join("raw");
        create_private(&raw, "").unwrap();
        fs::write(&raw, [0xff, 0xfe]).unwrap();
        assert!(matches!(read_private(&raw), Err(Error::Io(_))));
    }

    #[test]
    fn the_service_key_is_made_once_kept_private_and_checked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.nsec");
        let created = load_or_create_keys(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        assert!(fs::read_to_string(&path).unwrap().starts_with("nsec1"));
        assert_eq!(load_or_create_keys(&path).unwrap().public_key(), created.public_key());

        fs::write(&path, "not a key").unwrap();
        assert_eq!(
            load_or_create_keys(&path).unwrap_err().to_string(),
            format!(
                "invalid configuration: {} does not contain a nostr secret key",
                path.display()
            )
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_or_create_keys(&path)
            .unwrap_err()
            .to_string()
            .contains("chmod 600"));
        // Nowhere to create it.
        assert!(matches!(
            load_or_create_keys(&dir.path().join("missing/key")),
            Err(Error::Io(_))
        ));
    }

    #[test]
    fn a_directory_is_made_private_whether_new_or_not() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b");
        open_dir(&nested).unwrap();
        assert_eq!(mode(&nested), 0o700);
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o755)).unwrap();
        open_dir(&nested).unwrap();
        assert_eq!(mode(&nested), 0o700);
        // A file is in the way.
        fs::write(dir.path().join("file"), "x").unwrap();
        assert!(matches!(open_dir(&dir.path().join("file/sub")), Err(Error::Io(_))));
    }
}
