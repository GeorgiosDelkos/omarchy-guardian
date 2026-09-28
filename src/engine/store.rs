//! The review memory's store under the user's state directory:
//! content-addressed blobs, baseline manifests and cached verdicts. Only
//! user-level classes use it; the root pacman gate never opens it.

use std::env;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{Error, IoContext};
use crate::sha256::Sha256;

pub const BLOBS: &str = "blobs";
pub const BASELINES: &str = "baselines";
pub const VERDICTS: &str = "verdicts";

const TEMP_PREFIX: &str = ".tmp-";

pub struct Store {
    root: PathBuf,
}

impl Store {
    /// `$XDG_STATE_HOME/omarchy-guardian`, else `~/.local/state/omarchy-guardian`.
    pub fn default_root() -> Option<PathBuf> {
        let base = env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| {
                env::var_os("HOME")
                    .map(PathBuf::from)
                    .filter(|path| path.is_absolute())
                    .map(|home| home.join(".local").join("state"))
            })?;
        Some(base.join("omarchy-guardian"))
    }

    /// Opens the store, creating it with mode 0700. A store owned by another
    /// user, or open to group or others, is refused: whoever can write it
    /// can plant cached verdicts.
    pub fn open(root: PathBuf) -> Result<Self, String> {
        let describe = |path: &Path, error: io::Error| format!("{}: {error}", path.display());
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)
            .map_err(|error| describe(&root, error))?;

        let uid = effective_uid()?;
        let metadata = fs::symlink_metadata(&root).map_err(|error| describe(&root, error))?;
        if !metadata.file_type().is_dir() {
            return Err(format!("{} is not a directory", root.display()));
        }
        if metadata.uid() != uid {
            return Err(format!(
                "{} is owned by uid {}, not {uid}",
                root.display(),
                metadata.uid()
            ));
        }
        if metadata.mode() & 0o077 != 0 {
            return Err(format!(
                "{} is accessible to group or others",
                root.display()
            ));
        }

        for name in [BLOBS, BASELINES, VERDICTS] {
            let path = root.join(name);
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(describe(&path, error)),
            }
            if !fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_dir()) {
                return Err(format!("{} is not a directory", path.display()));
            }
        }
        Ok(Self { root })
    }

    fn path(&self, dir: &str, name: &str) -> PathBuf {
        self.root.join(dir).join(name)
    }

    /// Writes through a new temporary file in the same directory, then
    /// renames it into place, so a reader never sees half a file.
    pub fn write(&self, dir: &str, name: &str, bytes: &[u8]) -> Result<(), Error> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let target = self.path(dir, name);
        let temp = self.path(
            dir,
            &format!(
                "{TEMP_PREFIX}{}-{}",
                process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ),
        );

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .at(&temp)?;
        let written = file.write_all(bytes).and_then(|()| file.sync_all());
        drop(file);
        if let Err(source) = written.and_then(|()| fs::rename(&temp, &target)) {
            drop(fs::remove_file(&temp));
            return Err(Error::Io {
                path: target,
                source,
            });
        }
        Ok(())
    }

    pub fn read(&self, dir: &str, name: &str) -> Result<Option<Vec<u8>>, Error> {
        let path = self.path(dir, name);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(Error::Io { path, source }),
        }
    }

    pub fn remove(&self, dir: &str, name: &str) -> Result<(), Error> {
        let path = self.path(dir, name);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(Error::Io { path, source }),
        }
    }

    /// Entry names in one of the store's directories, sorted, leaving out
    /// temporary files.
    pub fn list(&self, dir: &str) -> Result<Vec<String>, Error> {
        let path = self.root.join(dir);
        let mut names = Vec::new();
        for entry in fs::read_dir(&path).at(&path)? {
            let entry = entry.at(&path)?;
            if let Some(name) = entry
                .file_name()
                .to_str()
                .filter(|name| !name.starts_with(TEMP_PREFIX))
            {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Total bytes of the store's files.
    pub fn size(&self) -> Result<u64, Error> {
        let mut total = 0;
        for dir in [BLOBS, BASELINES, VERDICTS] {
            for name in self.list(dir)? {
                let path = self.path(dir, &name);
                match fs::symlink_metadata(&path) {
                    Ok(metadata) => total += metadata.len(),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(source) => return Err(Error::Io { path, source }),
                }
            }
        }
        Ok(total)
    }

    /// Stores `bytes` under their SHA-256 and returns the hex digest.
    pub fn put_blob(&self, bytes: &[u8]) -> Result<String, Error> {
        let digest = Sha256::digest(bytes).to_string();
        if !self.path(BLOBS, &digest).exists() {
            self.write(BLOBS, &digest, bytes)?;
        }
        Ok(digest)
    }

    /// The blob with this digest, or `None` when it is missing or no longer
    /// matches its digest; a corrupt blob is deleted.
    pub fn get_blob(&self, digest: &str) -> Result<Option<Vec<u8>>, Error> {
        if !is_hex_digest(digest) {
            return Ok(None);
        }
        let Some(bytes) = self.read(BLOBS, digest)? else {
            return Ok(None);
        };
        if Sha256::digest(&bytes).to_string() == digest {
            Ok(Some(bytes))
        } else {
            self.remove(BLOBS, digest)?;
            Ok(None)
        }
    }
}

/// A lowercase hex SHA-256 digest, the only names blobs and verdicts use.
pub fn is_hex_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A read-only summary for `config show`: the number of baselines and the
/// store's bytes, or `None` when there is no store yet.
pub fn summary(root: &Path) -> Option<(usize, u64)> {
    if !root.is_dir() {
        return None;
    }
    let store = Store {
        root: root.to_path_buf(),
    };
    Some((
        store.list(BASELINES).map_or(0, |names| names.len()),
        store.size().unwrap_or(0),
    ))
}

/// The effective user id, from `/proc/self/status` (`Uid: real effective saved fs`).
fn effective_uid() -> Result<u32, String> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("/proc/self/status: {error}"))?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|ids| ids.split_whitespace().nth(1))
        .and_then(|id| id.parse().ok())
        .ok_or_else(|| "cannot read the effective user id".to_string())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::{BASELINES, BLOBS, Store, VERDICTS, is_hex_digest, summary};
    use crate::test_support::TempDir;

    #[test]
    fn opening_creates_private_directories() {
        let dir = TempDir::new("store-open");
        let root = dir.path().join("state").join("omarchy-guardian");
        Store::open(root.clone()).unwrap();

        for path in [
            root.clone(),
            root.join(BLOBS),
            root.join(BASELINES),
            root.join(VERDICTS),
        ] {
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", path.display());
        }
    }

    #[test]
    fn a_store_open_to_others_is_refused() {
        let dir = TempDir::new("store-mode");
        let root = dir.path().join("store");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();

        let error = Store::open(root).err().unwrap();
        assert!(error.contains("group or others"), "{error}");
    }

    #[test]
    fn writes_are_atomic_and_private() {
        let dir = TempDir::new("store-write");
        let store = Store::open(dir.path().join("store")).unwrap();

        store.write(VERDICTS, "k", b"one").unwrap();
        store.write(VERDICTS, "k", b"two").unwrap();

        assert_eq!(
            store.read(VERDICTS, "k").unwrap().as_deref(),
            Some(&b"two"[..])
        );
        assert_eq!(store.read(VERDICTS, "missing").unwrap(), None);
        assert_eq!(store.list(VERDICTS).unwrap(), ["k"]);
        let mode = fs::metadata(dir.path().join("store").join(VERDICTS).join("k"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        store.remove(VERDICTS, "k").unwrap();
        store.remove(VERDICTS, "k").unwrap();
        assert!(store.list(VERDICTS).unwrap().is_empty());
    }

    #[test]
    fn blobs_are_addressed_by_content_and_corrupt_ones_are_dropped() {
        let dir = TempDir::new("store-blob");
        let store = Store::open(dir.path().join("store")).unwrap();

        let digest = store.put_blob(b"hello\n").unwrap();
        assert!(is_hex_digest(&digest));
        assert_eq!(store.put_blob(b"hello\n").unwrap(), digest);
        assert_eq!(
            store.get_blob(&digest).unwrap().as_deref(),
            Some(&b"hello\n"[..])
        );

        fs::write(
            dir.path().join("store").join(BLOBS).join(&digest),
            "tampered",
        )
        .unwrap();
        assert_eq!(store.get_blob(&digest).unwrap(), None);
        assert!(store.list(BLOBS).unwrap().is_empty());

        assert_eq!(store.get_blob("../../etc/passwd").unwrap(), None);
    }

    #[test]
    fn size_and_summary_count_the_stores_files() {
        let dir = TempDir::new("store-size");
        let root = dir.path().join("store");
        assert_eq!(summary(&root), None);

        let store = Store::open(root.clone()).unwrap();
        store.write(BASELINES, "aur.x", b"12345").unwrap();
        store.put_blob(b"abc").unwrap();

        assert_eq!(store.size().unwrap(), 8);
        assert_eq!(summary(&root), Some((1, 8)));
    }

    #[test]
    fn default_root_uses_home_or_xdg_state_home() {
        if let Some(root) = Store::default_root() {
            assert!(root.ends_with("omarchy-guardian"));
        }
    }
}
