//! The sqns directory: where it is, and that it is not readable by anyone else.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use sqns_core::key::{self, HOME_ENV};

/// Both assertions live in one test on purpose: the environment is
/// process-global, so two tests setting `SQNS_HOME` in parallel would race.
#[test]
fn the_directory_is_relocatable_and_kept_private() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("sqns-home");

    // SAFETY: single-threaded test, and this is the only test touching the var.
    unsafe { std::env::set_var(HOME_ENV, &home) };

    assert_eq!(key::sqns_dir().unwrap(), home);
    assert!(!home.exists(), "reading the path must not create it");

    let created = key::ensure_sqns_dir().unwrap();
    assert_eq!(created, home);
    assert_eq!(
        fs::metadata(&home).unwrap().permissions().mode() & 0o777,
        0o700
    );

    // A directory that already exists with loose permissions is corrected,
    // because this is where private keys go.
    fs::set_permissions(&home, fs::Permissions::from_mode(0o755)).unwrap();
    key::ensure_sqns_dir().unwrap();
    assert_eq!(
        fs::metadata(&home).unwrap().permissions().mode() & 0o777,
        0o700,
        "permissions must be re-applied to a directory that already existed"
    );

    assert_eq!(key::default_path("identity.key").unwrap(), home.join("identity.key"));

    // SAFETY: as above.
    unsafe { std::env::remove_var(HOME_ENV) };
}

#[test]
fn a_key_written_into_the_directory_is_private() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.key");
    key::save_secret_file(&path, &key::generate()).unwrap();

    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    key::load_secret_file(&path).expect("loads back");

    // And a key anyone could read is refused rather than used.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(key::load_secret_file(&path).is_err());
}
