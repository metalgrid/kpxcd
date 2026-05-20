//! PAM handoff module for kpxcd.
//!
//! The module intentionally does not contact the daemon. It captures the login
//! token during authentication, then writes it during open_session after
//! pam_systemd has created XDG_RUNTIME_DIR.

use pamsm::{Pam, PamData, PamError, PamFlags, PamLibExt, PamServiceModule};
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::prelude::AsRawFd;
use std::path::{Path, PathBuf};

const DATA_NAME: &str = "kpxcd.authtok";
const DEFAULT_TOKEN_NAME: &str = "pam-token";

/// A token whose bytes are zeroed on drop.
#[derive(Clone)]
struct Token {
    bytes: Vec<u8>,
}

impl Drop for Token {
    fn drop(&mut self) {
        for b in &mut self.bytes {
            *b = 0;
        }
    }
}

impl PamData for Token {}

struct PamKpxcd;

impl PamServiceModule for PamKpxcd {
    fn authenticate(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        let bytes = match pamh.get_authtok(None) {
            Ok(Some(tok)) => tok.to_bytes().to_vec(),
            Ok(None) => return PamError::AUTH_ERR,
            Err(e) => return e,
        };

        let token = Token { bytes };
        match unsafe { pamh.send_data(DATA_NAME, token) } {
            Ok(()) => PamError::SUCCESS,
            Err(e) => e,
        }
    }

    fn setcred(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn open_session(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        let token: Token = match unsafe { pamh.retrieve_data(DATA_NAME) } {
            Ok(t) => t,
            // Do not fail login if no token is available. kpxcd will simply
            // skip PAM auto-unlock for this session.
            Err(_) => return PamError::SUCCESS,
        };

        match write_token(&pamh, &token.bytes) {
            Ok(()) => PamError::SUCCESS,
            Err(_) => PamError::SESSION_ERR,
        }
    }

    fn close_session(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
}

fn write_token(pamh: &Pam, token: &[u8]) -> Result<(), ()> {
    let (uid, gid) = user_ids(pamh)?;
    let runtime = runtime_dir(pamh, uid)?;
    let dir = runtime.join("kpxcd");
    let path = dir.join(DEFAULT_TOKEN_NAME);

    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|_| ())?;
    chown_path(&dir, uid, gid)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(|_| ())?;

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| ())?;
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(());
    }
    file.write_all(token).map_err(|_| ())?;
    file.sync_all().map_err(|_| ())?;
    drop(file);
    chmod_path(&path, 0o600)?;
    Ok(())
}

fn user_ids(pamh: &Pam) -> Result<(libc::uid_t, libc::gid_t), ()> {
    let user = pamh.get_user(None).map_err(|_| ())?.ok_or(())?;
    let pw = unsafe { libc::getpwnam(user.as_ptr()) };
    if pw.is_null() {
        return Err(());
    }
    unsafe { Ok(((*pw).pw_uid, (*pw).pw_gid)) }
}

fn runtime_dir(pamh: &Pam, uid: libc::uid_t) -> Result<PathBuf, ()> {
    if let Ok(Some(value)) = pamh.getenv("XDG_RUNTIME_DIR") {
        let s = value.to_string_lossy().into_owned();
        if !s.is_empty() {
            return Ok(PathBuf::from(s));
        }
    }
    Ok(PathBuf::from(format!("/run/user/{uid}")))
}

fn chown_path(path: &Path, uid: libc::uid_t, gid: libc::gid_t) -> Result<(), ()> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| ())?;
    if unsafe { libc::chown(c.as_ptr(), uid, gid) } == 0 {
        Ok(())
    } else {
        Err(())
    }
}

fn chmod_path(path: &Path, mode: libc::mode_t) -> Result<(), ()> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| ())?;
    if unsafe { libc::chmod(c.as_ptr(), mode) } == 0 {
        Ok(())
    } else {
        Err(())
    }
}

pamsm::pam_module!(PamKpxcd);
