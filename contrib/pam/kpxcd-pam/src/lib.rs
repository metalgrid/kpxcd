//! PAM handoff module for kpxcd.
//!
//! The module intentionally does not contact the daemon. It captures the login
//! token during authentication, then writes it during open_session after
//! pam_systemd has created XDG_RUNTIME_DIR.

use libc::{c_char, c_int, c_void, gid_t, mode_t, uid_t};
use std::ffi::{CStr, CString};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::prelude::AsRawFd;
use std::path::PathBuf;
use std::ptr;

const PAM_SUCCESS: c_int = 0;
const PAM_AUTH_ERR: c_int = 7;
const PAM_SESSION_ERR: c_int = 14;
const PAM_BUF_ERR: c_int = 5;
const PAM_AUTHTOK: c_int = 6;
const DATA_NAME: &[u8] = b"kpxcd.authtok\0";
const DEFAULT_TOKEN_NAME: &str = "pam-token";

#[repr(C)]
pub struct PamHandle(c_void);

type CleanupFn = unsafe extern "C" fn(*mut PamHandle, *mut c_void, c_int);

extern "C" {
    fn pam_get_authtok(
        pamh: *mut PamHandle,
        item: c_int,
        authtok: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
    fn pam_set_data(
        pamh: *mut PamHandle,
        module_data_name: *const c_char,
        data: *mut c_void,
        cleanup: Option<CleanupFn>,
    ) -> c_int;
    fn pam_get_data(
        pamh: *const PamHandle,
        module_data_name: *const c_char,
        data: *mut *const c_void,
    ) -> c_int;
    fn pam_get_user(
        pamh: *mut PamHandle,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
    fn pam_getenv(pamh: *mut PamHandle, name: *const c_char) -> *const c_char;

    fn getpwnam(name: *const c_char) -> *mut Passwd;
    fn fchown(fd: c_int, owner: uid_t, group: gid_t) -> c_int;
    fn chmod(path: *const c_char, mode: mode_t) -> c_int;
    fn chown(path: *const c_char, owner: uid_t, group: gid_t) -> c_int;
}

#[repr(C)]
struct Passwd {
    pw_name: *mut c_char,
    pw_passwd: *mut c_char,
    pw_uid: uid_t,
    pw_gid: gid_t,
    pw_gecos: *mut c_char,
    pw_dir: *mut c_char,
    pw_shell: *mut c_char,
}

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

unsafe extern "C" fn cleanup_token(_pamh: *mut PamHandle, data: *mut c_void, _error_status: c_int) {
    if !data.is_null() {
        drop(Box::from_raw(data as *mut Token));
    }
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let mut authtok: *const c_char = ptr::null();
    let rc = pam_get_authtok(pamh, PAM_AUTHTOK, &mut authtok, ptr::null());
    if rc != PAM_SUCCESS {
        return rc;
    }
    if authtok.is_null() {
        return PAM_AUTH_ERR;
    }

    let bytes = CStr::from_ptr(authtok).to_bytes().to_vec();
    let token = Box::new(Token { bytes });
    let rc = pam_set_data(
        pamh,
        DATA_NAME.as_ptr() as *const c_char,
        Box::into_raw(token) as *mut c_void,
        Some(cleanup_token),
    );
    if rc == PAM_SUCCESS {
        PAM_SUCCESS
    } else {
        PAM_BUF_ERR
    }
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let mut data: *const c_void = ptr::null();
    let rc = pam_get_data(pamh, DATA_NAME.as_ptr() as *const c_char, &mut data);
    if rc != PAM_SUCCESS || data.is_null() {
        // Do not fail login if no token is available. kpxcd will simply skip
        // PAM auto-unlock for this session.
        return PAM_SUCCESS;
    }
    let token = &*(data as *const Token);

    match write_token(pamh, &token.bytes) {
        Ok(()) => PAM_SUCCESS,
        Err(_) => PAM_SESSION_ERR,
    }
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_close_session(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

unsafe fn write_token(pamh: *mut PamHandle, token: &[u8]) -> Result<(), ()> {
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
    if fchown(file.as_raw_fd(), uid, gid) != 0 {
        return Err(());
    }
    file.write_all(token).map_err(|_| ())?;
    file.sync_all().map_err(|_| ())?;
    drop(file);
    chmod_path(&path, 0o600)?;
    Ok(())
}

unsafe fn user_ids(pamh: *mut PamHandle) -> Result<(uid_t, gid_t), ()> {
    let mut user: *const c_char = ptr::null();
    if pam_get_user(pamh, &mut user, ptr::null()) != PAM_SUCCESS || user.is_null() {
        return Err(());
    }
    let pw = getpwnam(user);
    if pw.is_null() {
        return Err(());
    }
    Ok(((*pw).pw_uid, (*pw).pw_gid))
}

unsafe fn runtime_dir(pamh: *mut PamHandle, uid: uid_t) -> Result<PathBuf, ()> {
    let name = CString::new("XDG_RUNTIME_DIR").map_err(|_| ())?;
    let value = pam_getenv(pamh, name.as_ptr());
    if !value.is_null() {
        let s = CStr::from_ptr(value).to_string_lossy().into_owned();
        if !s.is_empty() {
            return Ok(PathBuf::from(s));
        }
    }
    Ok(PathBuf::from(format!("/run/user/{uid}")))
}

unsafe fn chown_path(path: &PathBuf, uid: uid_t, gid: gid_t) -> Result<(), ()> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| ())?;
    if chown(c.as_ptr(), uid, gid) == 0 {
        Ok(())
    } else {
        Err(())
    }
}

unsafe fn chmod_path(path: &PathBuf, mode: mode_t) -> Result<(), ()> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| ())?;
    if chmod(c.as_ptr(), mode) == 0 {
        Ok(())
    } else {
        Err(())
    }
}
