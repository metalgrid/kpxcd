//! PAM handoff module for kpxcd.
//!
//! The module does **not** write any credentials to disk. It captures the login
//! password during PAM authentication, derives a kpxcd-specific token via
//! HKDF-SHA256, and sends that derived token to the kpxcd daemon over a Unix
//! domain socket during open_session (after pam_systemd has created
//! XDG_RUNTIME_DIR).
//!
//! Because the raw password is never written to the filesystem and the derived
//! token is useless for anything other than unwrapping the local kpxcd age
//! identity, this approach avoids exposing the user's Unix login password.

use hkdf::Hkdf;
use pamsm::{Pam, PamData, PamError, PamFlags, PamLibExt, PamServiceModule};
use sha2::Sha256;
use std::io::{self, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

const DATA_NAME: &str = "kpxcd.derived_token";
const HKDF_SALT: &[u8] = b"kpxcd-pam-v1";
const TOKEN_LEN: usize = 32;

/// A derived token whose bytes are zeroed on drop.
#[derive(Clone)]
struct DerivedToken {
    bytes: [u8; TOKEN_LEN],
}

impl Drop for DerivedToken {
    fn drop(&mut self) {
        for b in &mut self.bytes {
            *b = 0;
        }
    }
}

impl PamData for DerivedToken {}

/// Derive a kpxcd-specific 32-byte token from the login password using
/// HKDF-SHA256. Leaking this token does not reveal the original password.
fn derive_token(password: &[u8]) -> DerivedToken {
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), password);
    let mut token = DerivedToken {
        bytes: [0u8; TOKEN_LEN],
    };
    // hkdf.expand returns Ok for lengths up to 255 * HashLen (8160 bytes for SHA-256).
    hkdf.expand(&[], &mut token.bytes)
        .expect("hkdf expand failed: token length within bounds");
    token
}

struct PamKpxcd;

impl PamServiceModule for PamKpxcd {
    fn authenticate(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        let password = match pamh.get_authtok(None) {
            Ok(Some(tok)) => tok.to_bytes().to_vec(),
            Ok(None) => return PamError::AUTH_ERR,
            Err(e) => return e,
        };

        let token = derive_token(&password);

        // Zero the password Vec immediately after derivation.
        let mut pw = password;
        for b in &mut pw {
            *b = 0;
        }
        drop(pw);

        match unsafe { pamh.send_data(DATA_NAME, token) } {
            Ok(()) => PamError::SUCCESS,
            Err(e) => e,
        }
    }

    fn setcred(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn open_session(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        let token: DerivedToken = match unsafe { pamh.retrieve_data(DATA_NAME) } {
            Ok(t) => t,
            // No token available — skip silently so login is never blocked.
            Err(_) => return PamError::SUCCESS,
        };

        match send_token_to_socket(&pamh, &token.bytes) {
            Ok(()) => PamError::SUCCESS,
            Err(_) => PamError::SUCCESS, // Never block login.
        }
    }

    fn close_session(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
}

fn send_token_to_socket(pamh: &Pam, token: &[u8; TOKEN_LEN]) -> io::Result<()> {
    let socket_path = pam_socket_path(pamh)?;

    // The daemon may still be starting up when PAM open_session runs.
    // Retry with a short backoff so the socket has time to appear.
    let mut stream = None;
    for attempt in 0..5 {
        match UnixStream::connect(&socket_path) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) if attempt < 4 => {
                // Wait 50ms, 100ms, 150ms, 200ms.
                std::thread::sleep(std::time::Duration::from_millis(50 * (attempt as u64 + 1)));
            }
            Err(e) => return Err(e),
        }
    }
    let mut stream = stream.ok_or_else(|| {
        io::Error::new(io::ErrorKind::ConnectionRefused, "socket not available after retries")
    })?;
    stream.write_all(token)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    Ok(())
}

fn pam_socket_path(pamh: &Pam) -> io::Result<PathBuf> {
    if let Ok(Some(value)) = pamh.getenv("XDG_RUNTIME_DIR") {
        let s = value.to_string_lossy().into_owned();
        if !s.is_empty() {
            return Ok(PathBuf::from(s).join("kpxcd").join("pam.sock"));
        }
    }
    // Fallback: try to construct from UID.
    let uid = unsafe { libc::getuid() };
    let path = PathBuf::from(format!("/run/user/{uid}/kpxcd/pam.sock"));
    if path.parent().map(|p| p.exists()).unwrap_or(false) {
        return Ok(path);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "XDG_RUNTIME_DIR not set and /run/user/{uid} does not exist",
    ))
}

pamsm::pam_module!(PamKpxcd);
