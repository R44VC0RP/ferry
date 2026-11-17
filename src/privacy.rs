//! macOS privacy (TCC) handling.
//!
//! A background service that touches Desktop, Documents, Downloads and a few
//! other places makes macOS show a consent prompt. Nobody is watching a
//! service's prompt, and while it waits macOS holds up every other program's
//! access to those folders too. So a daemon without Full Disk Access confines
//! itself: a sandbox rule turns those folders into an immediate "not
//! permitted", for the daemon and for every command it starts. With Full Disk
//! Access macOS never prompts, and the daemon runs unconfined.

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::{CStr, CString, c_char, c_int};
    use std::fs::File;
    use std::path::Path;

    /// Readable only with Full Disk Access; a failed open never prompts.
    const PROBE: &str = "/Library/Application Support/com.apple.TCC/TCC.db";

    /// Places under the home directory where macOS would ask for consent.
    const GUARDED: &[&str] = &[
        "Desktop",
        "Documents",
        "Downloads",
        "Library/Mobile Documents",
        "Library/CloudStorage",
        "Library/Containers",
        "Library/Group Containers",
        "Library/Application Support/AddressBook",
        "Library/Calendars",
        "Library/Reminders",
        "Pictures/Photos Library.photoslibrary",
    ];

    unsafe extern "C" {
        fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
        fn sandbox_free_error(errorbuf: *mut c_char);
    }

    pub fn has_full_disk_access() -> bool {
        File::open(PROBE).is_ok()
    }

    pub fn confine(home: &Path) -> Result<(), String> {
        let mut profile = String::from("(version 1)\n(allow default)\n(deny file-read-data file-read-xattr file-write*\n");
        for dir in GUARDED {
            let path = home.join(dir).display().to_string().replace('\\', "\\\\").replace('"', "\\\"");
            profile.push_str(&format!("  (subpath \"{path}\")\n"));
        }
        profile.push_str(")\n");
        let profile = CString::new(profile).map_err(|err| err.to_string())?;
        let mut error: *mut c_char = std::ptr::null_mut();
        // SAFETY: `profile` is a valid NUL-terminated string that outlives the
        // call, and `error` is a valid out-pointer the function may fill.
        let rc = unsafe { sandbox_init(profile.as_ptr(), 0, &mut error) };
        if rc == 0 {
            return Ok(());
        }
        let message = if error.is_null() {
            "sandbox_init failed".to_string()
        } else {
            // SAFETY: on failure the function stores a NUL-terminated string
            // that we own until sandbox_free_error.
            let text = unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned();
            // SAFETY: `error` came from sandbox_init and is freed exactly once.
            unsafe { sandbox_free_error(error) };
            text
        };
        Err(message)
    }
}

#[cfg(target_os = "macos")]
pub use imp::{confine, has_full_disk_access};

#[cfg(not(target_os = "macos"))]
pub fn has_full_disk_access() -> bool {
    true
}

#[cfg(not(target_os = "macos"))]
pub fn confine(_home: &std::path::Path) -> Result<(), String> {
    Ok(())
}

pub const GRANT_HELP: &str = "System Settings > Privacy & Security > Full Disk Access > add ~/.local/bin/ferry";
