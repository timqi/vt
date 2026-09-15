//! Transport-neutral client display claims, never agent authorization scope.

use crate::core::sanitize_for_display as sanitize;

pub fn get_hostname() -> String {
    // gethostname(3); 256 covers every platform's HOST_NAME_MAX+1.
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is writable for `buf.len()` bytes; gethostname writes at
    // most that many and the NUL scan below never reads past it.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return "unknown".into();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Collect the per-process display fields shared by both the CF ceremony
/// (phone approval page) and the SSH-agent (Touch ID prompt) paths. Strings
/// are pre-sanitized (control chars stripped, length-capped).
pub fn collect_client_meta() -> crate::core::ClientMeta {
    sanitize_client_meta(crate::core::ClientMeta {
        user: username(),
        pwd: cwd(),
        tty: tty_name(),
        ppid_cmd: parent_cmd(),
        ssh_client: ssh_client_env(),
    })
}

fn sanitize_client_meta(meta: crate::core::ClientMeta) -> crate::core::ClientMeta {
    crate::core::ClientMeta {
        user: sanitize(&meta.user, 64),
        pwd: sanitize(&meta.pwd, 200),
        tty: sanitize(&meta.tty, 40),
        ppid_cmd: sanitize(&meta.ppid_cmd, 200),
        ssh_client: sanitize(&meta.ssh_client, 100),
    }
}

fn username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default()
}

fn cwd() -> String {
    std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default()
}

fn tty_name() -> String {
    // ttyname(3) on stdin; returns NULL if stdin isn't a TTY (cron, pipes).
    unsafe {
        let p = libc::ttyname(0);
        if p.is_null() {
            return String::new();
        }
        std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

/// Shorten a parent command line to `basename(argv[0]) + args`. A long
/// absolute argv[0] (`/opt/homebrew/Cellar/…/bin/zsh -c …`) drowned the
/// signal on every display surface (Touch ID `via:`, approval page Parent process,
/// notifications); the field is client-claimed display data everywhere, so
/// the shortening happens once at collection.
fn basename_cmdline(first: &str, rest: &[String]) -> String {
    let base = first.rsplit('/').next().unwrap_or(first);
    std::iter::once(base)
        .chain(rest.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

fn parent_cmd() -> String {
    let ppid = unsafe { libc::getppid() };
    if ppid <= 0 {
        return String::new();
    }
    // Linux: /proc/<ppid>/cmdline is NUL-separated argv.
    #[cfg(target_os = "linux")]
    {
        if let Ok(buf) = std::fs::read(format!("/proc/{ppid}/cmdline")) {
            let parts: Vec<String> = buf
                .split(|b| *b == 0)
                .filter(|p| !p.is_empty())
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect();
            if let Some(first) = parts.first() {
                return basename_cmdline(first, &parts[1..]);
            }
        }
    }
    // Fallback (macOS / no procfs): shell out to `ps`.
    if let Ok(out) = std::process::Command::new("ps")
        .args(["-o", "args=", "-p", &ppid.to_string()])
        .output()
    {
        if out.status.success() {
            let full = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let mut it = full.split_whitespace().map(str::to_string);
            if let Some(first) = it.next() {
                return basename_cmdline(&first, &it.collect::<Vec<_>>());
            }
        }
    }
    String::new()
}

fn ssh_client_env() -> String {
    std::env::var("SSH_CLIENT")
        .or_else(|_| std::env::var("SSH_CONNECTION"))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ClientMeta;

    #[test]
    fn client_meta_sanitization_preserves_wire_fields_and_caps() {
        let dirty = format!("\0\n{}\u{0085}", "x".repeat(220));
        let meta = sanitize_client_meta(ClientMeta {
            user: dirty.clone(),
            pwd: dirty.clone(),
            tty: dirty.clone(),
            ppid_cmd: dirty.clone(),
            ssh_client: dirty,
        });
        let json = serde_json::to_value(meta).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 5);
        for (field, cap) in [
            ("user", 64),
            ("pwd", 200),
            ("tty", 40),
            ("ppid_cmd", 200),
            ("ssh_client", 100),
        ] {
            assert_eq!(json[field], format!("{}\u{2026}", "x".repeat(cap)));
        }
        let blank = serde_json::to_value(sanitize_client_meta(ClientMeta::default())).unwrap();
        assert!(blank.as_object().unwrap().values().all(|value| value == ""));
    }

    #[test]
    fn parent_command_shortens_only_the_executable() {
        assert_eq!(
            basename_cmdline(
                "/opt/homebrew/bin/zsh",
                &["-c".into(), "/path/to/script".into()]
            ),
            "zsh -c /path/to/script"
        );
        assert_eq!(basename_cmdline("ssh", &[]), "ssh");
    }
}
