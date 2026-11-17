//! Installing the daemon as a background service: launchd on macOS, a
//! systemd user unit on Linux, a boot-time scheduled task on Windows.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::config::Paths;

#[cfg(target_os = "macos")]
pub const LABEL: &str = "dev.vogel.ferry";

/// Where the binary lives once installed.
pub fn installed_binary(paths: &Paths) -> PathBuf {
    if cfg!(windows) {
        let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(|| paths.home.join("AppData").join("Local"));
        base.join("Programs").join("ferry").join("ferry.exe")
    } else {
        paths.home.join(".local").join("bin").join("ferry")
    }
}

/// Copies the running binary into place. Safe while the daemon is running:
/// the old file is moved aside or replaced by rename, never written over.
pub fn place_binary(paths: &Paths) -> Result<PathBuf> {
    let current = std::env::current_exe().context("can't find the running binary")?;
    let dest = installed_binary(paths);
    let same = fs::canonicalize(&current).ok().zip(fs::canonicalize(&dest).ok()).is_some_and(|(a, b)| a == b);
    if same {
        return Ok(dest);
    }
    let dir = dest.parent().context("install path has no parent")?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let staged = dest.with_extension(format!("new{}", std::process::id()));
    fs::copy(&current, &staged).with_context(|| format!("copying to {}", staged.display()))?;
    if cfg!(windows) && dest.exists() {
        // A running .exe can't be replaced, but it can be renamed.
        let aside = dest.with_extension(format!("old{}", crate::config::now_secs()));
        fs::rename(&dest, &aside).with_context(|| format!("moving {} aside", dest.display()))?;
    }
    fs::rename(&staged, &dest).with_context(|| format!("installing {}", dest.display()))?;
    sweep_old_binaries(dir);
    Ok(dest)
}

fn sweep_old_binaries(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("ferry.old") {
            // Still in use by a daemon that hasn't restarted yet; the next
            // install removes it.
            if fs::remove_file(entry.path()).is_err() {}
        }
    }
}

fn run(command: &mut Command) -> Result<(bool, String)> {
    let output = command.output().with_context(|| format!("running {:?}", command.get_program()))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok((output.status.success(), text.trim().to_string()))
}

// --- macOS ---------------------------------------------------------------

#[cfg(target_os = "macos")]
fn plist_path(paths: &Paths) -> PathBuf {
    paths.home.join("Library").join("LaunchAgents").join(format!("{LABEL}.plist"))
}

#[cfg(target_os = "macos")]
fn uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(target_os = "macos")]
pub fn register(paths: &Paths, binary: &Path) -> Result<String> {
    let escape = |text: &str| text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let out = paths.dir.join("daemon.out.log");
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>{bin}</string><string>daemon</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>AbandonProcessGroup</key><true/>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>{out}</string>
  <key>StandardErrorPath</key><string>{out}</string>
</dict>
</plist>
"#,
        bin = escape(&binary.display().to_string()),
        out = escape(&out.display().to_string()),
    );
    let path = plist_path(paths);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(&path, plist).with_context(|| format!("writing {}", path.display()))?;

    // A logged-in desktop has a gui domain; a machine reached only over SSH
    // has just the user domain.
    let mut last = String::new();
    for domain in [format!("gui/{}", uid()), format!("user/{}", uid())] {
        let target = format!("{domain}/{LABEL}");
        // Not loaded yet is the normal first-install case.
        if run(Command::new("launchctl").args(["bootout", &target])).is_err() {}
        std::thread::sleep(std::time::Duration::from_millis(300));
        let (ok, text) = run(Command::new("launchctl").arg("bootstrap").arg(&domain).arg(&path))?;
        if ok {
            return Ok(format!("launchd agent {LABEL} ({domain})"));
        }
        last = text;
    }
    bail!("launchctl could not load the agent: {last}")
}

#[cfg(target_os = "macos")]
pub fn unregister(paths: &Paths) -> Result<()> {
    for domain in ["gui", "user"] {
        if run(Command::new("launchctl").args(["bootout", &format!("{domain}/{}/{LABEL}", uid())])).is_err() {}
    }
    let path = plist_path(paths);
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn is_registered(paths: &Paths) -> bool {
    plist_path(paths).exists()
}

// --- Linux ---------------------------------------------------------------

#[cfg(all(unix, not(target_os = "macos")))]
fn unit_path(paths: &Paths) -> PathBuf {
    paths.home.join(".config").join("systemd").join("user").join("ferry.service")
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn register(paths: &Paths, binary: &Path) -> Result<String> {
    // KillMode=process: restarting the daemon must not take down jobs it
    // started with `ferry run --detach`.
    let unit = format!(
        "[Unit]\nDescription=ferry: files and commands between your machines\nAfter=network-online.target\n\n\
         [Service]\nExecStart={} daemon\nRestart=always\nRestartSec=2\nKillMode=process\n\n\
         [Install]\nWantedBy=default.target\n",
        binary.display()
    );
    let path = unit_path(paths);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(&path, unit).with_context(|| format!("writing {}", path.display()))?;

    let systemctl = |args: &[&str]| run(Command::new("systemctl").arg("--user").args(args));
    let (ok, text) = systemctl(&["daemon-reload"])?;
    if !ok {
        bail!(
            "systemd user services aren't available here ({text}). Start the daemon yourself with: nohup {} daemon &",
            binary.display()
        );
    }
    let (ok, text) = systemctl(&["enable", "ferry.service"])?;
    if !ok {
        bail!("systemctl enable failed: {text}");
    }
    let (ok, text) = systemctl(&["restart", "ferry.service"])?;
    if !ok {
        bail!("systemctl restart failed: {text}");
    }

    // Lingering keeps the service up after logout and starts it at boot.
    let user = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_default();
    let linger = run(Command::new("loginctl").args(["enable-linger", &user])).map(|(ok, _)| ok).unwrap_or(false)
        || run(Command::new("sudo").args(["-n", "loginctl", "enable-linger", &user])).map(|(ok, _)| ok).unwrap_or(false);
    Ok(if linger {
        "systemd user service ferry.service (starts at boot)".to_string()
    } else {
        format!("systemd user service ferry.service. To start it at boot run: sudo loginctl enable-linger {user}")
    })
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn unregister(paths: &Paths) -> Result<()> {
    if run(Command::new("systemctl").args(["--user", "disable", "--now", "ferry.service"])).is_err() {}
    let path = unit_path(paths);
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn is_registered(paths: &Paths) -> bool {
    unit_path(paths).exists()
}

// --- Windows -------------------------------------------------------------

#[cfg(windows)]
fn powershell(script: &str) -> Result<(bool, String)> {
    let path = std::env::temp_dir().join(format!("ferry-install-{}.ps1", std::process::id()));
    fs::write(&path, format!("\u{feff}{script}"))?;
    let result = run(Command::new("powershell.exe")
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&path));
    if fs::remove_file(&path).is_err() {}
    result
}

#[cfg(windows)]
pub fn register(_paths: &Paths, binary: &Path) -> Result<String> {
    // S4U runs the task as this user at boot, logged in or not, without
    // storing a password. The firewall rule lets tailnet peers connect.
    let bin = binary.display().to_string().replace('\'', "''");
    let dir = binary.parent().map(|d| d.display().to_string()).unwrap_or_default().replace('\'', "''");
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {{ Write-Output 'NOT_ELEVATED'; exit 5 }}
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$action = New-ScheduledTaskAction -Execute '{bin}' -Argument 'daemon'
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType S4U -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'ferry' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Get-Process -Name ferry -ErrorAction SilentlyContinue | Where-Object {{ $_.Id -ne {pid} }} | Where-Object {{ (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine -match 'daemon' }} | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500
Start-ScheduledTask -TaskName 'ferry'
Get-NetFirewallRule -DisplayName 'ferry' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName 'ferry' -Direction Inbound -Program '{bin}' -Action Allow -Profile Any | Out-Null
$path = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($path -split ';') -notcontains '{dir}') {{
  [Environment]::SetEnvironmentVariable('Path', (($path.TrimEnd(';') + ';{dir}').TrimStart(';')), 'User')
}}
Write-Output 'OK'
"#,
        pid = std::process::id(),
    );
    let (ok, text) = powershell(&script)?;
    if text.contains("NOT_ELEVATED") {
        bail!("ferry install needs an elevated (Administrator) shell on Windows, to add the boot task and the firewall rule");
    }
    if !ok {
        bail!("could not register the scheduled task: {text}");
    }
    Ok("scheduled task 'ferry' (starts at boot) and firewall rule 'ferry'".to_string())
}

#[cfg(windows)]
pub fn unregister(_paths: &Paths) -> Result<()> {
    let (ok, text) = powershell(
        "Stop-ScheduledTask -TaskName 'ferry' -ErrorAction SilentlyContinue\n\
         Unregister-ScheduledTask -TaskName 'ferry' -Confirm:$false -ErrorAction SilentlyContinue\n\
         Get-NetFirewallRule -DisplayName 'ferry' -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n",
    )?;
    if !ok {
        bail!("could not remove the scheduled task: {text}");
    }
    Ok(())
}

#[cfg(windows)]
pub fn is_registered(_paths: &Paths) -> bool {
    run(Command::new("schtasks").args(["/query", "/tn", "ferry"])).map(|(ok, _)| ok).unwrap_or(false)
}
