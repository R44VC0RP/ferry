//! Running commands for a peer: build the process, stream its output, and
//! make sure it dies if the peer goes away or the timeout passes.

use std::ffi::OsString;
use std::fs;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::{Paths, hex_encode, random};
use crate::proto::{Conn, ExecExit, ExecSpec, ExecStarted, Kind, ProtoError, encode_frame, read_frame};
use crate::transfer::resolve_path;

/// How long a login shell gets to print its environment.
#[cfg(unix)]
const ENV_CAPTURE_TIMEOUT: Duration = Duration::from_secs(10);
/// The captured environment is refreshed after this long, so newly installed
/// tools show up without restarting the daemon.
const ENV_TTL: Duration = Duration::from_secs(300);
/// After the process exits, wait this long for output still in the pipes.
/// Anything quieter than this is a background child holding the pipe open.
const DRAIN_IDLE: Duration = Duration::from_millis(250);
/// Grace between asking a process tree to stop and killing it.
const KILL_GRACE: Duration = Duration::from_secs(2);
const PIPE_BUFFER: usize = 64 * 1024;
const ENV_BEGIN: &str = "__FERRY_ENV_BEGIN__";
const ENV_END: &str = "__FERRY_ENV_END__";

type Env = Vec<(OsString, OsString)>;

/// The environment commands run in. A service starts with a bare
/// environment, so this asks the user's shell what a terminal would have.
pub struct EnvCache {
    cached: Mutex<Option<(Instant, Arc<Env>)>>,
}

impl EnvCache {
    pub fn new() -> Self {
        Self { cached: Mutex::new(None) }
    }

    pub fn get(&self, paths: &Paths) -> Arc<Env> {
        let mut cached = self.cached.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((at, env)) = cached.as_ref()
            && at.elapsed() < ENV_TTL
        {
            return env.clone();
        }
        let fresh = match capture_env(paths) {
            Some(env) => Arc::new(env),
            // Keep the last good capture over the bare fallback.
            None => match cached.as_ref() {
                Some((_, env)) => env.clone(),
                None => Arc::new(fallback_env(paths)),
            },
        };
        *cached = Some((Instant::now(), fresh.clone()));
        fresh
    }
}

/// Prints this process's environment between markers. The daemon runs this
/// through a login shell (`ferry __dumpenv`) to learn the user's real PATH.
pub fn dump_env() {
    let vars: Vec<(String, String)> = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect();
    let json = serde_json::to_string(&vars).unwrap_or_else(|_| "[]".into());
    println!("{ENV_BEGIN}{json}{ENV_END}");
}

#[cfg(unix)]
fn user_shell() -> PathBuf {
    if let Some(shell) = std::env::var_os("SHELL").filter(|s| !s.is_empty()) {
        return PathBuf::from(shell);
    }
    let user = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_default();
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 7 && fields[0] == user && !fields[6].is_empty() {
                return PathBuf::from(fields[6]);
            }
        }
    }
    PathBuf::from("/bin/sh")
}

#[cfg(unix)]
fn capture_env(_paths: &Paths) -> Option<Env> {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().ok()?;
    let shell = user_shell();
    let quoted = format!("'{}'", exe.to_string_lossy().replace('\'', "'\\''"));
    let mut child = Command::new(&shell)
        .args(["-ilc", &format!("{quoted} __dumpenv")])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut out = String::new();
        // A failed read just yields a shorter string, which fails to parse below.
        if let Err(err) = stdout.read_to_string(&mut out) {
            tracing::debug!(%err, "reading the shell environment");
        }
        // The receiver may have timed out and left; nothing to do then.
        if tx.send(out).is_err() {}
    });
    let out = match rx.recv_timeout(ENV_CAPTURE_TIMEOUT) {
        Ok(out) => out,
        Err(_) => {
            tracing::warn!(shell = %shell.display(), "login shell did not report its environment in time");
            kill_tree(child.id());
            reap(child);
            return None;
        }
    };
    reap(child);
    let start = out.rfind(ENV_BEGIN)? + ENV_BEGIN.len();
    let end = out[start..].find(ENV_END)? + start;
    let vars: Vec<(String, String)> = serde_json::from_str(&out[start..end]).ok()?;
    // These describe the throwaway shell, not the user's setup.
    const DROP: &[&str] = &["_", "SHLVL", "PWD", "OLDPWD"];
    Some(
        vars.into_iter()
            .filter(|(k, _)| !DROP.contains(&k.as_str()))
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect(),
    )
}

fn reap(mut child: Child) {
    if let Err(err) = child.wait() {
        tracing::debug!(%err, "waiting for a helper process");
    }
}

/// On Windows the registry holds the live PATH; a service only sees the one
/// from when it started.
#[cfg(windows)]
fn capture_env(_paths: &Paths) -> Option<Env> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

    let mut env: Vec<(String, String)> =
        std::env::vars_os().filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))).collect();
    let lookup = |env: &[(String, String)], name: &str| {
        env.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone())
    };
    let expand = |env: &[(String, String)], raw: &str| {
        let mut out = String::new();
        let mut rest = raw;
        while let Some(start) = rest.find('%') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            match after.find('%') {
                Some(end) => {
                    match lookup(env, &after[..end]) {
                        Some(value) => out.push_str(&value),
                        None => out.push_str(&rest[start..start + end + 2]),
                    }
                    rest = &after[end + 1..];
                }
                None => {
                    out.push_str(&rest[start..]);
                    rest = "";
                }
            }
        }
        out.push_str(rest);
        out
    };

    let mut path_parts: Vec<String> = Vec::new();
    let sources = [
        RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
        RegKey::predef(HKEY_CURRENT_USER).open_subkey("Environment"),
    ];
    for key in sources.into_iter().flatten() {
        for (name, _) in key.enum_values().flatten() {
            let Ok(raw) = key.get_value::<String, _>(&name) else { continue };
            let value = expand(&env, &raw);
            if name.eq_ignore_ascii_case("PATH") {
                path_parts.push(value);
            } else if !name.eq_ignore_ascii_case("USERNAME") {
                env.retain(|(k, _)| !k.eq_ignore_ascii_case(&name));
                env.push((name, value));
            }
        }
    }
    if !path_parts.is_empty() {
        env.retain(|(k, _)| !k.eq_ignore_ascii_case("PATH"));
        env.push(("Path".into(), path_parts.join(";")));
    }
    Some(env.into_iter().map(|(k, v)| (OsString::from(k), OsString::from(v))).collect())
}

/// The daemon's own environment, with the usual tool directories added.
fn fallback_env(paths: &Paths) -> Env {
    let mut env: Env = std::env::vars_os().collect();
    if cfg!(unix) {
        let mut dirs: Vec<PathBuf> = [".local/bin", ".cargo/bin", ".bun/bin"].iter().map(|d| paths.home.join(d)).collect();
        dirs.extend(["/opt/homebrew/bin", "/usr/local/bin"].iter().map(PathBuf::from));
        let current = std::env::var_os("PATH").unwrap_or_default();
        dirs.extend(std::env::split_paths(&current));
        if let Ok(joined) = std::env::join_paths(dirs) {
            env.retain(|(k, _)| k != "PATH");
            env.push(("PATH".into(), joined));
        }
    }
    env
}

fn env_value<'a>(env: &'a Env, name: &str) -> Option<&'a OsString> {
    env.iter().find(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case(name)).map(|(_, v)| v)
}

/// A script written to disk for a shell that wants a file. Removed on drop.
struct TempScript(PathBuf);

impl Drop for TempScript {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.0) {
            tracing::debug!(path = %self.0.display(), %err, "removing a temporary script");
        }
    }
}

#[cfg(windows)]
fn temp_script(contents: &[u8], extension: &str) -> Result<TempScript, String> {
    let mut id = [0u8; 8];
    random(&mut id).map_err(|err| err.to_string())?;
    let path = std::env::temp_dir().join(format!("ferry-{}.{extension}", hex_encode(&id)));
    fs::write(&path, contents).map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(TempScript(path))
}

/// Finds a program the way `cmd` would, so `npm` resolves to `npm.cmd`.
#[cfg(windows)]
fn resolve_program(program: &str, env: &Env) -> PathBuf {
    let direct = Path::new(program);
    if direct.components().count() > 1 || direct.extension().is_some() {
        return direct.to_path_buf();
    }
    let path = env_value(env, "PATH").cloned().unwrap_or_default();
    let exts = env_value(env, "PATHEXT").map(|v| v.to_string_lossy().into_owned()).unwrap_or(".COM;.EXE;.BAT;.CMD".into());
    for dir in std::env::split_paths(&path) {
        for ext in exts.split(';').filter(|e| !e.is_empty()) {
            let candidate = dir.join(format!("{program}{ext}"));
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    direct.to_path_buf()
}

#[cfg(unix)]
fn resolve_program(program: &str, _env: &Env) -> PathBuf {
    PathBuf::from(program)
}

struct Prepared {
    command: Command,
    /// Kept alive until the process has finished reading it.
    _script: Option<TempScript>,
}

fn prepare(spec: &ExecSpec, paths: &Paths, env: &Env, peer: &str) -> Result<Prepared, String> {
    let mut script_file = None;
    let mut command = match &spec.script {
        Some(script) => script_command(script, spec.shell.as_deref(), env, &mut script_file)?,
        None => {
            let (program, args) = spec.argv.split_first().ok_or("no command given")?;
            let mut command = Command::new(resolve_program(program, env));
            command.args(args);
            command
        }
    };
    let cwd = resolve_path(spec.cwd.as_deref().unwrap_or(""), &paths.home, &paths.home);
    if !cwd.is_dir() {
        return Err(format!("{}: no such directory", cwd.display()));
    }
    command.current_dir(cwd).env_clear().envs(env.iter().map(|(k, v)| (k, v)));
    command.envs(spec.env.iter().map(|(k, v)| (k, v))).env("FERRY_PEER", peer);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Its own process group, so the whole tree can be signalled at once.
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);
    }
    Ok(Prepared { command, _script: script_file })
}

#[cfg(unix)]
fn script_command(
    script: &str,
    shell: Option<&str>,
    env: &Env,
    _file: &mut Option<TempScript>,
) -> Result<Command, String> {
    let shell = match shell {
        Some(shell) => PathBuf::from(shell),
        None => env_value(env, "SHELL").map(PathBuf::from).unwrap_or_else(user_shell),
    };
    let mut command = Command::new(shell);
    command.arg("-c").arg(script);
    Ok(command)
}

/// Windows shells get the script as a file: that sidesteps every layer of
/// command-line quoting, which is the usual way remote PowerShell goes wrong.
#[cfg(windows)]
fn script_command(script: &str, shell: Option<&str>, env: &Env, file: &mut Option<TempScript>) -> Result<Command, String> {
    let shell = shell.unwrap_or("powershell");
    let name = Path::new(shell).file_stem().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
    match name.as_str() {
        "powershell" | "pwsh" => {
            // UTF-8 with a BOM so Windows PowerShell 5 reads non-ASCII
            // correctly, and a real exit status from the last native command.
            let body = format!(
                "\u{feff}$ProgressPreference = 'SilentlyContinue'\r\n\
                 [Console]::OutputEncoding = [System.Text.Encoding]::UTF8\r\n\
                 $OutputEncoding = [System.Text.Encoding]::UTF8\r\n\
                 {script}\r\n\
                 if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}\r\n"
            );
            let script = temp_script(body.as_bytes(), "ps1")?;
            let mut command = Command::new(resolve_program(shell, env));
            command.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"]);
            command.arg(&script.0);
            *file = Some(script);
            Ok(command)
        }
        "cmd" => {
            let script = temp_script(format!("@echo off\r\n{script}\r\n").as_bytes(), "cmd")?;
            let mut command = Command::new("cmd.exe");
            command.args(["/d", "/c"]).arg(&script.0);
            *file = Some(script);
            Ok(command)
        }
        _ => {
            let mut command = Command::new(resolve_program(shell, env));
            command.arg("-c").arg(script);
            Ok(command)
        }
    }
}

/// Stops a process and everything it started.
pub fn kill_tree(pid: u32) {
    #[cfg(unix)]
    {
        let group = -(pid as i32);
        // SAFETY: `kill` only sends a signal; a stale or wrong id fails with
        // ESRCH and touches no memory.
        unsafe { libc::kill(group, libc::SIGTERM) };
        thread::spawn(move || {
            thread::sleep(KILL_GRACE);
            // SAFETY: as above.
            unsafe { libc::kill(group, libc::SIGKILL) };
        });
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _grace = KILL_GRACE;
        let result = Command::new("taskkill")
            .args(["/T", "/F", "/PID", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000)
            .status();
        if let Err(err) = result {
            tracing::warn!(pid, %err, "taskkill failed");
        }
    }
}

fn millis_since(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

/// Serves one exec request to the end.
pub fn serve(conn: Conn, spec: ExecSpec, paths: &Paths, env: &EnvCache, peer: &str) -> Result<(), ProtoError> {
    let mut conn = conn;
    let env = env.get(paths);
    let mut prepared = match prepare(&spec, paths, &env, peer) {
        Ok(prepared) => prepared,
        Err(message) => return conn.send_err(message),
    };

    if spec.detach {
        return serve_detached(conn, prepared, paths);
    }

    prepared.command.stdin(if spec.stdin { Stdio::piped() } else { Stdio::null() });
    prepared.command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = match prepared.command.spawn() {
        Ok(child) => child,
        Err(err) => return conn.send_err(describe_spawn(&spec, &err)),
    };
    let pid = child.id();
    conn.send_ok(ExecStarted { pid, log: None })?;

    let (mut reader, writer) = conn.into_split()?;
    let writer = Arc::new(Mutex::new(writer));
    let done = Arc::new(AtomicBool::new(false));
    let timed_out = Arc::new(AtomicBool::new(false));
    let started = Instant::now();
    let last_output = Arc::new(AtomicU64::new(0));
    let (finished_tx, finished_rx) = mpsc::channel::<()>();

    let mut pumps = 0;
    let stdout = child.stdout.take().map(|pipe| (Kind::Stdout, Box::new(pipe) as Box<dyn Read + Send>));
    let stderr = child.stderr.take().map(|pipe| (Kind::Stderr, Box::new(pipe) as Box<dyn Read + Send>));
    for (kind, mut pipe) in [stdout, stderr].into_iter().flatten() {
        pumps += 1;
        let writer = writer.clone();
        let last_output = last_output.clone();
        let finished = finished_tx.clone();
        thread::spawn(move || {
            let mut buf = vec![0u8; PIPE_BUFFER];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        last_output.store(millis_since(started), Ordering::Relaxed);
                        if send_frame(&writer, kind, &buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
            // The receiver is gone once the drain window closes; that's fine.
            if finished.send(()).is_err() {}
        });
    }
    drop(finished_tx);

    // Stdin, and the watch for a peer that hangs up.
    let mut stdin = child.stdin.take();
    {
        let done = done.clone();
        thread::spawn(move || {
            let mut buf = Vec::new();
            loop {
                match read_frame(&mut reader, &mut buf) {
                    Ok(Kind::Stdin) => {
                        if let Some(pipe) = stdin.as_mut()
                            && pipe.write_all(&buf).and_then(|()| pipe.flush()).is_err()
                        {
                            stdin = None;
                        }
                    }
                    Ok(Kind::StdinEof) => stdin = None,
                    Ok(_) => {}
                    Err(_) => {
                        if !done.load(Ordering::SeqCst) {
                            tracing::info!(pid, "peer disconnected, stopping its command");
                            kill_tree(pid);
                        }
                        break;
                    }
                }
            }
        });
    }

    let (exit_tx, exit_rx) = mpsc::channel::<()>();
    if let Some(secs) = spec.timeout_secs {
        let timed_out = timed_out.clone();
        thread::spawn(move || {
            if exit_rx.recv_timeout(Duration::from_secs(secs)) == Err(mpsc::RecvTimeoutError::Timeout) {
                timed_out.store(true, Ordering::SeqCst);
                kill_tree(pid);
            }
        });
    }

    let status = child.wait();
    done.store(true, Ordering::SeqCst);
    drop(exit_tx);
    let exited = millis_since(started);

    // Collect what is still in the pipes. A process the command left running
    // can hold them open forever, so stop once the output goes quiet.
    let mut remaining = pumps;
    while remaining > 0 {
        match finished_rx.recv_timeout(DRAIN_IDLE) {
            Ok(()) => remaining -= 1,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let quiet_since = last_output.load(Ordering::Relaxed).max(exited);
                if millis_since(started).saturating_sub(quiet_since) >= DRAIN_IDLE.as_millis() as u64 {
                    break;
                }
            }
        }
    }

    let exit = match status {
        Ok(status) => ExecExit { code: status.code(), signal: exit_signal(&status), timed_out: timed_out.load(Ordering::SeqCst) },
        Err(err) => {
            tracing::warn!(pid, %err, "could not wait for the command");
            ExecExit { code: None, signal: None, timed_out: false }
        }
    };
    let bytes = serde_json::to_vec(&exit)?;
    send_frame(&writer, Kind::Json, &bytes)
}

fn send_frame(writer: &Mutex<TcpStream>, kind: Kind, payload: &[u8]) -> Result<(), ProtoError> {
    let frame = encode_frame(kind, payload);
    let mut writer = writer.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    writer.write_all(&frame)?;
    Ok(())
}

#[cfg(unix)]
fn exit_signal(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn exit_signal(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

fn describe_spawn(spec: &ExecSpec, err: &std::io::Error) -> String {
    match (&spec.script, spec.argv.first()) {
        (None, Some(program)) => format!("{program}: {err}"),
        _ => format!("could not start the shell: {err}"),
    }
}

/// Starts a job that outlives the connection, with its output in a log file.
fn serve_detached(mut conn: Conn, mut prepared: Prepared, paths: &Paths) -> Result<(), ProtoError> {
    let mut id = [0u8; 4];
    if let Err(err) = random(&mut id) {
        return conn.send_err(err.to_string());
    }
    let dir = paths.jobs();
    let log = dir.join(format!("{}.log", hex_encode(&id)));
    let open = fs::create_dir_all(&dir).and_then(|()| fs::File::create(&log)).and_then(|out| Ok((out.try_clone()?, out)));
    let (out, err) = match open {
        Ok(pair) => pair,
        Err(err) => return conn.send_err(format!("{}: {err}", log.display())),
    };
    prepared.command.stdin(Stdio::null()).stdout(out).stderr(err);
    match prepared.command.spawn() {
        Ok(child) => {
            let pid = child.id();
            // A temporary script must outlive this request, so hand it to the
            // thread that waits for the job.
            let script = prepared._script.take();
            thread::spawn(move || {
                reap(child);
                drop(script);
            });
            conn.send_ok(ExecStarted { pid, log: Some(log.display().to_string()) })
        }
        Err(err) => conn.send_err(format!("could not start: {err}")),
    }
}

/// The client half: forwards stdin, prints output, returns the exit code.
pub fn run_client(conn: Conn, forward_stdin: bool) -> Result<i32, ProtoError> {
    let (mut reader, mut writer) = conn.into_split()?;
    if forward_stdin {
        thread::spawn(move || {
            let mut stdin = std::io::stdin().lock();
            let mut buf = vec![0u8; PIPE_BUFFER];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if writer.write_all(&encode_frame(Kind::Stdin, &buf[..n])).is_err() {
                            return;
                        }
                    }
                }
            }
            // If the command already finished there is nobody to tell.
            if writer.write_all(&encode_frame(Kind::StdinEof, &[])).is_err() {}
        });
    }
    read_output(&mut reader)
}

fn read_output(reader: &mut BufReader<TcpStream>) -> Result<i32, ProtoError> {
    let mut buf = Vec::new();
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    loop {
        match read_frame(reader, &mut buf)? {
            Kind::Stdout => stdout.write_all(&buf).and_then(|()| stdout.flush())?,
            Kind::Stderr => stderr.write_all(&buf).and_then(|()| stderr.flush())?,
            Kind::Json => {
                let exit: ExecExit = serde_json::from_slice(&buf)?;
                if exit.timed_out {
                    drop(stderr);
                    eprintln!("ferry: command timed out and was stopped");
                    return Ok(124);
                }
                return Ok(match (exit.code, exit.signal) {
                    (Some(code), _) => code,
                    (None, Some(signal)) => 128 + signal,
                    (None, None) => 1,
                });
            }
            got => return Err(ProtoError::Unexpected { got, want: "command output" }),
        }
    }
}
