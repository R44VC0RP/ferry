//! ferry: send files and run commands between your own machines.

mod client;
mod config;
mod daemon;
mod exec;
mod privacy;
mod proto;
mod service;
mod transfer;

use std::io::{IsTerminal, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde_json::json;

use client::Client;
use config::{PAIR_SECRET_LEN, PAIRING_TTL_SECS, Pairing, Paths, VERSION, hex_encode, now_secs, random, sanitize_name};
use proto::{CHUNK, ExecSpec, ExecStarted, Kind, Listing, Request, Written};
use transfer::{Summary, WalkOpts};

#[derive(Parser)]
#[command(
    name = "ferry",
    version,
    about = "Send files and run commands between your own machines over the tailnet.",
    after_help = "Examples:\n  \
        ferry cp ./dist exos:dev/app/          copy a folder to exos (lands in ~/dev/app/dist)\n  \
        ferry cp ./dist/ exos:dev/app/dist     copy a folder's contents\n  \
        ferry cp exon-desk:Documents/out.zip . fetch a file\n  \
        ferry run exos -- cargo test           run a program, no shell quoting\n  \
        ferry sh exon-desk 'Get-Date'          run a script in the machine's shell\n  \
        ferry sh exos < script.sh              run a script from stdin\n  \
        ferry peers                            list machines and whether they're reachable\n\n\
        Remote paths are relative to the home directory unless absolute. `~` works on every OS."
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Copy files or folders to or from a paired machine.
    ///
    /// Exactly one side is remote, written `machine:path`. Unchanged files
    /// (same size and time) are skipped. A folder is copied as itself into
    /// the destination; add a trailing slash to copy its contents instead.
    /// A single file may be given a new name at the destination.
    Cp {
        /// Sources, then the destination.
        #[arg(required = true, num_args = 2..)]
        paths: Vec<String>,
        /// Copy every file, even ones that look unchanged.
        #[arg(short, long)]
        force: bool,
        /// Skip paths matching this gitignore-style pattern (repeatable).
        #[arg(short = 'x', long, value_name = "PATTERN")]
        exclude: Vec<String>,
        /// Skip files ignored by .gitignore.
        #[arg(long)]
        gitignore: bool,
        /// Print the result as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run a program on a paired machine. Arguments arrive exactly as given.
    Run {
        machine: String,
        /// Working directory on the machine (default: home).
        #[arg(long, value_name = "DIR")]
        cwd: Option<String>,
        /// Set an environment variable (repeatable).
        #[arg(short, long, value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// Stop the command after this many seconds (exit code 124).
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
        /// Start it in the background and return; output goes to a log file there.
        #[arg(long)]
        detach: bool,
        /// Don't forward stdin.
        #[arg(short = 'n', long)]
        no_stdin: bool,
        /// The program and its arguments.
        #[arg(required = true, last = true)]
        command: Vec<String>,
    },
    /// Run a script in a paired machine's shell (login shell on macOS/Linux,
    /// PowerShell on Windows). Reads the script from stdin when not given.
    Sh {
        machine: String,
        /// The script. Omit to read it from stdin.
        script: Option<String>,
        /// Shell to use instead of the default (e.g. bash, pwsh, cmd).
        #[arg(long)]
        shell: Option<String>,
        #[arg(long, value_name = "DIR")]
        cwd: Option<String>,
        #[arg(short, long, value_name = "KEY=VALUE")]
        env: Vec<String>,
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
        #[arg(long)]
        detach: bool,
        #[arg(short = 'n', long)]
        no_stdin: bool,
    },
    /// List a directory on a paired machine.
    Ls {
        /// `machine:path` (path defaults to home).
        target: String,
        #[arg(long)]
        json: bool,
    },
    /// Print a file from a paired machine.
    Cat {
        /// `machine:path`
        target: String,
    },
    /// Write stdin to a file on a paired machine.
    Write {
        /// `machine:path`
        target: String,
    },
    /// List paired machines and check that each is reachable.
    Peers {
        #[arg(long)]
        json: bool,
    },
    /// Pair machines. Without a code: print one. With a code: join the
    /// machine that printed it (and every machine it is paired with).
    Pair {
        code: Option<String>,
        /// Leave the machines this one is already paired with.
        #[arg(long)]
        force: bool,
        #[arg(long)]
        json: bool,
    },
    /// Remove a machine from this machine's list.
    Forget { machine: String },
    /// Show this machine's name, address and whether the daemon is running.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Install (or update) ferry on this machine and start it at boot.
    Install {
        /// Name other machines will use for this one (default: hostname).
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        port: Option<u16>,
    },
    /// Stop the daemon and remove the service. Keeps the pairing.
    Uninstall,
    /// Run the daemon in the foreground (the service does this).
    Daemon,
    #[command(name = "__dumpenv", hide = true)]
    DumpEnv,
    #[command(name = "__fda-check", hide = true)]
    FdaCheck,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli.command) {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(err) => {
            let text = format!("{err:#}");
            eprintln!("ferry: {text}");
            print_hint(&text);
            ExitCode::from(1)
        }
    }
}

/// macOS refuses a few folders to a daemon without Full Disk Access; say how
/// to fix it instead of leaving a bare "not permitted".
fn print_hint(error: &str) {
    if error.contains("Operation not permitted") {
        eprintln!(
            "ferry: if that machine is a Mac, its ferry daemon has no Full Disk Access (see `ferry peers`). Grant it there: {}",
            privacy::GRANT_HELP
        );
    }
}

fn dispatch(command: Cmd) -> Result<i32> {
    if matches!(command, Cmd::DumpEnv) {
        exec::dump_env();
        return Ok(0);
    }
    if matches!(command, Cmd::FdaCheck) {
        return Ok(if privacy::has_full_disk_access() { 0 } else { 1 });
    }
    let paths = Paths::from_env()?;
    match command {
        Cmd::Cp { paths: args, force, exclude, gitignore, json } => {
            cp(Client::new(paths)?, args, force, WalkOpts { excludes: exclude, gitignore }, json)
        }
        Cmd::Run { machine, cwd, env, timeout, detach, no_stdin, command } => {
            let spec = ExecSpec {
                argv: command,
                cwd,
                env: parse_env(&env)?,
                timeout_secs: timeout,
                detach,
                stdin: !no_stdin && !detach,
                ..ExecSpec::default()
            };
            exec_remote(Client::new(paths)?, &machine, spec)
        }
        Cmd::Sh { machine, script, shell, cwd, env, timeout, detach, no_stdin } => {
            let from_stdin = script.is_none();
            let script = match script {
                Some(script) => script,
                None => {
                    if std::io::stdin().is_terminal() {
                        bail!("give a script, or pipe one in: ferry sh {machine} < script.sh");
                    }
                    let mut text = String::new();
                    std::io::stdin().read_to_string(&mut text).context("reading the script from stdin")?;
                    text
                }
            };
            let spec = ExecSpec {
                script: Some(script),
                shell,
                cwd,
                env: parse_env(&env)?,
                timeout_secs: timeout,
                detach,
                stdin: !no_stdin && !detach && !from_stdin,
                ..ExecSpec::default()
            };
            exec_remote(Client::new(paths)?, &machine, spec)
        }
        Cmd::Ls { target, json } => ls(Client::new(paths)?, &target, json),
        Cmd::Cat { target } => cat(Client::new(paths)?, &target),
        Cmd::Write { target } => write(Client::new(paths)?, &target),
        Cmd::Peers { json } => peers(Client::new(paths)?, json),
        Cmd::Pair { code: None, json, .. } => issue_code(paths, json),
        Cmd::Pair { code: Some(code), force, json } => join(paths, &code, force, json),
        Cmd::Forget { machine } => forget(paths, &machine),
        Cmd::Status { json } => status(paths, json),
        Cmd::Install { name, port } => install(paths, name, port),
        Cmd::Uninstall => {
            service::unregister(&paths)?;
            println!("ferry service removed. Pairing kept in {}", paths.dir.display());
            Ok(0)
        }
        Cmd::Daemon => {
            daemon::run(paths)?;
            Ok(0)
        }
        Cmd::DumpEnv | Cmd::FdaCheck => Ok(0),
    }
}

fn parse_env(pairs: &[String]) -> Result<Vec<(String, String)>> {
    pairs
        .iter()
        .map(|pair| {
            pair.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| anyhow!("--env wants KEY=VALUE, got {pair:?}"))
        })
        .collect()
}

/// Splits `machine:path`. Returns None for local paths, including Windows
/// drive paths and files that merely contain a colon.
fn remote(client: &Client, arg: &str) -> Result<Option<(String, String)>> {
    let Some((machine, path)) = arg.split_once(':') else { return Ok(None) };
    if machine.is_empty() || machine.contains(['/', '\\']) {
        return Ok(None);
    }
    let drive = machine.len() == 1 && machine.chars().all(|c| c.is_ascii_alphabetic());
    if cfg!(windows) && drive {
        return Ok(None);
    }
    if client.is_peer(machine) {
        return Ok(Some((machine.to_string(), path.to_string())));
    }
    if std::path::Path::new(arg).exists() {
        return Ok(None);
    }
    client.peer(machine).map(|_| None)
}

fn need_remote(client: &Client, arg: &str) -> Result<(String, String)> {
    remote(client, arg)?.ok_or_else(|| anyhow!("expected machine:path, got {arg:?}"))
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", UNITS[unit]) }
}

fn cp(client: Client, mut args: Vec<String>, force: bool, opts: WalkOpts, json: bool) -> Result<i32> {
    let dest = args.pop().context("missing destination")?;
    let cwd = std::env::current_dir().context("can't read the current directory")?;
    let home = client.paths.home.clone();
    let started = Instant::now();

    let remote_dest = remote(&client, &dest)?;
    let mut remote_sources = Vec::new();
    for source in &args {
        remote_sources.push(remote(&client, source)?);
    }

    let (direction, machine, summary): (&str, String, Summary) = match remote_dest {
        Some((machine, dest_path)) => {
            if remote_sources.iter().any(Option::is_some) {
                bail!("copying between two remote machines isn't supported; run the copy from one of them with `ferry run`");
            }
            let plan = transfer::plan(&args, &cwd, &home, &opts).map_err(|message| anyhow!(message))?;
            let mut conn = client.request(&machine, &Request::Push { dest: dest_path, force })?;
            let summary = transfer::send_tree(&mut conn, plan).map_err(|err| anyhow!("{machine}: {err}"))?;
            ("sent", machine, summary)
        }
        None => {
            let mut machine: Option<String> = None;
            let mut sources = Vec::new();
            for (source, parsed) in args.iter().zip(remote_sources) {
                let Some((name, path)) = parsed else {
                    bail!("one side must be remote (machine:path). {source:?} and {dest:?} are both local.");
                };
                if machine.as_ref().is_some_and(|m| *m != name) {
                    bail!("all sources must be on the same machine");
                }
                machine = Some(name);
                sources.push(path);
            }
            let machine = machine.context("missing source")?;
            let request = Request::Pull { sources, excludes: opts.excludes, gitignore: opts.gitignore };
            let mut conn = client.request(&machine, &request)?;
            let summary =
                transfer::recv_tree(&mut conn, &dest, &cwd, &home, force).map_err(|err| anyhow!("{machine}: {err}"))?;
            ("received", machine, summary)
        }
    };

    let seconds = started.elapsed().as_secs_f64();
    let landed = if direction == "sent" { format!("{machine}:{}", summary.root) } else { summary.root.clone() };
    if json {
        println!(
            "{}",
            json!({
                "direction": direction, "machine": machine, "destination": landed,
                "files": summary.files, "bytes": summary.bytes, "unchanged": summary.unchanged,
                "entries": summary.entries, "errors": summary.errors, "seconds": seconds,
            })
        );
    } else {
        let unchanged = if summary.unchanged > 0 { format!(", {} unchanged", summary.unchanged) } else { String::new() };
        println!(
            "{direction} {} file{} ({}) in {seconds:.2}s{unchanged} -> {landed}",
            summary.files,
            if summary.files == 1 { "" } else { "s" },
            human_bytes(summary.bytes),
        );
    }
    for error in &summary.errors {
        eprintln!("ferry: {error}");
    }
    if let Some(error) = summary.errors.iter().find(|e| e.contains("Operation not permitted")) {
        print_hint(error);
    }
    Ok(if summary.errors.is_empty() { 0 } else { 1 })
}

fn exec_remote(client: Client, machine: &str, spec: ExecSpec) -> Result<i32> {
    let detach = spec.detach;
    let forward_stdin = spec.stdin;
    let mut conn = client.request(machine, &Request::Exec(spec))?;
    let started: ExecStarted = conn.recv_reply().map_err(|err| anyhow!("{machine}: {err}"))?;
    if detach {
        println!("{}", json!({ "machine": machine, "pid": started.pid, "log": started.log }));
        return Ok(0);
    }
    exec::run_client(conn, forward_stdin).map_err(|err| anyhow!("{machine}: lost the connection: {err}"))
}

/// Seconds since the epoch as `YYYY-MM-DD HH:MM` (UTC).
fn format_time(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil-from-days, Howard Hinnant's algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02}", rem / 3600, rem % 3600 / 60)
}

fn ls(client: Client, target: &str, json: bool) -> Result<i32> {
    let (machine, path) = match remote(&client, target)? {
        Some(pair) => pair,
        None if client.is_peer(target) => (target.to_string(), String::new()),
        None => bail!("expected machine:path, got {target:?}"),
    };
    let mut conn = client.request(&machine, &Request::List { path })?;
    let listing: Listing = conn.recv_reply().map_err(|err| anyhow!("{machine}: {err}"))?;
    if json {
        println!("{}", serde_json::to_string(&listing)?);
        return Ok(0);
    }
    for entry in &listing.entries {
        let size = if entry.kind == "f" { human_bytes(entry.size) } else { "-".to_string() };
        let suffix = if entry.kind == "d" { "/" } else { "" };
        println!("{} {:>10}  {}  {}{suffix}", entry.kind, size, format_time(entry.mtime), entry.name);
    }
    Ok(0)
}

fn cat(client: Client, target: &str) -> Result<i32> {
    let (machine, path) = need_remote(&client, target)?;
    let mut conn = client.request(&machine, &Request::Read { path })?;
    conn.recv_reply::<()>().map_err(|err| anyhow!("{machine}: {err}"))?;
    let mut stdout = std::io::stdout().lock();
    loop {
        match conn.recv()? {
            (Kind::Data, bytes) => stdout.write_all(bytes)?,
            (Kind::FileEnd, _) => break,
            (got, _) => bail!("{machine}: unexpected {got:?} frame"),
        }
    }
    stdout.flush()?;
    Ok(0)
}

fn write(client: Client, target: &str) -> Result<i32> {
    let (machine, path) = need_remote(&client, target)?;
    let mut conn = client.request(&machine, &Request::Write { path })?;
    conn.recv_reply::<()>().map_err(|err| anyhow!("{machine}: {err}"))?;
    let mut stdin = std::io::stdin().lock();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = stdin.read(&mut buf)?;
        if n == 0 {
            break;
        }
        conn.send(Kind::Data, &buf[..n])?;
    }
    conn.send(Kind::FileEnd, &[])?;
    conn.flush()?;
    let written: Written = conn.recv_reply().map_err(|err| anyhow!("{machine}: {err}"))?;
    println!("wrote {} -> {machine}:{}", human_bytes(written.bytes), written.path);
    Ok(0)
}

struct Reach {
    name: String,
    ip: String,
    os: String,
    arch: String,
    version: String,
    home: String,
    online: bool,
    limited: bool,
    ms: Option<u128>,
    error: Option<String>,
}

/// Contacts every paired machine at once. Each contact also tells that
/// machine about this one, which is how a new machine spreads.
fn reach_all(client: &Client) -> Vec<Reach> {
    let checks: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = client
            .config
            .peers
            .iter()
            .map(|peer| (peer.clone(), scope.spawn(move || client.connect(&peer.name))))
            .collect();
        handles
            .into_iter()
            .map(|(peer, handle)| {
                let result = handle.join().unwrap_or_else(|_| Err(anyhow!("the check crashed")));
                (peer, result)
            })
            .collect()
    });
    checks
        .into_iter()
        .map(|(peer, result)| match result {
            Ok((_, welcome, elapsed)) => Reach {
                name: peer.name,
                ip: peer.ip.to_string(),
                os: welcome.info.os,
                arch: welcome.info.arch,
                version: welcome.info.version,
                home: welcome.info.home,
                limited: welcome.info.limited,
                online: true,
                ms: Some(elapsed.as_millis()),
                error: None,
            },
            Err(err) => Reach {
                name: peer.name,
                ip: peer.ip.to_string(),
                os: peer.os,
                arch: peer.arch,
                version: peer.version,
                home: peer.home,
                limited: false,
                online: false,
                ms: None,
                error: Some(format!("{err:#}")),
            },
        })
        .collect()
}

fn peers(client: Client, json: bool) -> Result<i32> {
    let reached = reach_all(&client);
    if json {
        let list: Vec<_> = reached
            .iter()
            .map(|r| {
                json!({
                    "name": r.name, "ip": r.ip, "os": r.os, "arch": r.arch, "version": r.version,
                    "home": r.home, "online": r.online, "limited": r.limited, "ms": r.ms, "error": r.error,
                })
            })
            .collect();
        println!("{}", json!({ "this": client.config.name, "peers": list }));
        return Ok(0);
    }
    if reached.is_empty() {
        println!("No machines paired yet. Run `ferry pair` here and `ferry pair <code>` on another machine.");
        return Ok(0);
    }
    let width = reached.iter().map(|r| r.name.len()).max().unwrap_or(4).max(4);
    println!("{:width$}  {:8}  {:15}  STATUS", "NAME", "OS", "ADDRESS");
    for r in &reached {
        let state = match r.ms {
            Some(ms) if r.limited => format!("online ({ms} ms, v{}), limited: no Full Disk Access", r.version),
            Some(ms) => format!("online ({ms} ms, v{})", r.version),
            None => "unreachable".to_string(),
        };
        println!("{:width$}  {:8}  {:15}  {state}", r.name, r.os, r.ip);
    }
    println!("\nThis machine: {}", client.config.name);
    if reached.iter().any(|r| r.limited) {
        println!(
            "\nlimited = a Mac whose ferry daemon lacks Full Disk Access. Through it, Desktop, Documents and Downloads\n\
             are refused and tools that sandbox themselves (xcodebuild, swift build, Chrome) fail. Fix on that Mac:\n  {}",
            privacy::GRANT_HELP
        );
    }
    Ok(0)
}

fn daemon_reachable(ip: IpAddr, port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_secs(2)).is_ok()
}

fn listen_ip(config: &config::Config) -> Option<IpAddr> {
    config.bind.or_else(|| daemon::tailscale_ip().map(IpAddr::V4))
}

fn issue_code(paths: Paths, json: bool) -> Result<i32> {
    let config = paths.require()?;
    let ip = match listen_ip(&config) {
        Some(IpAddr::V4(ip)) => ip,
        _ => bail!("Tailscale isn't running on this machine, so there is no address to pair on"),
    };
    if !daemon_reachable(IpAddr::V4(ip), config.port) {
        bail!("the ferry daemon isn't running here: run `ferry install` first");
    }
    let mut secret = [0u8; PAIR_SECRET_LEN];
    random(&mut secret)?;
    paths.save_pairing(&Pairing { secret: hex_encode(&secret), expires: now_secs() + PAIRING_TTL_SECS, attempts: 0 })?;
    let code = config::encode_code(ip, config.port, &secret);
    if json {
        println!("{}", json!({ "code": code, "expires_in_seconds": PAIRING_TTL_SECS, "machine": config.name }));
    } else {
        println!("Pairing code for {} (works once, for {} minutes):\n", config.name, PAIRING_TTL_SECS / 60);
        println!("    {code}\n");
        println!("On the other machine run:\n\n    ferry pair {code}\n");
        println!("That machine gets full access to this one and every machine paired with it, and they to it.");
    }
    Ok(0)
}

fn join(paths: Paths, code: &str, force: bool, json: bool) -> Result<i32> {
    let (_, issuer) = client::join(&paths, code, force)?;
    // Say hello to the rest of the fleet so they can address this machine.
    let client = Client::new(paths)?;
    let reached = reach_all(&client);
    let names: Vec<&str> = reached.iter().map(|r| r.name.as_str()).collect();
    if json {
        println!("{}", json!({ "paired_with": issuer, "machines": names, "this": client.config.name }));
    } else {
        println!("Paired with {issuer}. This machine ({}) can now reach: {}", client.config.name, names.join(", "));
        for r in reached.iter().filter(|r| !r.online) {
            println!("  note: {} isn't reachable right now; it will learn about this machine on first contact", r.name);
        }
    }
    Ok(0)
}

fn forget(paths: Paths, machine: &str) -> Result<i32> {
    let mut config = paths.require()?;
    let before = config.peers.len();
    config.peers.retain(|p| p.name != machine);
    if config.peers.len() == before {
        bail!("no paired machine named {machine:?}");
    }
    if !config.forgotten.iter().any(|n| n == machine) {
        config.forgotten.push(machine.to_string());
    }
    paths.save(&config)?;
    println!("Forgot {machine}. It still holds the fleet key; this only removes it from this machine's list.");
    Ok(0)
}

fn status(paths: Paths, json: bool) -> Result<i32> {
    let config = paths.load()?;
    let ip = config.as_ref().and_then(listen_ip);
    let running = match (&config, ip) {
        (Some(config), Some(ip)) => daemon_reachable(ip, config.port),
        _ => false,
    };
    let registered = service::is_registered(&paths);
    let binary: Option<PathBuf> = std::env::current_exe().ok();
    if json {
        println!(
            "{}",
            json!({
                "name": config.as_ref().map(|c| c.name.clone()),
                "version": VERSION,
                "address": ip.map(|ip| ip.to_string()),
                "port": config.as_ref().map(|c| c.port),
                "daemon_running": running,
                "service_installed": registered,
                "peers": config.as_ref().map(|c| c.peers.iter().map(|p| p.name.clone()).collect::<Vec<_>>()),
                "config": paths.config().display().to_string(),
                "log": paths.log().display().to_string(),
                "binary": binary.map(|b| b.display().to_string()),
            })
        );
        return Ok(if running { 0 } else { 1 });
    }
    match &config {
        None => println!("ferry {VERSION}: not set up here yet. Run `ferry install`."),
        Some(config) => {
            println!("ferry {VERSION} on {}", config.name);
            match ip {
                Some(ip) => println!("  address   {ip}:{}", config.port),
                None => println!("  address   none (Tailscale is not running)"),
            }
            println!("  daemon    {}", if running { "running" } else { "NOT running" });
            println!("  service   {}", if registered { "installed" } else { "not installed (run `ferry install`)" });
            let names: Vec<&str> = config.peers.iter().map(|p| p.name.as_str()).collect();
            println!("  paired    {}", if names.is_empty() { "nothing yet".to_string() } else { names.join(", ") });
            println!("  log       {}", paths.log().display());
        }
    }
    Ok(if running { 0 } else { 1 })
}

fn install(paths: Paths, name: Option<String>, port: Option<u16>) -> Result<i32> {
    let mut config = paths.load_or_init()?;
    let mut changed = false;
    if let Some(name) = name {
        let clean = sanitize_name(&name);
        if clean.is_empty() {
            bail!("a name needs letters or digits");
        }
        changed |= config.name != clean;
        config.name = clean;
    }
    if let Some(port) = port {
        changed |= config.port != port;
        config.port = port;
    }
    if changed {
        paths.save(&config)?;
    }

    let binary = service::place_binary(&paths)?;
    let how = service::register(&paths, &binary)?;

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut running = false;
    while Instant::now() < deadline {
        if listen_ip(&config).is_some_and(|ip| daemon_reachable(ip, config.port)) {
            running = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    println!("ferry {VERSION} installed as {}", config.name);
    println!("  binary    {}", binary.display());
    println!("  service   {how}");
    if !running {
        match listen_ip(&config) {
            None => println!("  daemon    waiting for Tailscale (it starts listening as soon as Tailscale is up)"),
            Some(_) => println!("  daemon    NOT reachable yet; see {}", paths.log().display()),
        }
        return Ok(1);
    }
    println!("  daemon    running");
    if cfg!(target_os = "macos")
        && let Ok(client) = Client::new(paths.clone())
        && let Ok((_, welcome, _)) = client.connect(&config.name)
        && welcome.info.limited
    {
        println!("  access    limited: Desktop, Documents and Downloads are blocked, and tools that sandbox");
        println!("            themselves (xcodebuild, swift build, Chrome) fail, until you grant Full Disk Access:");
        println!("            {}", privacy::GRANT_HELP);
    }
    let on_path = std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| Some(dir.as_path()) == binary.parent()));
    if !on_path {
        println!("  note      {} is not on PATH in this shell", binary.parent().map(|d| d.display().to_string()).unwrap_or_default());
    }
    if config.peers.is_empty() {
        println!("\nNext: run `ferry pair` here and enter the code on another machine (or the other way round).");
    }
    Ok(0)
}
