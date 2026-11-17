//! Outgoing connections: find a peer in the address book, connect, prove the
//! fleet key, and keep the address book fresh from what the peer reports.

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};

use crate::config::{Config, Key, Paths, Peer, hex_decode};
use crate::daemon::{node_info, tailscale_ip};
use crate::proto::{CONNECT_TIMEOUT, Conn, HelloMode, ProtoError, Request, Welcome, client_handshake, pair_key, xor32};

pub struct Client {
    pub paths: Paths,
    pub config: Config,
}

impl Client {
    pub fn new(paths: Paths) -> Result<Self> {
        let config = paths.require()?;
        Ok(Self { paths, config })
    }

    /// This machine as a peer, so `ferry … <own name>:path` works too.
    fn this_machine(&self) -> Result<Peer> {
        let ip = match self.config.bind {
            Some(IpAddr::V4(ip)) => ip,
            _ => tailscale_ip().context("Tailscale isn't running on this machine")?,
        };
        Ok(Peer {
            name: self.config.name.clone(),
            ip,
            port: self.config.port,
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            version: crate::config::VERSION.into(),
            home: self.paths.home.display().to_string(),
        })
    }

    pub fn peer(&self, name: &str) -> Result<Peer> {
        if name == self.config.name {
            return self.this_machine();
        }
        self.config.peer(name).cloned().ok_or_else(|| {
            let known: Vec<&str> = self.config.peers.iter().map(|p| p.name.as_str()).collect();
            if known.is_empty() {
                anyhow!("unknown machine {name:?}: nothing is paired yet (run `ferry pair`)")
            } else {
                anyhow!("unknown machine {name:?}. Paired machines: {}", known.join(", "))
            }
        })
    }

    pub fn is_peer(&self, name: &str) -> bool {
        name == self.config.name || self.config.peer(name).is_some()
    }

    /// Connects and authenticates. Returns the connection and how long the
    /// round trip took.
    pub fn connect(&self, name: &str) -> Result<(Conn, Welcome, Duration)> {
        let peer = self.peer(name)?;
        let started = Instant::now();
        let mut conn = dial(&peer)?;
        let me = node_info(&self.config, &self.paths);
        let (welcome, _pad) = client_handshake(&mut conn, &me, HelloMode::Fleet, self.config.key.as_bytes())
            .map_err(|err| explain(&peer, err))?;
        let elapsed = started.elapsed();
        self.learn(&peer, &welcome);
        Ok((conn, welcome, elapsed))
    }

    /// Connects and sends one request.
    pub fn request(&self, name: &str, request: &Request) -> Result<Conn> {
        let (mut conn, _, _) = self.connect(name)?;
        conn.send_json(request)?;
        Ok(conn)
    }

    /// Folds what a peer reported about itself and its peers into the
    /// address book, so one pairing reaches the whole fleet.
    fn learn(&self, peer: &Peer, welcome: &Welcome) {
        // `ferry peers` contacts every machine at once; one writer at a time.
        static WRITING: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = WRITING.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Ok(Some(mut config)) = self.paths.load() else { return };
        let mut changed = false;
        if peer.name != config.name {
            changed |= config.upsert_peer(Peer {
                name: peer.name.clone(),
                ip: peer.ip,
                port: welcome.info.port,
                os: welcome.info.os.clone(),
                arch: welcome.info.arch.clone(),
                version: welcome.info.version.clone(),
                home: welcome.info.home.clone(),
            });
        }
        for other in &welcome.peers {
            if config.peer(&other.name).is_none() && !config.forgotten.contains(&other.name) {
                changed |= config.upsert_peer(other.clone());
            }
        }
        if changed && let Err(err) = self.paths.save(&config) {
            eprintln!("ferry: could not update the peer list: {err:#}");
        }
    }
}

fn dial(peer: &Peer) -> Result<Conn> {
    let addr = SocketAddr::new(IpAddr::V4(peer.ip), peer.port);
    let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(|err| {
        anyhow!(
            "can't reach {} at {addr}: {err}. Check that the machine is on, on the tailnet, and that `ferry status` there shows the daemon running.",
            peer.name
        )
    })?;
    Ok(Conn::new(stream)?)
}

fn explain(peer: &Peer, err: ProtoError) -> anyhow::Error {
    match err {
        ProtoError::Auth(message) => anyhow!("{}: {message}", peer.name),
        other => anyhow!("{}: {other}", peer.name),
    }
}

/// Joins the fleet of the machine that issued `code`.
pub fn join(paths: &Paths, code: &str, force: bool) -> Result<(Config, String)> {
    let (ip, port, secret) = crate::config::decode_code(code)
        .context("that doesn't look like a pairing code (expected 18 characters like K3F9QA-7ZP2M4-X81C0D)")?;
    if !crate::daemon::is_tailnet(ip) && !ip.is_loopback() {
        bail!("that pairing code isn't valid (check for a typo)");
    }
    let mut config = paths.load_or_init()?;
    if !config.peers.is_empty() && !force {
        bail!(
            "this machine is already paired with {}. To add a machine, run `ferry pair` here and enter the code there. \
             To leave this fleet and join another, add --force.",
            config.peers.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", ")
        );
    }
    let issuer = Peer { name: "the other machine".into(), ip, port, os: String::new(), arch: String::new(), version: String::new(), home: String::new() };
    let mut conn = dial(&issuer)?;
    let me = node_info(&config, paths);
    let key = pair_key(&secret);
    let (welcome, pad) = client_handshake(&mut conn, &me, HelloMode::Pair, &key).map_err(|err| anyhow!("{err}"))?;
    let grant = welcome.grant.as_deref().and_then(hex_decode).and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
    let grant = grant.context("the other machine did not send a fleet key")?;

    config.key = Key::from_bytes(xor32(&grant, &pad));
    config.peers.clear();
    config.forgotten.clear();
    let issuer_name = welcome.info.name.clone();
    config.upsert_peer(Peer {
        name: issuer_name.clone(),
        ip,
        port: welcome.info.port,
        os: welcome.info.os,
        arch: welcome.info.arch,
        version: welcome.info.version,
        home: welcome.info.home,
    });
    for other in welcome.peers {
        config.upsert_peer(other);
    }
    paths.save(&config)?;
    Ok((config, issuer_name))
}
