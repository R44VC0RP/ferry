//! On-disk state: this machine's name, the fleet key and the address book.

use std::fmt;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

pub const DEFAULT_PORT: u16 = 7433;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// How long a pairing code stays valid, and how many wrong guesses it survives.
pub const PAIRING_TTL_SECS: u64 = 600;
pub const PAIRING_MAX_ATTEMPTS: u32 = 5;

/// The 32-byte secret every machine in the fleet shares.
#[derive(Clone, PartialEq, Eq)]
pub struct Key([u8; 32]);

impl Key {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; 32];
        random(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

impl Serialize for Key {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex_encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        let bytes = hex_decode(&text).ok_or_else(|| serde::de::Error::custom("key is not hex"))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("key must be 32 bytes"))?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Peer {
    pub name: String,
    pub ip: Ipv4Addr,
    pub port: u16,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub home: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub name: String,
    pub port: u16,
    pub key: Key,
    /// Listen address override. Unset means "the Tailscale address", which is
    /// what every real install uses; this exists for local testing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind: Option<IpAddr>,
    #[serde(default)]
    pub peers: Vec<Peer>,
    #[serde(default)]
    pub forgotten: Vec<String>,
}

impl Config {
    pub fn peer(&self, name: &str) -> Option<&Peer> {
        self.peers.iter().find(|p| p.name == name)
    }

    /// Adds or updates a peer. Returns true when something changed.
    pub fn upsert_peer(&mut self, peer: Peer) -> bool {
        if peer.name == self.name {
            return false;
        }
        match self.peers.iter_mut().find(|p| p.name == peer.name) {
            Some(existing) if *existing == peer => false,
            Some(existing) => {
                *existing = peer;
                true
            }
            None => {
                self.forgotten.retain(|n| *n != peer.name);
                self.peers.push(peer);
                self.peers.sort_by(|a, b| a.name.cmp(&b.name));
                true
            }
        }
    }
}

/// A pairing code waiting to be used, written by `ferry pair` and consumed by
/// the daemon.
#[derive(Serialize, Deserialize)]
pub struct Pairing {
    pub secret: String,
    pub expires: u64,
    #[serde(default)]
    pub attempts: u32,
}

impl fmt::Debug for Pairing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pairing")
            .field("secret", &"<redacted>")
            .field("expires", &self.expires)
            .field("attempts", &self.attempts)
            .finish()
    }
}

/// Where everything lives. Built once in `main` from the environment.
#[derive(Clone, Debug)]
pub struct Paths {
    pub dir: PathBuf,
    pub home: PathBuf,
}

impl Paths {
    pub fn from_env() -> Result<Self> {
        let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .map(PathBuf::from)
            .context("can't find the home directory (HOME / USERPROFILE is unset)")?;
        let dir = std::env::var_os("FERRY_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".ferry"));
        Ok(Self { dir, home })
    }

    pub fn config(&self) -> PathBuf {
        self.dir.join("config.json")
    }

    pub fn pairing(&self) -> PathBuf {
        self.dir.join("pairing.json")
    }

    pub fn log(&self) -> PathBuf {
        self.dir.join("daemon.log")
    }

    pub fn jobs(&self) -> PathBuf {
        self.dir.join("jobs")
    }

    pub fn load(&self) -> Result<Option<Config>> {
        let path = self.config();
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
        };
        let config = serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        Ok(Some(config))
    }

    /// Loads the config, or explains how to create one.
    pub fn require(&self) -> Result<Config> {
        match self.load()? {
            Some(config) => Ok(config),
            None => bail!("ferry isn't set up on this machine yet: run `ferry install`"),
        }
    }

    pub fn load_or_init(&self) -> Result<Config> {
        if let Some(config) = self.load()? {
            return Ok(config);
        }
        let config = Config {
            name: default_name(),
            port: DEFAULT_PORT,
            key: Key::generate()?,
            bind: None,
            peers: Vec::new(),
            forgotten: Vec::new(),
        };
        self.save(&config)?;
        Ok(config)
    }

    pub fn save(&self, config: &Config) -> Result<()> {
        let text = serde_json::to_string_pretty(config)?;
        write_private(&self.config(), text.as_bytes())
    }

    pub fn load_pairing(&self) -> Option<Pairing> {
        let text = fs::read_to_string(self.pairing()).ok()?;
        serde_json::from_str(&text).ok()
    }

    pub fn save_pairing(&self, pairing: &Pairing) -> Result<()> {
        write_private(&self.pairing(), serde_json::to_string(pairing)?.as_bytes())
    }

    pub fn clear_pairing(&self) {
        // A missing file is the state we want, so the error carries nothing.
        if let Err(err) = fs::remove_file(self.pairing())
            && err.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(%err, "could not remove the used pairing code");
        }
    }
}

/// Writes a file only its owner can read, replacing it atomically.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("path has no parent")?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
        file.write_all(bytes)?;
    }
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

pub fn default_name() -> String {
    let host = gethostname::gethostname().to_string_lossy().to_lowercase();
    let short = host.split('.').next().unwrap_or("").to_string();
    let clean = sanitize_name(&short);
    if clean.is_empty() { "machine".to_string() } else { clean }
}

pub fn sanitize_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|err| anyhow::anyhow!("no system randomness: {err}"))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

pub fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    text.as_bytes()
        .chunks(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

// --- pairing codes -------------------------------------------------------

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
pub const PAIR_SECRET_LEN: usize = 5;

/// A pairing code packs the issuer's address and a one-time secret into 18
/// Crockford base32 characters, so the joiner needs nothing else.
pub fn encode_code(ip: Ipv4Addr, port: u16, secret: &[u8; PAIR_SECRET_LEN]) -> String {
    let mut bytes = Vec::with_capacity(11);
    bytes.extend_from_slice(&ip.octets());
    bytes.extend_from_slice(&port.to_be_bytes());
    bytes.extend_from_slice(secret);
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for byte in bytes {
        acc = acc << 8 | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[(acc >> bits & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[(acc << (5 - bits) & 31) as usize] as char);
    }
    let groups: Vec<&str> = out.as_bytes().chunks(6).filter_map(|c| std::str::from_utf8(c).ok()).collect();
    groups.join("-")
}

pub fn decode_code(code: &str) -> Option<(Ipv4Addr, u16, [u8; PAIR_SECRET_LEN])> {
    let mut bytes = Vec::with_capacity(12);
    let (mut acc, mut bits) = (0u32, 0u32);
    let mut count = 0;
    for c in code.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };
        let value = ALPHABET.iter().position(|a| *a as char == c)? as u32;
        count += 1;
        acc = (acc << 5 | value) & 0xFFFF;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((acc >> bits & 0xFF) as u8);
        }
    }
    if count != 18 || bytes.len() != 11 {
        return None;
    }
    let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    let port = u16::from_be_bytes([bytes[4], bytes[5]]);
    let secret: [u8; PAIR_SECRET_LEN] = bytes[6..11].try_into().ok()?;
    Some((ip, port, secret))
}
