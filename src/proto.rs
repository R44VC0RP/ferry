//! Wire format: a magic prefix, a mutual HMAC handshake, then typed frames.
//!
//! Confidentiality comes from the tailnet (WireGuard). This layer only proves
//! that both ends hold the fleet key, so another device on the tailnet can't
//! drive the daemon.

use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{Peer, hex_decode, hex_encode};

pub const MAGIC: &[u8; 6] = b"FERRY1";
pub const PROTO_VERSION: u32 = 1;
/// Largest frame either side will allocate for.
pub const MAX_FRAME: usize = 64 * 1024 * 1024;
/// File data travels in chunks of this size.
pub const CHUNK: usize = 1024 * 1024;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const SOCKET_BUFFER: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("connection closed")]
    Closed,
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("frame of {len} bytes is over the {max} byte limit")]
    FrameTooLarge { len: usize, max: usize },
    #[error("unknown frame kind {0}")]
    UnknownKind(u8),
    #[error("unexpected {got:?} frame while waiting for {want}")]
    Unexpected { got: Kind, want: &'static str },
    #[error("malformed message: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Auth(String),
    /// The operation failed, on this side or the other; the text says why.
    #[error("{0}")]
    Failed(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Json = 1,
    Data = 2,
    DataLz4 = 3,
    FileBegin = 4,
    FileEnd = 5,
    FileAbort = 6,
    Need = 7,
    Stdin = 8,
    StdinEof = 9,
    Stdout = 10,
    Stderr = 11,
}

impl Kind {
    fn from_byte(byte: u8) -> Result<Self, ProtoError> {
        Ok(match byte {
            1 => Self::Json,
            2 => Self::Data,
            3 => Self::DataLz4,
            4 => Self::FileBegin,
            5 => Self::FileEnd,
            6 => Self::FileAbort,
            7 => Self::Need,
            8 => Self::Stdin,
            9 => Self::StdinEof,
            10 => Self::Stdout,
            11 => Self::Stderr,
            other => return Err(ProtoError::UnknownKind(other)),
        })
    }
}

pub fn write_frame(w: &mut impl Write, kind: Kind, payload: &[u8]) -> Result<(), ProtoError> {
    if payload.len() > MAX_FRAME {
        return Err(ProtoError::FrameTooLarge { len: payload.len(), max: MAX_FRAME });
    }
    let mut header = [0u8; 5];
    header[0] = kind as u8;
    header[1..].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    w.write_all(&header)?;
    w.write_all(payload)?;
    Ok(())
}

/// Builds header and payload into one buffer, for writers that are shared
/// between threads and must not interleave.
pub fn encode_frame(kind: Kind, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.push(kind as u8);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

pub fn read_frame(r: &mut impl Read, buf: &mut Vec<u8>) -> Result<Kind, ProtoError> {
    let mut header = [0u8; 5];
    match r.read_exact(&mut header) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Err(ProtoError::Closed),
        Err(err) => return Err(err.into()),
    }
    let kind = Kind::from_byte(header[0])?;
    let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_FRAME {
        return Err(ProtoError::FrameTooLarge { len, max: MAX_FRAME });
    }
    buf.resize(len, 0);
    match r.read_exact(buf) {
        Ok(()) => Ok(kind),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Err(ProtoError::Closed),
        Err(err) => Err(err.into()),
    }
}

/// A buffered, framed connection.
pub struct Conn {
    r: BufReader<TcpStream>,
    w: BufWriter<TcpStream>,
    buf: Vec<u8>,
}

impl Conn {
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        let keepalive = socket2::TcpKeepalive::new().with_time(KEEPALIVE_IDLE).with_interval(KEEPALIVE_INTERVAL);
        socket2::SockRef::from(&stream).set_tcp_keepalive(&keepalive)?;
        let reader = stream.try_clone()?;
        Ok(Self {
            r: BufReader::with_capacity(SOCKET_BUFFER, reader),
            w: BufWriter::with_capacity(SOCKET_BUFFER, stream),
            buf: Vec::new(),
        })
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.r.get_ref().set_read_timeout(timeout)
    }

    /// Queues a frame. Call `flush` before waiting for the other side.
    pub fn send(&mut self, kind: Kind, payload: &[u8]) -> Result<(), ProtoError> {
        write_frame(&mut self.w, kind, payload)
    }

    pub fn flush(&mut self) -> Result<(), ProtoError> {
        self.w.flush()?;
        Ok(())
    }

    pub fn send_json<T: Serialize>(&mut self, value: &T) -> Result<(), ProtoError> {
        let bytes = serde_json::to_vec(value)?;
        self.send(Kind::Json, &bytes)?;
        self.flush()
    }

    pub fn recv(&mut self) -> Result<(Kind, &[u8]), ProtoError> {
        let kind = read_frame(&mut self.r, &mut self.buf)?;
        Ok((kind, &self.buf))
    }

    pub fn recv_json<T: DeserializeOwned>(&mut self) -> Result<T, ProtoError> {
        match self.recv()? {
            (Kind::Json, bytes) => Ok(serde_json::from_slice(bytes)?),
            (got, _) => Err(ProtoError::Unexpected { got, want: "a control message" }),
        }
    }

    /// Reads a reply and turns a remote error into `ProtoError::Failed`.
    pub fn recv_reply<T: DeserializeOwned>(&mut self) -> Result<T, ProtoError> {
        match self.recv_json::<Reply<T>>()? {
            Reply::Ok(value) => Ok(value),
            Reply::Err(message) => Err(ProtoError::Failed(message)),
        }
    }

    pub fn send_ok<T: Serialize>(&mut self, value: T) -> Result<(), ProtoError> {
        self.send_json(&Reply::Ok(value))
    }

    pub fn send_err(&mut self, message: impl Into<String>) -> Result<(), ProtoError> {
        self.send_json(&Reply::<()>::Err(message.into()))
    }

    /// Splits into a reader and a raw writer, for the exec stream where
    /// several threads write.
    pub fn into_split(mut self) -> Result<(BufReader<TcpStream>, TcpStream), ProtoError> {
        self.w.flush()?;
        let writer = self.r.get_ref().try_clone()?;
        Ok((self.r, writer))
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Reply<T> {
    Ok(T),
    Err(String),
}

// --- handshake -----------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HelloMode {
    /// A normal request, authenticated with the fleet key.
    Fleet,
    /// A machine joining the fleet, authenticated with a pairing code.
    Pair,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeInfo {
    pub name: String,
    pub port: u16,
    pub os: String,
    pub arch: String,
    pub version: String,
    pub home: String,
    /// A Mac daemon without Full Disk Access: Desktop, Documents, Downloads
    /// and sandbox-using tools are unavailable through it.
    #[serde(default)]
    pub limited: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Hello {
    pub v: u32,
    pub mode: HelloMode,
    pub nonce: String,
    pub info: NodeInfo,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Challenge {
    pub nonce: String,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Proof {
    pub mac: String,
}

#[derive(Serialize, Deserialize)]
pub struct Welcome {
    pub mac: String,
    pub info: NodeInfo,
    pub peers: Vec<Peer>,
    /// The fleet key, masked with a pad derived from the pairing secret.
    /// Present only when pairing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
}

type HmacSha256 = Hmac<Sha256>;

/// HMAC over a label and length-prefixed parts, so parts can't run together.
fn mac_state(key: &[u8], label: &str, parts: &[&[u8]]) -> HmacSha256 {
    // HMAC accepts a key of any length, so this cannot fail.
    #[allow(clippy::expect_used)]
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(label.as_bytes());
    for part in parts {
        mac.update(&(part.len() as u64).to_le_bytes());
        mac.update(part);
    }
    mac
}

pub fn mac(key: &[u8], label: &str, parts: &[&[u8]]) -> [u8; 32] {
    mac_state(key, label, parts).finalize().into_bytes().into()
}

/// Constant-time check of a hex tag.
pub fn mac_verify(key: &[u8], label: &str, parts: &[&[u8]], tag_hex: &str) -> bool {
    match hex_decode(tag_hex) {
        Some(tag) => mac_state(key, label, parts).verify_slice(&tag).is_ok(),
        None => false,
    }
}

/// Stretches a short pairing secret into a handshake key.
pub fn pair_key(secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ferry-pair-v1");
    hasher.update(secret);
    hasher.finalize().into()
}

pub const LABEL_CLIENT: &str = "ferry-client";
pub const LABEL_SERVER: &str = "ferry-server";
pub const LABEL_WRAP: &str = "ferry-wrap";

pub fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = a[i] ^ b[i];
    }
    out
}

/// Runs the client side of the handshake. On success both ends have proved
/// they hold `key`.
pub fn client_handshake(
    conn: &mut Conn,
    me: &NodeInfo,
    mode: HelloMode,
    key: &[u8; 32],
) -> Result<(Welcome, [u8; 32]), ProtoError> {
    conn.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|err| ProtoError::Failed(format!("no system randomness: {err}")))?;
    let nonce_c = hex_encode(&nonce);

    conn.w.write_all(MAGIC)?;
    conn.send_json(&Hello { v: PROTO_VERSION, mode, nonce: nonce_c.clone(), info: me.clone() })?;

    let challenge: Challenge = conn.recv_reply()?;
    let parts: [&[u8]; 4] =
        [nonce_c.as_bytes(), challenge.nonce.as_bytes(), me.name.as_bytes(), challenge.name.as_bytes()];
    conn.send_json(&Proof { mac: hex_encode(&mac(key, LABEL_CLIENT, &parts)) })?;

    let welcome: Welcome = match conn.recv_reply() {
        Ok(welcome) => welcome,
        Err(ProtoError::Failed(message)) => return Err(ProtoError::Auth(message)),
        Err(other) => return Err(other),
    };
    if !mac_verify(key, LABEL_SERVER, &parts, &welcome.mac) {
        return Err(ProtoError::Auth(format!("{} could not prove it holds the fleet key", challenge.name)));
    }
    let pad = mac(key, LABEL_WRAP, &parts[..2]);
    conn.set_read_timeout(None)?;
    Ok((welcome, pad))
}

// --- requests ------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Ping,
    Push { dest: String, force: bool },
    Pull { sources: Vec<String>, excludes: Vec<String>, gitignore: bool },
    List { path: String },
    Read { path: String },
    Write { path: String },
    Exec(ExecSpec),
}

impl Request {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Push { .. } => "push",
            Self::Pull { .. } => "pull",
            Self::List { .. } => "list",
            Self::Read { .. } => "read",
            Self::Write { .. } => "write",
            Self::Exec(_) => "exec",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ExecSpec {
    /// Program and arguments, run without a shell.
    #[serde(default)]
    pub argv: Vec<String>,
    /// A script to run through `shell` instead of `argv`.
    #[serde(default)]
    pub script: Option<String>,
    #[serde(default)]
    pub shell: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub detach: bool,
    #[serde(default)]
    pub stdin: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExecStarted {
    pub pid: u32,
    /// Set for detached jobs: where the output is being written.
    #[serde(default)]
    pub log: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExecExit {
    pub code: Option<i32>,
    #[serde(default)]
    pub signal: Option<i32>,
    #[serde(default)]
    pub timed_out: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ListEntry {
    pub name: String,
    /// "f", "d" or "l".
    pub kind: String,
    pub size: u64,
    pub mtime: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Listing {
    pub path: String,
    pub entries: Vec<ListEntry>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Written {
    pub path: String,
    pub bytes: u64,
}
