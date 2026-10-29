// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Private Linux process adapter. No changes to the CSQTT wire protocol.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, atomic::{AtomicBool, Ordering}},
    time::{SystemTime, UNIX_EPOCH, Duration},
};
use tokio_util::sync::CancellationToken;

static RUNTIME: OnceLock<Arc<Runtime>> = OnceLock::new();
const MAX_CONFIG: u64 = 65_536;
// Matches the broker RPC bound and accommodates a 16 KiB result plus JSON
// escaping, field names and the challenge ID.
const MAX_CONTROL: u64 = 65_536;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketAdapter {
    #[default]
    Udp,
    Tun,
}

/// This is a private, same-host packet transport, never a LAN listener. Both
/// endpoints must be fixed so another datagram cannot replace the return peer.
pub fn validate_packet_endpoints(listen: SocketAddr, peer: SocketAddr) -> Result<()> {
    if listen.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST)
        || peer.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST)
        || listen.port() == 0 || peer.port() == 0 || listen == peer
    {
        bail!("packet endpoints must be distinct fixed IPv4 loopback ports");
    }
    Ok(())
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub peer: String,
    pub password: String,
    pub vk_hashes: Vec<String>,
    pub workers: usize,
    pub obfs: String,
    pub turn_transport: String,
    pub turn_host: String,
    pub turn_port: Option<u16>,
    pub vk_auth_mode: String,
    pub fingerprint: String,
    pub client_ids: String,
    pub device_id: Option<String>,
    pub packet_adapter: PacketAdapter,
    pub packet_listen: SocketAddr,
    pub packet_peer: SocketAddr,
    pub tun_device: String,
    pub tun_config_hook: PathBuf,
    pub status_file: PathBuf,
    pub control_socket: PathBuf,
    pub identity_file: PathBuf,
    pub captcha_timeout_secs: u64,
    pub captcha_auto_attempts: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            peer: String::new(), password: String::new(), vk_hashes: Vec::new(),
            workers: 9, obfs: "video".into(), turn_transport: "udp".into(),
            turn_host: String::new(), turn_port: None, vk_auth_mode: "vkcalls".into(),
            fingerprint: "firefox".into(), client_ids: "8202606,6287487".into(),
            device_id: None, packet_adapter: PacketAdapter::Udp,
            packet_listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 39000)),
            packet_peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 39001)),
            tun_device: "csqtt0".into(),
            tun_config_hook: "/opt/libexec/csqtt/tun-hook".into(),
            status_file: "/opt/var/run/csqtt/status.json".into(),
            control_socket: "/opt/var/run/csqtt/control.sock".into(),
            identity_file: "/opt/etc/csqtt/identity.json".into(), captcha_timeout_secs: 180,
            captcha_auto_attempts: 3,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        validate_packet_endpoints(self.packet_listen, self.packet_peer)?;
        if self.peer.len() > 255 || self.peer.rsplit_once(':')
            .is_none_or(|(host, port)| !valid_host(host) || port.parse::<u16>().ok().is_none_or(|p| p == 0)) {
            bail!("peer must be a host and port");
        }
        if !(4..=128).contains(&self.password.len()) || self.password.contains('|') || self.password.chars().any(char::is_control) {
            bail!("password must be 4..128 bytes without control delimiters");
        }
        if self.vk_hashes.is_empty() || self.vk_hashes.len() > 6
            || self.vk_hashes.iter().any(|v| v.len() > 2048) {
            bail!("provide 1..6 VK call hashes or links");
        }
        let hashes = crate::worker::parse_hashes(&self.vk_hashes.join(","));
        if hashes.len() != self.vk_hashes.len() || hashes.is_empty() || hashes.len() > 6 || hashes.iter().any(|h|
            h.len() < 16 || h.len() > 1024 || !h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')) {
            bail!("invalid VK call hash");
        }
        let max_workers = (hashes.len() * 27).min(126);
        if self.workers < 9 || self.workers > max_workers || self.workers % 9 != 0 {
            bail!("workers must be a multiple of 9 within the hash capacity");
        }
        crate::obfs::ObfsMode::parse(&self.obfs).map_err(|_| anyhow::anyhow!("invalid obfuscation mode"))?;
        crate::turn_endpoint::TurnTransportMode::parse(&self.turn_transport).map_err(|_| anyhow::anyhow!("invalid TURN transport"))?;
        if !matches!(self.vk_auth_mode.as_str(), "vkcalls" | "legacy") {
            bail!("daemon supports vkcalls or legacy authentication");
        }
        if !matches!(self.fingerprint.as_str(), "firefox" | "chrome" | "edge" | "safari" | "opera") {
            bail!("invalid browser fingerprint");
        }
        if self.client_ids.len() > 128 || self.client_ids.split(',').any(|id|
            id.is_empty() || !id.bytes().all(|c| c.is_ascii_digit())) {
            bail!("invalid client IDs");
        }
        if self.turn_port == Some(0) || self.turn_host.len() > 255 || self.turn_host.contains(['\n', '\r', '/', '|', '\0']) {
            bail!("invalid TURN override");
        }
        if !(30..=600).contains(&self.captcha_timeout_secs) { bail!("invalid CAPTCHA timeout"); }
        if self.captcha_auto_attempts > 3 { bail!("invalid CAPTCHA automatic attempt count"); }
        crate::linux_tun::validate_name(&self.tun_device)?;
        for path in [&self.tun_config_hook, &self.status_file, &self.control_socket, &self.identity_file] {
            if !path.is_absolute() || path.components().any(|p| p == std::path::Component::ParentDir) {
                bail!("daemon paths must be absolute without parent components");
            }
        }
        if self.status_file == self.identity_file || self.status_file == self.control_socket
            || self.identity_file == self.control_socket || self.tun_config_hook == self.status_file
            || self.tun_config_hook == self.identity_file || self.tun_config_hook == self.control_socket {
            bail!("daemon paths must be distinct");
        }
        if let Some(id) = &self.device_id { validate_device_id(id)?; }
        Ok(())
    }
}

fn valid_host(host: &str) -> bool {
    if let Some(ip) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return ip.parse::<std::net::Ipv6Addr>().is_ok();
    }
    if host.parse::<IpAddr>().is_ok() { return !host.contains(':'); }
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty() && host.len() <= 253 && host.split('.').all(|label|
        !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-')
            && label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
}

fn validate_device_id(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 128 || !value.bytes().all(|b|
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')) {
        bail!("invalid persistent device identity");
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity { device_id: String, generation: u64 }

#[derive(Clone, Serialize)]
pub struct Status {
    schema_version: u8,
    generation: u64,
    packet_adapter: PacketAdapter,
    state: String,
    pid: u32,
    // Private ownership metadata. Public RPC must keep its explicit allowlist.
    process_startticks: u64,
    boot_id: String,
    updated_boottime_ms: u64,
    uptime_secs: u64,
    tun_device: String,
    tunnel_ip: Option<Ipv4Addr>,
    dns: Vec<Ipv4Addr>,
    active_workers: i64,
    bytes_up: i64,
    bytes_down: i64,
    captcha: Option<Value>,
    error_code: Option<String>,
    updated_at: u64,
    health: Health,
}

#[derive(Clone, Default, Serialize)]
struct Health {
    auth_phase: &'static str,
    auth_inflight: u64,
    auth_network_inflight: u64,
    auth_attempts: u64,
    auth_successes: u64,
    auth_failures: u64,
    auth_cancelled: u64,
    fresh_auth_retries: u64,
    human_epoch: u64,
    auth_progress_age_secs: Option<u64>,
    peer_progress_age_secs: Option<u64>,
    liveness_probes: u64,
    liveness_replies: u64,
    liveness_misses: u64,
    liveness_timeouts: u64,
    network_timeout_events: u64,
    unavailable_calls: u64,
    session_errors: u64,
    last_session_error: Option<&'static str>,
    #[serde(skip)]
    last_auth_progress_ms: Option<u64>,
    #[serde(skip)]
    last_peer_progress_ms: Option<u64>,
}

pub struct Runtime {
    pub config: Config,
    status: Mutex<Status>,
    _identity_lock: File,
    // Serializes up/down scripts and prevents a cancelled up hook from running
    // after the shutdown hook. Process kill_on_drop also applies on cancellation.
    hook_lock: tokio::sync::Mutex<()>,
    control_owned: AtomicBool,
    tun_owned: AtomicBool,
    started: std::time::Instant,
}

pub fn current() -> Option<&'static Arc<Runtime>> { RUNTIME.get() }
pub fn enabled() -> bool { current().is_some() }
pub fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }

pub fn boottime_ms() -> u64 {
    #[cfg(target_os = "linux")] {
        let mut time = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } == 0 {
            return (time.tv_sec as u64).saturating_mul(1_000)
                .saturating_add(time.tv_nsec as u64 / 1_000_000);
        }
    }
    0
}

fn process_startticks() -> u64 {
    // Select the kernel TGID leader even when called from a worker thread.
    // QEMU 8.2.2 synthesizes both /proc/self/stat and /proc/<pid>/stat using
    // TaskState::start_boottime; the explicit task path retains kernel ticks.
    // https://github.com/qemu/qemu/blob/v8.2.2/linux-user/syscall.c#L7632-L7668
    // https://github.com/qemu/qemu/blob/v8.2.2/linux-user/syscall.c#L7699-L7720
    let pid = std::process::id();
    std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/stat")).ok()
        .and_then(|stat| stat.rsplit_once(')').map(|(_, fields)| fields.to_owned()))
        .and_then(|fields| fields.split_whitespace().nth(19).and_then(|field| field.parse().ok()))
        .unwrap_or(0)
}

fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default().trim().to_owned()
}

fn secure_open(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)] {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            bail!("private file must be owned by the daemon user and mode 0600");
        }
        return Ok(file);
    }
    #[cfg(not(unix))] { Ok(options.open(path)?) }
}

fn read_private(path: &Path) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    secure_open(path)?.take(MAX_CONFIG + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_CONFIG { bail!("private file is too large"); }
    Ok(data)
}

fn private_parent(path: &Path) -> Result<&Path> {
    let parent = path.parent().context("missing parent directory")?;
    if !parent.exists() {
        #[cfg(unix)] {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).recursive(true).create(parent)?;
        }
        #[cfg(not(unix))] std::fs::create_dir_all(parent)?;
    }
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() { bail!("unsafe runtime directory"); }
    #[cfg(unix)] {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o022 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            bail!("runtime directory must be owned by daemon user and not writable by other users");
        }
    }
    Ok(parent)
}

fn write_private<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = private_parent(path)?;
    let temporary = parent.join(format!(".csqtt-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let result = (|| -> Result<()> {
        let mut file = options.open(&temporary)?;
        serde_json::to_writer(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() { let _ = std::fs::remove_file(&temporary); }
    result
}

fn reserve_identity(config: &Config) -> Result<(Identity, File)> {
    private_parent(&config.identity_file)?;
    let lock_path = config.identity_file.with_extension("lock");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let lock = options.open(lock_path)?;
    #[cfg(unix)] {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let metadata = lock.metadata()?;
        if !metadata.is_file() || metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            bail!("unsafe identity lock");
        }
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            bail!("another client owns the persistent identity");
        }
    }
    let mut identity: Identity = match read_private(&config.identity_file) {
        Ok(bytes) => serde_json::from_slice(&bytes).context("invalid identity file; refusing to replace it")?,
        Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            Identity { device_id: config.device_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string()), generation: 0 },
        Err(error) => return Err(error),
    };
    validate_device_id(&identity.device_id)?;
    if config.device_id.as_ref().is_some_and(|id| id != &identity.device_id) {
        bail!("configured identity differs from persisted identity");
    }
    identity.generation = identity.generation.checked_add(1).context("identity generation exhausted")?;
    write_private(&config.identity_file, &identity)?;
    Ok((identity, lock))
}

pub fn prepare(arguments: &mut crate::Arguments) -> Result<()> {
    let Some(path) = arguments.config_file.as_ref() else { return Ok(()); };
    if !cfg!(target_os = "linux") { bail!("daemon mode requires Linux"); }
    let config: Config = serde_json::from_slice(&read_private(path)?)
        .map_err(|_| anyhow::anyhow!("invalid daemon configuration JSON"))?;
    config.validate()?;
    private_parent(&config.status_file)?;
    private_parent(&config.control_socket)?;
    let (identity, lock) = reserve_identity(&config)?;
    arguments.peer = config.peer.clone();
    arguments.password = config.password.clone();
    arguments.vk = config.vk_hashes.join(",");
    arguments.vk_hash_mode = "manual".into();
    arguments.workers = config.workers;
    arguments.allow_hash_redistribution = false;
    arguments.device_id = identity.device_id;
    arguments.generation = identity.generation;
    arguments.salt = uuid::Uuid::new_v4().to_string();
    arguments.obfs = config.obfs.clone();
    arguments.turn_transport = config.turn_transport.clone();
    arguments.turn = config.turn_host.clone();
    arguments.port = config.turn_port.map(|p| p.to_string()).unwrap_or_default();
    arguments.vk_auth_mode = config.vk_auth_mode.clone();
    arguments.fingerprint = config.fingerprint.clone();
    arguments.client_ids = config.client_ids.clone();
    arguments.captcha_mode = "auto".into();
    arguments.tun_uds.clear();
    arguments.validate_vk_hashes = false;
    let runtime = Arc::new(Runtime {
        status: Mutex::new(Status {
            schema_version: 1, generation: identity.generation, packet_adapter: config.packet_adapter,
            state: "starting".into(), pid: std::process::id(),
            process_startticks: process_startticks(), boot_id: boot_id(), updated_boottime_ms: boottime_ms(), uptime_secs: 0,
            tun_device: config.tun_device.clone(), tunnel_ip: None, dns: Vec::new(),
            active_workers: 0, bytes_up: 0, bytes_down: 0, captcha: None,
            error_code: None, updated_at: now(),
            health: Health { auth_phase: "idle", ..Health::default() },
        }), config, _identity_lock: lock, hook_lock: tokio::sync::Mutex::new(()),
        control_owned: AtomicBool::new(false), tun_owned: AtomicBool::new(false),
        started: std::time::Instant::now(),
    });
    runtime.persist()?;
    RUNTIME.set(runtime).map_err(|_| anyhow::anyhow!("daemon initialized twice"))?;
    Ok(())
}

impl Runtime {
    async fn accept_tunnel_configuration(&self, ip: Ipv4Addr, dns: Vec<Ipv4Addr>) -> Result<()> {
        if self.config.packet_adapter == PacketAdapter::Tun {
            crate::linux_tun::configure(&self.config.tun_device, ip).await?;
            self.hook("up", Some(ip), &dns).await?;
        }
        self.update(|status| { status.tunnel_ip = Some(ip); status.dns = dns; refresh_state(status); });
        Ok(())
    }

    fn persist(&self) -> Result<()> {
        let status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        write_private(&self.config.status_file, &*status)
    }
    fn update(&self, apply: impl FnOnce(&mut Status)) {
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        apply(&mut status);
        status.updated_at = now();
        status.updated_boottime_ms = boottime_ms();
        self.refresh_clocks(&mut status);
        if write_private(&self.config.status_file, &*status).is_err() {
            // Never print config, challenge or server strings on persistence errors.
            crate::log_error!("[DAEMON] status_write_failed");
        }
    }
    pub fn snapshot(&self) -> Value {
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner()).clone();
        self.refresh_clocks(&mut status);
        serde_json::to_value(&status).unwrap_or(Value::Null)
    }
    fn refresh_clocks(&self, status: &mut Status) {
        status.uptime_secs = self.started.elapsed().as_secs();
        let current = boottime_ms();
        status.health.auth_progress_age_secs = status.health.last_auth_progress_ms.map(|last| current.saturating_sub(last) / 1_000);
        status.health.peer_progress_age_secs = status.health.last_peer_progress_ms.map(|last| current.saturating_sub(last) / 1_000);
    }
    async fn hook(&self, action: &str, ip: Option<Ipv4Addr>, dns: &[Ipv4Addr]) -> Result<()> {
        let _lock = self.hook_lock.lock().await;
        let result = tokio::time::timeout(Duration::from_secs(15),
            tokio::process::Command::new(&self.config.tun_config_hook)
                .arg(action).env("CSQTT_TUN_DEVICE", &self.config.tun_device)
                .env("CSQTT_TUN_IP", ip.map(|ip| ip.to_string()).unwrap_or_default())
                .env("CSQTT_TUN_DNS", dns.iter().map(ToString::to_string).collect::<Vec<_>>().join(","))
                .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null()).kill_on_drop(true).status()).await??;
        if !result.success() { bail!("TUN integration hook failed"); }
        Ok(())
    }
}

fn refresh_state(status: &mut Status) {
    refresh_auth_phase(status);
    if status.error_code.is_some() || status.state == "stopped" { return; }
    status.state = if status.tunnel_ip.is_some() && status.active_workers > 0 { "connected" }
    else if status.captcha.as_ref().and_then(|c| c.get("state")).and_then(Value::as_str) == Some("manual") {
        "captcha_required"
    }
    else { "connecting" }.into();
}

fn refresh_auth_phase(status: &mut Status) {
    status.health.auth_phase = if status.health.auth_network_inflight > 0 { "network" }
        else if status.captcha.as_ref().is_some_and(|challenge| challenge["human_active"].as_bool() == Some(true)) { "manual" }
        else if status.captcha.is_some() { "captcha_wait" }
        else if status.health.auth_inflight > 0 { "waiting" }
        else { "idle" };
}

pub fn record_event(kind: &str, payload: &Value) {
    let Some(runtime) = current() else { return; };
    if !matches!(kind, "PROCESS" | "READY" | "STATS" | "ACTIVE_ZERO" | "STOPPED" | "ERROR" | "CALL_UNAVAILABLE" | "NETWORK_TIMEOUT" | "PROGRESS") { return; }
    runtime.update(|status| apply_event(status, kind, payload));
}

fn apply_event(status: &mut Status, kind: &str, payload: &Value) {
        match kind {
            "STATS" => {
                status.active_workers = payload["active"].as_i64().unwrap_or(0).max(0);
                status.bytes_up = payload["bytes_up"].as_i64().unwrap_or(0).max(0);
                status.bytes_down = payload["bytes_down"].as_i64().unwrap_or(0).max(0);
            }
            "READY" => {
                status.active_workers = status.active_workers.max(1);
                status.health.last_peer_progress_ms = Some(boottime_ms());
            }
            "ACTIVE_ZERO" => { status.active_workers = 0; }
            "CALL_UNAVAILABLE" => { status.health.unavailable_calls = status.health.unavailable_calls.saturating_add(1); }
            "NETWORK_TIMEOUT" => { status.health.network_timeout_events = status.health.network_timeout_events.saturating_add(1); }
            "PROGRESS" if payload["kind"].as_str() == Some("credentials") => {
                status.health.last_auth_progress_ms = Some(boottime_ms());
            }
            "STOPPED" => {
                if status.error_code.is_none() { status.state = "stopped".into(); }
                status.active_workers = 0; status.captcha = None;
                status.tunnel_ip = None; status.dns.clear();
            }
            "ERROR" => {
                // These are session-local failures; the worker supervisor
                // retries them. Actual daemon failure is set only by fail().
                status.health.session_errors = status.health.session_errors.saturating_add(1);
                status.health.last_session_error = match payload["code"].as_str() {
                    Some("handshake_timeout") => Some("handshake_timeout"),
                    Some("handshake_rejected") => Some("handshake_rejected"),
                    _ => Some("session_failed"),
                };
            }
            _ => {}
        }
        refresh_state(status);
}

pub fn fail(code: &str) {
    if let Some(runtime) = current() {
        runtime.update(|status| {
            status.state = "error".into();
            if status.error_code.is_none() { status.error_code = Some(code.into()); }
        });
    }
}

pub fn captcha_status(value: Option<Value>) {
    if let Some(runtime) = current() {
        let redacted = value.map(|c| json!({"id": c["id"], "state": c["state"], "expires_at": c["expires_at"],
            "human_active": c["human_active"].as_bool().unwrap_or(false)}));
        runtime.update(|status| { status.captcha = redacted; refresh_state(status); });
    }
}

pub(crate) fn auth_event(kind: &'static str) {
    if let Some(runtime) = current() {
        runtime.update(|status| {
            let health = &mut status.health;
            match kind {
                "network_acquired" => { health.auth_network_inflight = health.auth_network_inflight.saturating_add(1); }
                "network_released" => { health.auth_network_inflight = health.auth_network_inflight.saturating_sub(1); }
                "started" => { health.auth_attempts = health.auth_attempts.saturating_add(1); health.auth_inflight = health.auth_inflight.saturating_add(1); }
                "succeeded" => {
                    health.auth_inflight = health.auth_inflight.saturating_sub(1);
                    health.auth_successes = health.auth_successes.saturating_add(1);
                    health.last_auth_progress_ms = Some(boottime_ms());
                }
                "failed" => { health.auth_inflight = health.auth_inflight.saturating_sub(1); health.auth_failures = health.auth_failures.saturating_add(1); }
                "cancelled" => { health.auth_inflight = health.auth_inflight.saturating_sub(1); health.auth_cancelled = health.auth_cancelled.saturating_add(1); }
                "fresh_retry" => { health.fresh_auth_retries = health.fresh_auth_retries.saturating_add(1); }
                "human_started" => { health.human_epoch = health.human_epoch.saturating_add(1); }
                _ => return,
            }
            refresh_auth_phase(status);
        });
    }
}

pub(crate) fn liveness_event(kind: &'static str) {
    if let Some(runtime) = current() {
        runtime.update(|status| {
            let health = &mut status.health;
            match kind {
                "probe" => health.liveness_probes = health.liveness_probes.saturating_add(1),
                "reply" => { health.liveness_replies = health.liveness_replies.saturating_add(1); health.last_peer_progress_ms = Some(boottime_ms()); }
                "miss" => health.liveness_misses = health.liveness_misses.saturating_add(1),
                "timeout" => health.liveness_timeouts = health.liveness_timeouts.saturating_add(1),
                _ => {},
            }
        });
    }
}

pub fn parse_tunconf(value: &str) -> Result<(Ipv4Addr, Vec<Ipv4Addr>)> {
    let value = value.strip_prefix("TUNCONF:").context("unexpected tunnel configuration")?;
    let mut fields = value.split(':');
    let ip: Ipv4Addr = fields.next().context("missing tunnel IP")?.parse()?;
    let octets = ip.octets();
    if octets[..3] != [10, 66, 67] || !(2..=254).contains(&octets[3]) { bail!("unexpected server tunnel subnet"); }
    let dns = fields.next().context("missing tunnel DNS")?.split(',')
        .map(str::parse).collect::<std::result::Result<Vec<Ipv4Addr>, _>>()?;
    if dns.is_empty() || dns.len() > 4 || dns.iter().any(|ip| ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast()) {
        bail!("invalid tunnel DNS");
    }
    Ok((ip, dns))
}

pub async fn apply_tunconf(value: &str) -> Result<()> {
    if let Some(runtime) = current() {
        let (ip, dns) = parse_tunconf(value)?;
        runtime.accept_tunnel_configuration(ip, dns).await?;
    }
    Ok(())
}

pub fn mark_tun_owned() {
    if let Some(runtime) = current() { runtime.tun_owned.store(true, Ordering::Release); }
}

pub async fn shutdown() {
    if let Some(runtime) = current() {
        if runtime.tun_owned.swap(false, Ordering::AcqRel)
            && runtime.hook("down", None, &[]).await.is_err() { fail("tun_down_hook_failed"); }
        record_event("STOPPED", &json!({}));
        if runtime.control_owned.swap(false, Ordering::AcqRel) {
            let _ = std::fs::remove_file(&runtime.config.control_socket);
        }
    }
}

/// Reduce daemon logs to diagnostics. Upstream sometimes embeds API JSON, call
/// hashes and CAPTCHA URLs in errors. These lines cannot safely go to logread.
pub fn redact_log(line: String) -> String {
    let Some(runtime) = current() else { return line; };
    redact_diagnostic(line, &runtime.config.password, &crate::worker::parse_hashes(&runtime.config.vk_hashes.join(",")))
}

fn redact_diagnostic(line: String, password: &str, hashes: &[String]) -> String {
    let lower = line.to_ascii_lowercase();
    if ["token", "secret", "session_key", "password", "captcha_solve|", "captcha_result|",
        "https://", "http://", "[stdin]", "sid=", "captcha_sid", "redirect_uri",
        "device id", "device_id=", "salt=", "generation=", "{", "}"].iter().any(|s| lower.contains(s)) {
        return "[DAEMON] sensitive upstream diagnostic omitted".into();
    }
    let mut result = line.replace(password, "[redacted]");
    for hash in hashes {
        result = result.replace(hash, "[redacted]");
    }
    result
}

#[test]
fn daemon_diagnostics_hide_upstream_identity_fields() {
    for message in ["[CLIENT] Device ID: opaque value", "[VKCalls] Identity - Name: test | device_id=opaque value",
                    "request salt=opaque value", "request generation=1", "request https://vk.com/test"] {
        assert_eq!(redact_diagnostic(message.into(), "fixture-password", &[]),
                   "[DAEMON] sensitive upstream diagnostic omitted");
    }
    assert_eq!(redact_diagnostic("worker connected".into(), "fixture-password", &[]), "worker connected");
    assert_eq!(redact_diagnostic("failed with fixture-credential".into(), "fixture-credential", &[]),
               "failed with [redacted]");
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlRequest { command: String, id: Option<String>, token: Option<String> }

fn dispatch_control(request: ControlRequest, captcha: &crate::captcha::CaptchaSolver, cancel: &CancellationToken) -> Value {
    match request.command.as_str() {
        "status" => json!({"ok":true,"status":current().map(|r| r.snapshot())}),
        "captcha_get" => json!({"ok":true,"captcha":captcha.daemon_challenge()}),
        "recovery_begin" => match captcha.daemon_recovery_begin(request.id.as_deref()) {
            Ok((id, expires)) => {
                let human_epoch = current().and_then(|runtime| runtime.snapshot()["health"]["human_epoch"].as_u64()).unwrap_or(0);
                json!({"ok":true,"recovery_id":id,"recovery_expires_at":expires,
                    "lease_secs":90,"pid":std::process::id(),"process_startticks":process_startticks(),
                    "boot_id":boot_id(),"updated_boottime_ms":boottime_ms(),"human_epoch":human_epoch})
            },
            Err(error) => json!({"ok":false,"error":error}),
        },
        "recovery_end" => match request.id {
            Some(id) if captcha.daemon_recovery_end(&id) => json!({"ok":true}),
            _ => json!({"ok":false,"error":"stale_recovery"}),
        },
        "captcha_manual" | "captcha_cancel" | "captcha_result" => {
            let Some(id) = request.id else { return json!({"ok":false,"error":"missing_id"}); };
            let result = match request.command.as_str() {
                "captcha_manual" => captcha.daemon_takeover(&id),
                "captcha_cancel" => captcha.daemon_answer(&id, Err("cancelled".into())),
                _ => match request.token {
                    Some(token) if !token.trim().is_empty() && token.len() <= crate::captcha::MAX_CAPTCHA_TOKEN_BYTES
                        && !token.chars().any(char::is_control) => captcha.daemon_answer(&id, Ok(token)),
                    _ => return json!({"ok":false,"error":"invalid_token"}),
                },
            };
            if result { json!({"ok":true,"captcha":captcha.daemon_challenge()}) }
            else if request.command == "captcha_manual" && captcha.recovery_in_progress() {
                json!({"ok":false,"error":"recovery_in_progress"})
            } else { json!({"ok":false,"error":"stale_or_unavailable_challenge"}) }
        }
        "stop" => { cancel.cancel(); json!({"ok":true}) }
        _ => json!({"ok":false,"error":"unknown_command"}),
    }
}

/// Root-only machine interface. Its stdout is a PRIVATE control response and
/// may contain challenge credentials. Callers must never copy it into logs/RPC.
/// The endpoint is fixed so this cannot become an arbitrary Unix socket proxy.
pub fn run_control_cli() -> i32 {
    #[cfg(unix)] {
        let result = (|| -> Result<Value> {
            use std::os::unix::fs::{FileTypeExt, MetadataExt};
            let started = std::time::Instant::now();
            if unsafe { libc::geteuid() } != 0 { bail!("root required"); }
            let path = Path::new("/opt/var/run/csqtt/control.sock");
            let metadata = std::fs::symlink_metadata(path)?;
            if !metadata.file_type().is_socket() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
                bail!("unsafe control socket");
            }
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            std::thread::Builder::new().name("control-input".into()).spawn(move || {
                let mut input = Vec::new();
                let read = std::io::stdin().take(MAX_CONTROL + 1).read_to_end(&mut input);
                let _ = send.send(read.map(|_| input));
            })?;
            let mut input = receive.recv_timeout(Duration::from_secs(1)).context("input deadline")??;
            if input.len() as u64 >= MAX_CONTROL { bail!("invalid request"); }
            let _: ControlRequest = serde_json::from_slice(&input)?;
            if input.last() != Some(&b'\n') { input.push(b'\n'); }
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            let remaining = Duration::from_secs(3).saturating_sub(started.elapsed());
            runtime.block_on(async {
                tokio::time::timeout(remaining, control_exchange(path, &input))
                    .await.context("control deadline")?
            })
        })();
        match result {
            Ok(response) => {
                if serde_json::to_writer(std::io::stdout().lock(), &response).is_err() { return 1; }
                println!();
                return 0;
            }
            Err(_) => { eprintln!("[DAEMON] control_request_failed"); return 1; }
        }
    }
    #[cfg(not(unix))] { eprintln!("[DAEMON] control_request_unavailable"); 1 }
}

#[cfg(unix)]
async fn control_exchange(path: &Path, input: &[u8]) -> Result<Value> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    let stream = tokio::net::UnixStream::connect(path).await?;
    if stream.peer_cred()?.uid() != 0 { bail!("untrusted control peer"); }
    let (read, mut write) = stream.into_split();
    write.write_all(input).await?;
    let mut line = Vec::new();
    BufReader::new(read.take(MAX_CONTROL + 1)).read_until(b'\n', &mut line).await?;
    if line.len() as u64 > MAX_CONTROL || line.last() != Some(&b'\n') { bail!("invalid control response"); }
    Ok(serde_json::from_slice(&line)?)
}

#[cfg(unix)]
pub async fn start_control(captcha: Arc<crate::captcha::CaptchaSolver>, cancel: CancellationToken) -> Result<tokio::task::JoinHandle<()>> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let runtime = current().context("daemon not initialized")?;
    if let Ok(metadata) = std::fs::symlink_metadata(&runtime.config.control_socket) {
        if !metadata.file_type().is_socket() { bail!("control path is not a socket"); }
        if tokio::net::UnixStream::connect(&runtime.config.control_socket).await.is_ok() { bail!("control socket already active"); }
        std::fs::remove_file(&runtime.config.control_socket)?;
    }
    let listener = tokio::net::UnixListener::bind(&runtime.config.control_socket)?;
    runtime.control_owned.store(true, Ordering::Release);
    std::fs::set_permissions(&runtime.config.control_socket, std::fs::Permissions::from_mode(0o600))?;
    Ok(spawn_control_listener(listener, captcha, cancel))
}

#[cfg(unix)]
fn spawn_control_listener(listener: tokio::net::UnixListener, captcha: Arc<crate::captcha::CaptchaSolver>,
    cancel: CancellationToken) -> tokio::task::JoinHandle<()>
{
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = listener.accept(), if tasks.len() < 16 => {
                    let Ok((stream, _)) = accepted else { fail("control_socket_failed"); cancel.cancel(); break; };
                    if stream.peer_cred().ok().is_none_or(|cred| cred.uid() != unsafe { libc::geteuid() }) { continue; }
                    let captcha = captcha.clone(); let token = cancel.clone();
                    tasks.spawn(async move {
                        let (read, mut write) = stream.into_split();
                        let mut reader = BufReader::new(read.take(MAX_CONTROL + 1));
                        let mut line = Vec::new();
                        let read = tokio::select! {
                            _ = token.cancelled() => return,
                            result = tokio::time::timeout(Duration::from_secs(5), reader.read_until(b'\n', &mut line)) => result,
                        };
                        let response = if !matches!(read, Ok(Ok(_))) || line.len() as u64 > MAX_CONTROL || line.last() != Some(&b'\n') {
                            json!({"ok":false,"error":"invalid_request"})
                        } else {
                            match serde_json::from_slice::<ControlRequest>(&line) {
                                Ok(request) => dispatch_control(request, &captcha, &token),
                                Err(_) => json!({"ok":false,"error":"invalid_request"}),
                            }
                        };
                        if let Ok(mut data) = serde_json::to_vec(&response) {
                            data.push(b'\n');
                            let _ = tokio::time::timeout(Duration::from_secs(5), write.write_all(&data)).await;
                        }
                    });
                }
            }
        }
        // A stop request cancels the listener before its own reply is written.
        // Let in-flight handlers flush their bounded replies before aborting.
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            while tasks.join_next().await.is_some() {}
        }).await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    })
}

#[cfg(not(unix))]
pub async fn start_control(_captcha: Arc<crate::captcha::CaptchaSolver>, _cancel: CancellationToken) -> Result<tokio::task::JoinHandle<()>> {
    bail!("daemon control requires Unix")
}

pub async fn termination_signal() {
    #[cfg(unix)] {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => { tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = signal.recv() => {} } }
            Err(_) => { let _ = tokio::signal::ctrl_c().await; }
        }
    }
    #[cfg(not(unix))] { let _ = tokio::signal::ctrl_c().await; }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> Config { Config { peer:"server.example:46000".into(), password:"a-real-test-password".into(), vk_hashes:vec!["abcdefghijklmnop".into()], ..Config::default() } }
    #[test]
    fn configuration_rejects_typos_and_protocol_delimiters() {
        assert!(valid().validate().is_ok());
        assert!(serde_json::from_str::<Config>(r#"{"passwrod":"oops"}"#).is_err());
        let mut config=valid(); config.password="bad|password".into(); assert!(config.validate().is_err());
        let mut config=valid(); config.workers=36; assert!(config.validate().is_err());
        let mut config=valid(); config.vk_hashes=vec!["short".into()]; assert!(config.validate().is_err());
        let mut config=valid(); config.password="has\tcontrol".into(); assert!(config.validate().is_err());
        let mut config=valid(); config.vk_hashes.push(config.vk_hashes[0].clone()); assert!(config.validate().is_err());
        let mut config=valid(); config.peer="user@host:443".into(); assert!(config.validate().is_err());
        let mut config=valid(); config.peer="[2001:db8::1]:46000".into(); assert!(config.validate().is_ok());
    }
    #[test]
    fn captcha_auto_attempts_default_and_bounds() {
        assert_eq!(Config::default().captcha_auto_attempts, 3);
        assert_eq!(serde_json::from_str::<Config>("{}").unwrap().captcha_auto_attempts, 3);
        for attempts in 0..=3 {
            let mut config=valid(); config.captcha_auto_attempts=attempts;
            assert!(config.validate().is_ok());
        }
        let mut config=valid(); config.captcha_auto_attempts=4;
        assert!(config.validate().is_err());
        for invalid in [r#"{"captcha_auto_attempts":-1}"#, r#"{"captcha_auto_attempts":1.5}"#, r#"{"captcha_auto_attempts":"0"}"#] {
            assert!(serde_json::from_str::<Config>(invalid).is_err());
        }
        assert_eq!(serde_json::from_str::<Config>(r#"{"captcha_auto_attempts":0}"#).unwrap().captcha_auto_attempts, 0);
    }
    #[test]
    fn packet_endpoints_are_fixed_local_and_distinct() {
        let config = valid();
        assert_eq!(config.packet_adapter, PacketAdapter::Udp);
        assert_eq!(config.packet_listen.to_string(), "127.0.0.1:39000");
        assert_eq!(config.packet_peer.to_string(), "127.0.0.1:39001");
        for endpoint in ["0.0.0.0:39000", "192.168.2.1:39000", "127.0.0.2:39000", "[::1]:39000", "127.0.0.1:0"] {
            let mut value = config.clone(); value.packet_listen = endpoint.parse().unwrap();
            assert!(value.validate().is_err());
            let mut value = config.clone(); value.packet_peer = endpoint.parse().unwrap();
            assert!(value.validate().is_err());
        }
        let mut value = config.clone(); value.packet_peer = value.packet_listen;
        assert!(value.validate().is_err());
        assert!(serde_json::from_str::<Config>(r#"{"packet_adapter":"auto"}"#).is_err());
        assert!(serde_json::from_str::<Config>(r#"{"packet_listen":"localhost:39000"}"#).is_err());
    }
    #[test]
    fn tunconf_cannot_inject_commands_or_foreign_routes() {
        assert_eq!(parse_tunconf("TUNCONF:10.66.67.2:1.1.1.1,8.8.8.8:0:stream-v2").unwrap().1.len(),2);
        for value in ["TUNCONF:192.168.1.1:1.1.1.1:0", "TUNCONF:10.66.67.0:1.1.1.1:0", "TUNCONF:10.66.67.2:1.1.1.1;reboot:0"] { assert!(parse_tunconf(value).is_err()); }
    }
    #[test]
    fn status_does_not_publish_challenge_credentials() {
        let mut status=Status { schema_version:1,generation:7,packet_adapter:PacketAdapter::Udp,state:"connecting".into(),pid:1,process_startticks:0,boot_id:String::new(),updated_boottime_ms:0,uptime_secs:0,tun_device:"csqtt0".into(),tunnel_ip:Some(Ipv4Addr::new(10,66,67,2)),dns:vec![],active_workers:0,bytes_up:0,bytes_down:0,captcha:None,error_code:None,updated_at:0,health:Health::default() };
        refresh_state(&mut status); assert_eq!(status.state,"connecting");
        status.active_workers=1; refresh_state(&mut status); assert_eq!(status.state,"connected");
        status.captcha=Some(json!({"id":"request","state":"manual","expires_at":1}));
        refresh_state(&mut status); assert_eq!(status.state,"connected");
        status.active_workers=0;
        refresh_state(&mut status); assert_eq!(status.state,"captcha_required");
        let value=serde_json::to_string(&status).unwrap(); assert!(!value.contains("token")); assert!(!value.contains("redirect_uri"));
        status.captcha=None;
        apply_event(&mut status,"ERROR",&json!({"code":"handshake_timeout","fatal":true,"message":"private-upstream-error"}));
        assert!(status.error_code.is_none());
        assert_eq!(status.health.session_errors,1);
        apply_event(&mut status,"STATS",&json!({"active":3,"bytes_up":1,"bytes_down":1}));
        assert_eq!(status.state,"connected");
        assert!(!serde_json::to_string(&status).unwrap().contains("private-upstream-error"));
        let public = serde_json::to_value(&status).unwrap();
        assert_eq!(public["generation"],7);
        assert_eq!(public["packet_adapter"],"udp");
        assert!(public.get("device_id").is_none());
    }

    #[tokio::test]
    async fn udp_configuration_updates_private_status_without_kernel_tun_or_hook() {
        let dir=std::env::temp_dir().join(format!("csqtt-udp-status-{}",uuid::Uuid::new_v4()));
        let mut config=valid(); config.identity_file=dir.join("identity.json");
        config.status_file=dir.join("status.json");
        config.tun_config_hook=dir.join("must-never-execute");
        let (identity,lock)=reserve_identity(&config).unwrap();
        let runtime=Runtime {
            status:Mutex::new(Status {schema_version:1,generation:identity.generation,packet_adapter:PacketAdapter::Udp,
                state:"connecting".into(),pid:std::process::id(),process_startticks:process_startticks(),boot_id:boot_id(),
                updated_boottime_ms:0,uptime_secs:0,tun_device:"csqtt0".into(),tunnel_ip:None,dns:vec![],active_workers:1,
                bytes_up:0,bytes_down:0,captcha:None,error_code:None,updated_at:0,health:Health::default()}),
            config,_identity_lock:lock,hook_lock:tokio::sync::Mutex::new(()),control_owned:AtomicBool::new(false),
            tun_owned:AtomicBool::new(false),started:std::time::Instant::now(),
        };
        runtime.accept_tunnel_configuration(Ipv4Addr::new(10,66,67,2),vec![Ipv4Addr::new(1,1,1,1)]).await.unwrap();
        let status:Value=serde_json::from_slice(&read_private(&runtime.config.status_file).unwrap()).unwrap();
        assert_eq!(status["tunnel_ip"],"10.66.67.2");
        assert_eq!(status["dns"],json!(["1.1.1.1"]));
        assert_eq!(status["generation"],identity.generation);
        assert_eq!(status["packet_adapter"],"udp");
        assert_eq!(status["state"],"connected");
        assert!(!runtime.tun_owned.load(Ordering::Acquire));
        drop(runtime);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn recovery_control_returns_private_bounded_admission_and_requires_its_token() {
        let cancel=CancellationToken::new();
        let captcha=crate::captcha::CaptchaSolver::new("auto",cancel.clone());
        let request=|command: &str,id:Option<String>| ControlRequest { command:command.into(),id,token:None };
        let begin=dispatch_control(request("recovery_begin",None),&captcha,&cancel);
        assert_eq!(begin["ok"],true);
        assert_eq!(begin["lease_secs"],90);
        assert!(begin["pid"].as_u64().is_some());
        assert!(begin["human_epoch"].as_u64().is_some());
        assert!(begin.get("password").is_none());
        assert!(begin.get("session_token").is_none());
        let second=dispatch_control(request("recovery_begin",None),&captcha,&cancel);
        assert_eq!(second["error"],"recovery_in_progress");
        assert_eq!(dispatch_control(request("recovery_end",Some("wrong".into())),&captcha,&cancel)["ok"],false);
        assert_eq!(dispatch_control(request("recovery_end",begin["recovery_id"].as_str().map(str::to_owned)),&captcha,&cancel)["ok"],true);
    }

    #[cfg(target_os="linux")]
    #[test]
    fn private_ownership_metadata_matches_kernel_process_instance() {
        let pid=std::process::id();
        let leader=std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let expected:u64=leader.rsplit_once(')').unwrap().1.split_whitespace().nth(19).unwrap().parse().unwrap();
        assert!(expected>0);
        assert_eq!(process_startticks(),expected);
        assert_eq!(std::thread::spawn(process_startticks).join().unwrap(),expected);
        let id=boot_id();
        assert_eq!(id.len(),36);
        assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit() || byte==b'-'));
        assert!(boottime_ms()>0);
    }
    #[test]
    fn persistent_identity_survives_restart_and_locks_parallel_instances() {
        let dir=std::env::temp_dir().join(format!("csqtt-identity-{}",uuid::Uuid::new_v4()));
        let mut config=valid(); config.identity_file=dir.join("identity.json");
        let (first,lock)=reserve_identity(&config).unwrap();
        #[cfg(unix)] assert!(reserve_identity(&config).is_err());
        drop(lock);
        let (second,lock)=reserve_identity(&config).unwrap();
        assert_eq!(first.device_id,second.device_id); assert_eq!(second.generation,first.generation+1);
        drop(lock);
        config.device_id=Some("different-device".into()); assert!(reserve_identity(&config).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_configuration_rejects_public_files_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir=std::env::temp_dir().join(format!("csqtt-private-{}",uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path=dir.join("config.json");
        std::fs::write(&path,b"{}").unwrap();
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private(&path).is_err());
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_private(&path).unwrap(),b"{}");
        let link=dir.join("link.json"); symlink(&path,&link).unwrap();
        assert!(read_private(&link).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn control_socket_rejects_bad_requests_and_flushes_stop_reply() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let dir=std::env::temp_dir().join(format!("csqtt-control-{}",uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path=dir.join("control.sock");
        let listener=tokio::net::UnixListener::bind(&path).unwrap();
        let cancel=CancellationToken::new();
        let captcha=crate::captcha::CaptchaSolver::new("auto",cancel.clone());
        let task=spawn_control_listener(listener,captcha,cancel.clone());
        let maximal_result=format!("{}\n",json!({"command":"captcha_result","id":"stale", "token":"x".repeat(crate::captcha::MAX_CAPTCHA_TOKEN_BYTES)}));
        for (request, error) in [
            (maximal_result.as_str(),Some("stale_or_unavailable_challenge")),
            ("{bad}\n",Some("invalid_request")),
            ("{\"command\":\"captcha_result\",\"token\":\"secret\"}\n",Some("missing_id")),
            ("{\"command\":\"captcha_cancel\",\"id\":\"stale\"}\n",Some("stale_or_unavailable_challenge")),
            ("{\"command\":\"shell\"}\n",Some("unknown_command")),
            ("{\"command\":\"stop\"}\n",None),
        ] {
            let mut stream=tokio::net::UnixStream::connect(&path).await.unwrap();
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut line=String::new();
            tokio::time::timeout(Duration::from_secs(2),BufReader::new(stream).read_line(&mut line)).await.unwrap().unwrap();
            let response:Value=serde_json::from_str(&line).unwrap();
            assert_eq!(response["ok"],error.is_none());
            if let Some(error)=error { assert_eq!(response["error"],error); }
        }
        assert!(cancel.is_cancelled());
        tokio::time::timeout(Duration::from_secs(2),task).await.unwrap().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}
