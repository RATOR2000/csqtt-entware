// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use crate::profiles::{Profile, SavedProfile};
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use primp::{Client, Method, header};
use rand::RngExt;
use regex::Regex;
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    sync::{Arc, LazyLock},
    time::Duration,
};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

const API_VERSION: &str = "5.131";
const SCRIPT_VERSION: &str = "1.1.1370";
pub const MAX_CAPTCHA_TOKEN_BYTES: usize = 16_384;
const FRESH_AUTH_INTERVAL: Duration = Duration::from_secs(60);
const RECOVERY_LEASE: Duration = Duration::from_secs(90);
const DEVICE_INFO: &str = r#"{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1040,"innerWidth":1920,"innerHeight":970,"devicePixelRatio":1,"language":"ru-RU","languages":["ru-RU","ru","en-US","en"],"webdriver":false,"hardwareConcurrency":8,"notificationsPermission":"default"}"#;
static POW_INPUT: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"const\s+powInput\s*=\s*["']([^"']+)["']"#).ok());
static POW_DIFFICULTY: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"const\s+difficulty\s*=\s*(\d+)").ok());
static POW_OBFUSCATED: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"["']([A-Za-z0-9+/=_-]{6,})["']\s*,\s*(\d+)\s*,\s*["'](?:pow_timeout|pow[a-zA-Z0-9_-]*)["']"#).ok()
});
static SCRIPT_SOURCE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"src=["']([^"']*not_robot_captcha[^"']*)["']"#).ok());
static DEBUG_UUID: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"[a-zA-Z0-9_]{6,}:\s*["']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']"#).ok()
});
static SCRIPT_VERSION_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"vkid/([0-9.]*)/not_robot_captcha\.js").ok());
static WINDOW_INIT: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?s)window\.init\s*=\s*(\{.*?})\s*;").ok());

#[derive(Debug, Clone)]
pub struct VkCaptchaError {
    pub error_code: i64,
    pub error_msg: String,
    pub captcha_sid: String,
    pub captcha_img: String,
    pub redirect_uri: String,
    pub session_token: String,
    pub captcha_timestamp: String,
    pub captcha_attempt: String,
}

impl VkCaptchaError {
    pub fn from_json(raw: &Value) -> Result<Self> {
        if !raw.is_object() {
            bail!("invalid VK captcha response: {raw}");
        }
        let redirect_uri = string_value(raw.get("redirect_uri"));
        let session_token = Url::parse(&redirect_uri)
            .ok()
            .and_then(|url| {
                url.query_pairs()
                    .find(|(key, _)| key == "session_token")
                    .map(|(_, value)| value.into_owned())
            })
            .unwrap_or_default();
        Ok(Self {
            error_code: match raw.get("error_code") {
                Some(Value::Number(value)) => value
                    .as_i64()
                    .or_else(|| value.as_f64().map(|value| value as i64))
                    .unwrap_or_default(),
                Some(Value::String(value)) => value.parse().unwrap_or_default(),
                _ => 0,
            },
            error_msg: string_value(raw.get("error_msg")),
            captcha_sid: string_value(raw.get("captcha_sid")),
            captcha_img: string_value(raw.get("captcha_img")),
            redirect_uri,
            session_token,
            captcha_timestamp: string_value(raw.get("captcha_ts")),
            captcha_attempt: string_value(raw.get("captcha_attempt")),
        })
    }
}

impl fmt::Display for VkCaptchaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.error_code != 0 && self.error_code != 14 {
            if self.error_msg.is_empty() {
                return write!(formatter, "VK API error {}", self.error_code);
            }
            return write!(
                formatter,
                "VK API error {}: {}",
                self.error_code, self.error_msg
            );
        }
        if !self.redirect_uri.is_empty() {
            return write!(
                formatter,
                "VK captcha required: redirect_uri, sid={:?}",
                self.captcha_sid
            );
        }
        if !self.captcha_img.is_empty() {
            return write!(
                formatter,
                "VK captcha required: captcha_img, sid={:?}",
                self.captcha_sid
            );
        }
        if !self.captcha_sid.is_empty() {
            return write!(formatter, "VK captcha required: sid={:?}", self.captcha_sid);
        }
        if !self.error_msg.is_empty() {
            return write!(formatter, "VK captcha required: {}", self.error_msg);
        }
        formatter.write_str("VK captcha required")
    }
}

impl std::error::Error for VkCaptchaError {}

#[derive(Debug)]
pub(crate) struct RateLimit;

impl fmt::Display for RateLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("captcha session rate limit reached")
    }
}

impl std::error::Error for RateLimit {}

#[derive(Debug)]
pub(crate) struct FreshAuthRequired;
impl fmt::Display for FreshAuthRequired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fresh normal authentication required")
    }
}
impl std::error::Error for FreshAuthRequired {}

#[derive(Debug)]
struct BotChallenge;

impl fmt::Display for BotChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("captcha bot challenge")
    }
}

impl std::error::Error for BotChallenge {}

#[derive(Debug)]
struct ShowTypeMismatch(String);

impl fmt::Display for ShowTypeMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "captcha show type mismatch: {}", self.0)
    }
}

impl std::error::Error for ShowTypeMismatch {}

pub struct CaptchaSolver {
    mode: Arc<str>,
    result_tx: mpsc::Sender<String>,
    result_rx: Mutex<mpsc::Receiver<String>>,
    cancel: CancellationToken,
    daemon_serial: Mutex<()>,
    daemon_pending: std::sync::Mutex<Option<DaemonChallenge>>,
    recovery: std::sync::Mutex<Option<RecoveryLease>>,
}

struct RecoveryLease { id: String, expires_at: u64, deadline: tokio::time::Instant }

/// Credentials live only in this process and the private Unix control socket.
/// The public status projection deliberately has no URL or session token.
struct DaemonChallenge {
    id: String,
    state: &'static str,
    human_active: bool,
    redirect_uri: String,
    session_token: String,
    expires_at: u64,
    deadline: tokio::time::Instant,
    auto_cancel: CancellationToken,
    answer: oneshot::Sender<std::result::Result<String, String>>,
}

impl DaemonChallenge {
    fn public_status(&self) -> Value {
        serde_json::json!({"id": self.id, "state": self.state, "expires_at": self.expires_at,
            "human_active": self.human_active})
    }
    fn private_status(&self) -> Value {
        serde_json::json!({"id": self.id, "state": self.state, "expires_at": self.expires_at,
            "human_active": self.human_active,
            "redirect_uri": self.redirect_uri, "session_token": self.session_token})
    }
    fn live(&self) -> bool {
        // The broker enforces the published Unix timestamp. Also retain a
        // monotonic cap so a backwards clock adjustment cannot extend a job.
        crate::daemon::now() < self.expires_at && tokio::time::Instant::now() < self.deadline
    }
}

struct ChallengeGuard<'a> { solver: &'a CaptchaSolver, id: String }
impl Drop for ChallengeGuard<'_> {
    fn drop(&mut self) { self.solver.clear_daemon_challenge(&self.id); }
}

impl CaptchaSolver {
    pub fn new(mode: &str, cancel: CancellationToken) -> Arc<Self> {
        let (result_tx, result_rx) = mpsc::channel(1);
        Arc::new(Self {
            mode: Arc::from(match mode.trim().to_ascii_lowercase().as_str() {
                "wv" => "wv",
                "rjs" => "rjs",
                _ => "auto",
            }),
            result_tx,
            result_rx: Mutex::new(result_rx),
            cancel,
            daemon_serial: Mutex::new(()),
            daemon_pending: std::sync::Mutex::new(None),
            recovery: std::sync::Mutex::new(None),
        })
    }

    pub fn submit_result(&self, result: String) -> bool {
        self.result_tx.try_send(result).is_ok()
    }

    pub fn daemon_challenge(&self) -> Option<Value> {
        let mut pending = self.daemon_pending.lock().unwrap_or_else(|e| e.into_inner());
        self.expire_challenge(&mut pending);
        pending.as_ref().map(DaemonChallenge::private_status)
    }

    fn expire_challenge(&self, pending: &mut Option<DaemonChallenge>) {
        if pending.as_ref().is_some_and(|challenge| self.cancel.is_cancelled() || !challenge.live()) {
            if let Some(challenge) = pending.take() { challenge.auto_cancel.cancel(); }
            crate::daemon::captcha_status(None);
        }
    }

    pub fn daemon_takeover(&self, id: &str) -> bool {
        // Recovery and explicit human takeover share this admission lock. A
        // status read followed by a restart would otherwise race broker pairing.
        let mut recovery = self.recovery.lock().unwrap_or_else(|e| e.into_inner());
        Self::expire_recovery(&mut recovery);
        if recovery.is_some() { return false; }
        let mut pending = self.daemon_pending.lock().unwrap_or_else(|e| e.into_inner());
        self.expire_challenge(&mut pending);
        let Some(challenge) = pending.as_mut().filter(|c| c.id == id) else { return false; };
        challenge.state = "manual";
        challenge.human_active = true;
        challenge.auto_cancel.cancel();
        crate::daemon::captcha_status(Some(challenge.public_status()));
        crate::daemon::auth_event("human_started");
        true
    }

    fn expire_recovery(recovery: &mut Option<RecoveryLease>) {
        // The Unix timestamp is informational for the private caller. An NTP
        // jump must not reopen human admission while a monotonic lease is held.
        if recovery.as_ref().is_some_and(|lease| tokio::time::Instant::now() >= lease.deadline) {
            *recovery = None;
        }
    }

    pub(crate) fn daemon_recovery_begin(&self, expected: Option<&str>)
        -> std::result::Result<(String, u64), &'static str>
    {
        let mut recovery = self.recovery.lock().unwrap_or_else(|e| e.into_inner());
        Self::expire_recovery(&mut recovery);
        if self.cancel.is_cancelled() { return Err("stopping"); }
        if recovery.is_some() { return Err("recovery_in_progress"); }
        let mut pending = self.daemon_pending.lock().unwrap_or_else(|e| e.into_inner());
        self.expire_challenge(&mut pending);
        if pending.as_ref().is_some_and(|challenge| challenge.human_active) { return Err("human_active"); }
        if expected.is_some_and(|id| pending.as_ref().is_none_or(|challenge| challenge.id != id)) {
            return Err("stale_challenge");
        }
        let id = Uuid::new_v4().to_string();
        let expires_at = crate::daemon::now().saturating_add(RECOVERY_LEASE.as_secs());
        *recovery = Some(RecoveryLease { id: id.clone(), expires_at,
            deadline: tokio::time::Instant::now() + RECOVERY_LEASE });
        Ok((id, recovery.as_ref().map_or(expires_at, |lease| lease.expires_at)))
    }

    pub(crate) fn daemon_recovery_end(&self, id: &str) -> bool {
        let mut recovery = self.recovery.lock().unwrap_or_else(|e| e.into_inner());
        Self::expire_recovery(&mut recovery);
        if recovery.as_ref().is_none_or(|lease| lease.id != id) { return false; }
        *recovery = None;
        true
    }

    pub(crate) fn recovery_in_progress(&self) -> bool {
        let mut recovery = self.recovery.lock().unwrap_or_else(|e| e.into_inner());
        Self::expire_recovery(&mut recovery);
        recovery.is_some()
    }

    fn manual_available(&self, id: &str) {
        let mut pending = self.daemon_pending.lock().unwrap_or_else(|e| e.into_inner());
        self.expire_challenge(&mut pending);
        if let Some(challenge) = pending.as_mut().filter(|c| c.id == id) {
            challenge.state = "manual";
            challenge.auto_cancel.cancel();
            crate::daemon::captcha_status(Some(challenge.public_status()));
        }
    }

    fn retry_unclaimed(&self, id: &str) -> bool {
        let mut pending = self.daemon_pending.lock().unwrap_or_else(|e| e.into_inner());
        self.expire_challenge(&mut pending);
        if pending.as_ref().is_some_and(|c| c.id == id && !c.human_active) {
            if let Some(challenge) = pending.take() { challenge.auto_cancel.cancel(); }
            crate::daemon::captcha_status(None);
            crate::daemon::auth_event("fresh_retry");
            return true;
        }
        false
    }

    pub fn daemon_answer(&self, id: &str, answer: std::result::Result<String, String>) -> bool {
        let mut pending = self.daemon_pending.lock().unwrap_or_else(|e| e.into_inner());
        self.expire_challenge(&mut pending);
        let Some(challenge) = pending.as_ref() else { return false; };
        if challenge.id != id || (answer.is_ok() && !challenge.human_active) { return false; }
        if let Ok(token) = &answer {
            if token.trim().is_empty() || token.len() > MAX_CAPTCHA_TOKEN_BYTES || token.chars().any(char::is_control) {
                return false;
            }
        }
        let Some(challenge) = pending.take() else { return false; };
        challenge.auto_cancel.cancel();
        crate::daemon::captcha_status(None);
        challenge.answer.send(answer).is_ok()
    }

    fn clear_daemon_challenge(&self, id: &str) {
        let mut pending = self.daemon_pending.lock().unwrap_or_else(|e| e.into_inner());
        if pending.as_ref().is_some_and(|c| c.id == id) {
            if let Some(challenge) = pending.take() { challenge.auto_cancel.cancel(); }
            crate::daemon::captcha_status(None);
        }
    }

    fn begin_daemon_challenge(&self, captcha: &VkCaptchaError, timeout: Duration)
        -> (String, CancellationToken, oneshot::Receiver<std::result::Result<String, String>>, tokio::time::Instant)
    {
        let id = Uuid::new_v4().to_string();
        let auto_cancel = self.cancel.child_token();
        let deadline = tokio::time::Instant::now() + timeout;
        let (answer, receive) = oneshot::channel();
        let challenge = DaemonChallenge {
            id: id.clone(), state: "auto", human_active: false, redirect_uri: captcha.redirect_uri.clone(),
            session_token: captcha.session_token.clone(),
            expires_at: crate::daemon::now().saturating_add(timeout.as_secs()), deadline,
            auto_cancel: auto_cancel.clone(), answer,
        };
        let mut pending = self.daemon_pending.lock().unwrap_or_else(|e| e.into_inner());
        crate::daemon::captcha_status(Some(challenge.public_status()));
        *pending = Some(challenge);
        (id, auto_cancel, receive, deadline)
    }

    fn finish_daemon_auto(&self, id: &str) -> bool {
        let mut pending = self.daemon_pending.lock().unwrap_or_else(|e| e.into_inner());
        self.expire_challenge(&mut pending);
        if pending.as_ref().is_none_or(|c| c.id != id || c.state != "auto") { return false; }
        if let Some(challenge) = pending.take() { challenge.auto_cancel.cancel(); }
        crate::daemon::captcha_status(None);
        true
    }

    async fn solve_daemon(&self, client: &Client, profile: &Profile,
        saved_profile: Option<&SavedProfile>, captcha: &VkCaptchaError,
        network: &mut crate::auth::AuthNetworkPermit) -> Result<String>
    {
        // Another request may already be waiting for a human. It must not
        // monopolize the network permit while we queue for the challenge slot.
        network.suspend();
        let _serial = tokio::select! {
            _ = self.cancel.cancelled() => bail!("captcha cancelled"),
            lock = tokio::time::timeout(FRESH_AUTH_INTERVAL, self.daemon_serial.lock()) =>
                match lock { Ok(lock) => lock, Err(_) => return Err(FreshAuthRequired.into()) },
        };
        network.acquire().await?;
        if captcha.redirect_uri.is_empty() || captcha.session_token.is_empty() {
            bail!("captcha data is incomplete");
        }
        let timeout = Duration::from_secs(crate::daemon::current()
            .map_or(180, |runtime| runtime.config.captcha_timeout_secs));
        let (id, auto_cancel, receive, deadline) = self.begin_daemon_challenge(captcha, timeout);
        let _guard = ChallengeGuard { solver: self, id: id.clone() };
        let retry_at = tokio::time::Instant::now() + FRESH_AUTH_INTERVAL;
        let automatic = tokio::select! {
            biased;
            _ = self.cancel.cancelled() => bail!("captcha cancelled"),
            _ = tokio::time::sleep_until(deadline) => bail!("captcha expired"),
            _ = tokio::time::sleep_until(retry_at) => None,
            _ = auto_cancel.cancelled() => None,
            result = self.solve_attempts_with_cancel(client, profile, saved_profile, captcha, 3, &auto_cancel) => Some(result),
        };
        match automatic {
            Some(Ok(token)) if self.finish_daemon_auto(&id) => return Ok(token),
            Some(Err(_)) => { self.manual_available(&id); }
            _ => {},
        }
        network.suspend();
        let result = self.wait_daemon_answer(&id, receive, deadline, retry_at).await;
        // No HTTP continuation runs concurrently with another automatic auth.
        if result.is_ok() { network.acquire().await?; }
        result
    }

    async fn wait_daemon_answer(&self, id: &str,
        receive: oneshot::Receiver<std::result::Result<String, String>>,
        deadline: tokio::time::Instant, retry_at: tokio::time::Instant) -> Result<String>
    {
        tokio::pin!(receive);
        let mut retry_pending = true;
        loop {
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => bail!("captcha cancelled"),
            _ = tokio::time::sleep_until(deadline) => bail!("captcha expired"),
            _ = tokio::time::sleep_until(retry_at), if retry_pending => {
                if self.retry_unclaimed(id) { return Err(FreshAuthRequired.into()); }
                retry_pending = false;
            }
            result = &mut receive => return match result {
                Ok(Ok(token)) => Ok(token),
                Ok(Err(_)) => bail!("captcha cancelled"),
                Err(_) => bail!("captcha no longer available"),
            },
        }
        }
    }

    pub(crate) async fn solve(
        &self,
        client: &Client,
        profile: &Profile,
        saved_profile: Option<&SavedProfile>,
        stream_id: usize,
        captcha: &VkCaptchaError,
        network: &mut crate::auth::AuthNetworkPermit,
    ) -> Result<String> {
        if crate::daemon::enabled() {
            return self.solve_daemon(client, profile, saved_profile, captcha, network).await;
        }
        match self.mode.as_ref() {
            "wv" => {
                crate::log_error!("[STREAM {stream_id}] [КАПЧА] WBV: режим из настроек Android");
                self.webview(stream_id, captcha, "selected", Duration::from_secs(120))
                    .await
            }
            "rjs" => {
                crate::log_error!("[STREAM {stream_id}] [КАПЧА] RJS: Rust v2 выбран в настройках");
                match self
                    .solve_attempts(client, profile, saved_profile, captcha, 2)
                    .await
                {
                    Ok(token) => Ok(token),
                    Err(error) => {
                        crate::log_error!(
                            "[STREAM {stream_id}] [КАПЧА] RJS: ошибка, fallback на WBV Auto: {error}"
                        );
                        self.webview(stream_id, captcha, "auto", Duration::from_secs(10))
                            .await
                    }
                }
            }
            _ => {
                self.solve_auto(client, profile, saved_profile, stream_id, captcha)
                    .await
            }
        }
    }

    async fn solve_auto(
        &self,
        client: &Client,
        profile: &Profile,
        saved_profile: Option<&SavedProfile>,
        stream_id: usize,
        captcha: &VkCaptchaError,
    ) -> Result<String> {
        crate::log_error!("[STREAM {stream_id}] [КАПЧА] AUTO: старт цепочки");
        match self
            .solve_attempts(client, profile, saved_profile, captcha, 2)
            .await
        {
            Ok(token) => {
                crate::log_error!("[STREAM {stream_id}] [КАПЧА] AUTO: Rust v2 решил капчу");
                return Ok(token);
            }
            Err(error) => {
                crate::log_error!(
                    "[STREAM {stream_id}] [КАПЧА] AUTO: Rust v2 не решил за 2 попытки: {error}"
                );
                error
            }
        };
        for attempt in 1..=2 {
            crate::log_error!(
                "[STREAM {stream_id}] [КАПЧА] AUTO: WBV Auto попытка {attempt}/2 (timeout 10s)"
            );
            match self
                .webview(stream_id, captcha, "auto", Duration::from_secs(10))
                .await
            {
                Ok(token) => {
                    crate::log_error!("[STREAM {stream_id}] [КАПЧА] AUTO: WBV Auto решил капчу");
                    return Ok(token);
                }
                Err(error) => {
                    crate::log_error!(
                        "[STREAM {stream_id}] [КАПЧА] AUTO: WBV Auto ошибка {attempt}/2: {error}"
                    );
                }
            }
            let delay = rand::rng().random_range(250..500);
            tokio::select! {
                _ = self.cancel.cancelled() => bail!("captcha cancelled"),
                _ = tokio::time::sleep(Duration::from_millis(delay)) => {}
            }
        }
        crate::log_error!("[STREAM {stream_id}] [КАПЧА] AUTO: финальная Rust v2 попытка после WBV");
        let last_error = match self
            .solve_attempts(client, profile, saved_profile, captcha, 1)
            .await
        {
            Ok(token) => {
                crate::log_error!(
                    "[STREAM {stream_id}] [КАПЧА] AUTO: финальная Rust v2 решила капчу"
                );
                return Ok(token);
            }
            Err(error) => {
                crate::log_error!(
                    "[STREAM {stream_id}] [КАПЧА] AUTO: финальная Rust v2 ошибка: {error}"
                );
                error
            }
        };
        crate::log_error!(
            "[STREAM {stream_id}] [КАПЧА] AUTO: автоцепочка не прошла, открыт ручной WebView"
        );
        self.webview(stream_id, captcha, "manual", Duration::from_secs(60))
            .await
            .with_context(|| {
                format!("automatic captcha chain failed: {last_error}; manual fallback failed")
            })
    }

    async fn webview(
        &self,
        stream_id: usize,
        captcha: &VkCaptchaError,
        mode: &str,
        timeout: Duration,
    ) -> Result<String> {
        if captcha.redirect_uri.is_empty() || captcha.session_token.is_empty() {
            bail!("webview captcha data is incomplete");
        }
        let mut receiver = self.result_rx.lock().await;
        while receiver.try_recv().is_ok() {}
        crate::log_output!(
            "CAPTCHA_SOLVE|{mode}|{}|{}",
            captcha.redirect_uri,
            captcha.session_token
        );
        let result = tokio::select! {
            _ = self.cancel.cancelled() => bail!("webview captcha cancelled"),
            result = tokio::time::timeout(timeout, receiver.recv()) => {
                result
                    .map_err(|_| anyhow!("webview captcha timed out"))?
                    .ok_or_else(|| anyhow!("webview captcha result channel closed"))?
            }
        };
        let result = result.trim();
        if result.is_empty() {
            bail!("webview captcha returned empty result");
        }
        let lower = result.to_ascii_lowercase();
        if lower == "error:timeout" {
            bail!("webview captcha timed out");
        }
        if lower.starts_with("error:") {
            bail!("webview captcha failed: {result}");
        }
        crate::log_error!("[STREAM {stream_id}] [КАПЧА] WBV: {mode} solve succeeded");
        Ok(result.to_owned())
    }

    async fn solve_attempts(
        &self,
        client: &Client,
        profile: &Profile,
        saved_profile: Option<&SavedProfile>,
        captcha: &VkCaptchaError,
        attempts: usize,
    ) -> Result<String> {
        self.solve_attempts_with_cancel(client, profile, saved_profile, captcha, attempts, &self.cancel).await
    }

    async fn solve_attempts_with_cancel(
        &self, client: &Client, profile: &Profile, saved_profile: Option<&SavedProfile>,
        captcha: &VkCaptchaError, attempts: usize, cancel: &CancellationToken,
    ) -> Result<String> {
        if captcha.session_token.is_empty() {
            bail!("no session_token in redirect_uri");
        }
        crate::log_error!(
            "[КАПЧА] Решаю VK Smart Captcha автоматически (v2, попыток={attempts})..."
        );
        let session = CaptchaSession {
            client,
            profile,
            saved_profile,
            cancel: cancel.clone(),
        };
        let mut last_error = None;
        for attempt in 1..=attempts {
            match session.solve_once(captcha).await {
                Ok(token) => return Ok(token),
                Err(error) => {
                    crate::log_error!("[КАПЧА] v2 попытка {attempt} ошибка: {error}");
                    if error.downcast_ref::<RateLimit>().is_some() {
                        crate::log_error!(
                            "[КАПЧА] Превышен лимит сессии капчи. Ожидаю 5 секунд..."
                        );
                        tokio::select! {
                            _ = cancel.cancelled() => bail!("captcha cancelled"),
                            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                        }
                    } else {
                        let delay = 1500 + rand::rng().random_range(0..1200);
                        tokio::select! {
                            _ = cancel.cancelled() => bail!("captcha cancelled"),
                            _ = tokio::time::sleep(Duration::from_millis(delay)) => {}
                        }
                    }
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("v2 captcha attempts exhausted ({attempts})")))
    }
}

pub(crate) struct CaptchaSession<'a> {
    client: &'a Client,
    profile: &'a Profile,
    saved_profile: Option<&'a SavedProfile>,
    cancel: CancellationToken,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct CaptchaInit {
    data: CaptchaInitData,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct CaptchaInitData {
    show_captcha_type: String,
    captcha_settings: Vec<CaptchaSetting>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct CaptchaSetting {
    #[serde(rename = "type")]
    kind: String,
    settings: String,
    settings_key: String,
}

struct CaptchaPage {
    pow_input: String,
    pow_difficulty: usize,
    script_url: String,
    init: Option<CaptchaInit>,
    debug_info: String,
}

struct CaptchaCheck {
    status: String,
    success_token: String,
    show_type: String,
}

impl CaptchaSession<'_> {
    async fn solve_once(&self, captcha: &VkCaptchaError) -> Result<String> {
        crate::log_error!("[КАПЧА] solveOnce URL: {}", captcha.redirect_uri);
        if std::env::var_os("ONLY_PRINT_URL").is_some() {
            bail!("ONLY_PRINT_URL active, skipping solve");
        }
        let html = self.fetch_html(&captcha.redirect_uri).await?;
        let mut page = parse_page(&html)?;
        if !page.script_url.starts_with("http://") && !page.script_url.starts_with("https://") {
            if let Ok(base) = Url::parse(&captcha.redirect_uri) {
                page.script_url = base
                    .join(&page.script_url)
                    .map(|url| url.to_string())
                    .unwrap_or_else(|_| format!("https://id.vk.com{}", page.script_url));
            } else {
                page.script_url = format!("https://id.vk.com{}", page.script_url);
            }
        }
        if page.pow_input.is_empty() {
            bail!("failed to find PoW settings");
        }
        crate::log_error!("[КАПЧА] v2 solving pow difficulty={}", page.pow_difficulty);
        let input = page.pow_input.clone();
        let difficulty = page.pow_difficulty;
        let cancel = self.cancel.clone();
        let hash = crate::cpu_task::run("csqtt-captcha-pow", move || {
            solve_pow(&input, difficulty, &cancel)
        })
        .await?;
        crate::log_error!("[КАПЧА] v2 pow solved");
        let base = base_values(&captcha.session_token);
        self.request("captchaNotRobot.settings", &base)
            .await
            .context("captcha settings failed")?;
        let browser_fp = self
            .saved_profile
            .filter(|saved| !saved.browser_fp.trim().is_empty())
            .map(|saved| saved.browser_fp.clone())
            .unwrap_or_else(|| hex::encode(rand::rng().random::<[u8; 16]>()));
        if let Some(captures) = SCRIPT_VERSION_RE
            .as_ref()
            .and_then(|regex| regex.captures(&page.script_url))
        {
            let latest = &captures[1];
            if latest != SCRIPT_VERSION {
                crate::log_error!(
                    "[КАПЧА] v2 script version drift: known={SCRIPT_VERSION} latest={latest}"
                );
            }
        }
        let debug_info = if page.debug_info.is_empty() {
            let value = Uuid::new_v4().to_string();
            crate::log_error!(
                "[КАПЧА] debug_info UUID не найден в HTML, сгенерирован fallback: {value}"
            );
            value
        } else {
            page.debug_info
        };
        let (mut show_type, mut slider_settings) = initial_captcha_state(page.init);
        if show_type.is_empty() {
            let domain = Url::parse(&captcha.redirect_uri)
                .ok()
                .and_then(|url| {
                    url.query_pairs()
                        .find(|(key, _)| key == "domain")
                        .map(|(_, value)| value.into_owned())
                })
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "vk.com".to_owned());
            match self
                .request(
                    "captchaNotRobot.initSession",
                    &[
                        ("session_token", captcha.session_token.as_str()),
                        ("domain", domain.as_str()),
                        ("lang", "0"),
                    ],
                )
                .await
            {
                Ok(value) => {
                    if let Some(response) = value.get("response") {
                        show_type = string_value(response.get("show_captcha_type"));
                        if let Some(settings) =
                            response.get("content_settings").and_then(Value::as_array)
                        {
                            for setting in settings {
                                if string_value(setting.get("type")) == "slider" {
                                    slider_settings = string_value(setting.get("settings"));
                                    if slider_settings.is_empty() {
                                        slider_settings = string_value(setting.get("settings_key"));
                                    }
                                }
                            }
                        }
                    }
                }
                Err(error) => crate::log_error!("[КАПЧА] Ошибка вызова initSession: {error}"),
            }
        }
        loop {
            crate::log_error!("[КАПЧА] v2 solving show_type={show_type}");
            let solved = match show_type.as_str() {
                "slider" => {
                    self.solve_slider(
                        &captcha.session_token,
                        &browser_fp,
                        &hash,
                        &slider_settings,
                        &debug_info,
                    )
                    .await
                }
                "checkbox" | "" => {
                    self.solve_checkbox(&captcha.session_token, &browser_fp, &hash, &debug_info)
                        .await
                }
                _ => bail!("unsupported captcha type: {show_type}"),
            };
            match solved {
                Ok(token) => {
                    if let Err(error) = self.request("captchaNotRobot.endSession", &base).await {
                        crate::log_error!("[КАПЧА] v2 endSession failed: {error}");
                    }
                    return Ok(token);
                }
                Err(error)
                    if error.downcast_ref::<BotChallenge>().is_some()
                        && show_type != "slider"
                        && !slider_settings.is_empty() =>
                {
                    crate::log_error!("[КАПЧА] v2 checkbox returned BOT, trying slider");
                    show_type = "slider".to_owned();
                }
                Err(error) => {
                    if let Some(mismatch) = error.downcast_ref::<ShowTypeMismatch>()
                        && !mismatch.0.is_empty()
                    {
                        show_type = mismatch.0.clone();
                        continue;
                    }
                    return Err(error);
                }
            }
        }
    }

    async fn fetch_html(&self, endpoint: &str) -> Result<String> {
        let body = self
            .raw(
                Method::GET,
                endpoint,
                None,
                &[
                    (
                        "accept",
                        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    ),
                    ("sec-fetch-dest", "document"),
                    ("sec-fetch-mode", "navigate"),
                    ("sec-fetch-site", "cross-site"),
                ],
            )
            .await?;
        String::from_utf8(body.to_vec()).context("captcha HTML is not UTF-8")
    }

    async fn request(&self, method: &str, values: &[(&str, &str)]) -> Result<Value> {
        let endpoint = format!("https://api.vk.ru/method/{method}?v={API_VERSION}");
        let body = self
            .raw(
                Method::POST,
                &endpoint,
                Some(values),
                &[
                    ("origin", "https://id.vk.com"),
                    ("referer", "https://id.vk.com/"),
                    ("priority", "u=1, i"),
                ],
            )
            .await?;
        serde_json::from_slice(&body).context("captcha api decode")
    }

    async fn raw(
        &self,
        method: Method,
        endpoint: &str,
        form: Option<&[(&str, &str)]>,
        extra: &[(&str, &str)],
    ) -> Result<bytes::Bytes> {
        let mut headers = header::HeaderMap::with_capacity(18);
        if !self.profile.user_agent.is_empty() {
            headers.insert(
                header::USER_AGENT,
                header::HeaderValue::from_str(&self.profile.user_agent)?,
            );
        }
        if !self.profile.sec_ch_ua.is_empty() {
            insert_header(&mut headers, "sec-ch-ua", &self.profile.sec_ch_ua)?;
        }
        if !self.profile.sec_ch_ua_mobile.is_empty() {
            insert_header(
                &mut headers,
                "sec-ch-ua-mobile",
                &self.profile.sec_ch_ua_mobile,
            )?;
        }
        if !self.profile.sec_ch_ua_platform.is_empty() {
            insert_header(
                &mut headers,
                "sec-ch-ua-platform",
                &self.profile.sec_ch_ua_platform,
            )?;
        }
        headers.insert(header::ACCEPT, header::HeaderValue::from_static("*/*"));
        headers.insert(
            header::ACCEPT_LANGUAGE,
            header::HeaderValue::from_static("ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"),
        );
        headers.insert("dnt", header::HeaderValue::from_static("1"));
        headers.insert(
            "sec-fetch-site",
            header::HeaderValue::from_static("same-site"),
        );
        headers.insert("sec-fetch-mode", header::HeaderValue::from_static("cors"));
        headers.insert("sec-fetch-dest", header::HeaderValue::from_static("empty"));
        headers.insert(
            header::ORIGIN,
            header::HeaderValue::from_static("https://vk.com"),
        );
        headers.insert(
            header::REFERER,
            header::HeaderValue::from_static("https://vk.com/"),
        );
        for (name, value) in extra {
            insert_header(&mut headers, name, value)?;
        }
        let mut request = self.client.request(method, endpoint).headers(headers);
        if let Some(values) = form {
            request = request
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(encode_form(values));
        }
        let response = request.send().await?;
        response.bytes().await.map_err(Into::into)
    }

    async fn perform_check(
        &self,
        session_token: &str,
        browser_fp: &str,
        hash: &str,
        answer: &str,
        cursor: &str,
        debug_info: &str,
    ) -> Result<CaptchaCheck> {
        let encoded_answer = STANDARD.encode(answer);
        let response = self
            .request(
                "captchaNotRobot.check",
                &[
                    ("session_token", session_token),
                    ("domain", "vk.com"),
                    ("adFp", ""),
                    ("accelerometer", "[]"),
                    ("gyroscope", "[]"),
                    ("motion", "[]"),
                    ("cursor", cursor),
                    ("taps", "[]"),
                    ("connectionRtt", "[]"),
                    ("connectionDownlink", "[]"),
                    ("browser_fp", browser_fp),
                    ("hash", hash),
                    ("answer", &encoded_answer),
                    ("debug_info", debug_info),
                    ("access_token", ""),
                ],
            )
            .await
            .context("captcha check failed")?;
        let raw = response
            .get("response")
            .ok_or_else(|| anyhow!("invalid captcha check response: {response}"))?;
        let check = CaptchaCheck {
            status: string_value(raw.get("status")),
            success_token: string_value(raw.get("success_token")),
            show_type: string_value(raw.get("show_captcha_type")),
        };
        if check.status.is_empty() {
            bail!("captcha check status missing: {response}");
        }
        if check.show_type.is_empty() {
            crate::log_error!("[КАПЧА] v2 check status={}", check.status);
        } else {
            crate::log_error!(
                "[КАПЧА] v2 check status={} show_type={}",
                check.status,
                check.show_type
            );
        }
        Ok(check)
    }

    async fn solve_checkbox(
        &self,
        session_token: &str,
        browser_fp: &str,
        hash: &str,
        debug_info: &str,
    ) -> Result<String> {
        let device = self
            .saved_profile
            .filter(|saved| !saved.device_json.trim().is_empty())
            .map(|saved| saved.device_json.as_str())
            .unwrap_or(DEVICE_INFO);
        self.request(
            "captchaNotRobot.componentDone",
            &[
                ("session_token", session_token),
                ("domain", "vk.com"),
                ("adFp", ""),
                ("browser_fp", browser_fp),
                ("device", device),
                ("access_token", ""),
            ],
        )
        .await
        .context("captcha componentDone failed")?;
        let delay = rand::rng().random_range(400..650);
        tokio::select! {
            _ = self.cancel.cancelled() => bail!("captcha cancelled"),
            _ = tokio::time::sleep(Duration::from_millis(delay)) => {}
        }
        let check = self
            .perform_check(session_token, browser_fp, hash, "{}", "[]", debug_info)
            .await?;
        if !check.show_type.is_empty() && !check.show_type.eq_ignore_ascii_case("checkbox") {
            return Err(ShowTypeMismatch(check.show_type).into());
        }
        if check.status.eq_ignore_ascii_case("error_limit") {
            return Err(RateLimit.into());
        }
        if check.status.eq_ignore_ascii_case("bot") {
            return Err(BotChallenge.into());
        }
        if !check.status.eq_ignore_ascii_case("ok") {
            bail!("checkbox captcha rejected: status={}", check.status);
        }
        if check.success_token.is_empty() {
            bail!("captcha success token not found");
        }
        Ok(check.success_token)
    }

    async fn solve_slider(
        &self,
        session_token: &str,
        browser_fp: &str,
        hash: &str,
        settings: &str,
        debug_info: &str,
    ) -> Result<String> {
        crate::captcha_slider::solve_slider(
            self,
            session_token,
            browser_fp,
            hash,
            settings,
            debug_info,
        )
        .await
    }
}

fn parse_page(html: &str) -> Result<CaptchaPage> {
    let init: Option<CaptchaInit> = match extract_window_init(html) {
        Ok(raw) => Some(serde_json::from_str(&raw).context("captcha init json parse")?),
        Err(_) => WINDOW_INIT
            .as_ref()
            .and_then(|regex| regex.captures(html))
            .and_then(|captures| serde_json::from_str(&captures[1]).ok()),
    };
    let debug_info = DEBUG_UUID
        .as_ref()
        .and_then(|regex| regex.captures(html))
        .map(|captures| captures[1].to_owned())
        .unwrap_or_default();
    let script_url = SCRIPT_SOURCE
        .as_ref()
        .and_then(|regex| regex.captures(html))
        .map(|captures| captures[1].to_owned())
        .unwrap_or_else(|| "https://id.vk.com/js/api/oauth.js".to_owned());
    let mut pow_input = POW_INPUT
        .as_ref()
        .and_then(|regex| regex.captures(html))
        .map(|captures| captures[1].to_owned())
        .unwrap_or_default();
    let mut pow_difficulty = POW_DIFFICULTY
        .as_ref()
        .and_then(|regex| regex.captures(html))
        .and_then(|captures| captures[1].parse().ok())
        .unwrap_or_default();
    if pow_input.is_empty()
        && let Some(captures) = POW_OBFUSCATED
            .as_ref()
            .and_then(|regex| regex.captures(html))
    {
        pow_input = captures[1].to_owned();
        pow_difficulty = captures[2].parse().unwrap_or(4);
    }
    if let Some(init) = &init
        && pow_input.is_empty()
        && let Some(setting) = init
            .data
            .captcha_settings
            .iter()
            .find(|setting| setting.kind == "pow")
    {
        pow_input = if setting.settings.is_empty() {
            setting.settings_key.clone()
        } else {
            setting.settings.clone()
        };
    }
    if !pow_input.is_empty() && pow_difficulty == 0 {
        pow_difficulty = 4;
    }
    Ok(CaptchaPage {
        pow_input,
        pow_difficulty,
        script_url,
        init,
        debug_info,
    })
}

fn initial_captcha_state(init: Option<CaptchaInit>) -> (String, String) {
    let Some(init) = init else {
        return (String::new(), String::new());
    };
    let mut slider_settings = String::new();
    for setting in init.data.captcha_settings {
        if setting.kind == "slider" {
            slider_settings = setting.settings;
        }
    }
    (init.data.show_captcha_type, slider_settings)
}

fn extract_window_init(html: &str) -> Result<String> {
    let token = html
        .find("window.init")
        .ok_or_else(|| anyhow!("window.init token not found"))?;
    let start = html[token + "window.init".len()..]
        .find('{')
        .map(|offset| token + "window.init".len() + offset)
        .ok_or_else(|| anyhow!("captcha init json start brace not found"))?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, character) in html[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
        } else if character == '"' {
            in_string = true;
        } else if character == '{' {
            depth += 1;
        } else if character == '}' {
            depth -= 1;
            if depth == 0 {
                return Ok(html[start..=start + offset].to_owned());
            }
        }
    }
    bail!("unbalanced braces in captcha init json")
}

// Difficulty comes from server HTML; a hostile value would otherwise build a
// multi-megabyte target string before burning the full nonce range.
const MAX_POW_DIFFICULTY: usize = 8;

fn hash_meets_target(digest: &[u8], difficulty: usize) -> bool {
    // Hex target is `difficulty` leading '0' chars == that many leading
    // zero bits (high nibble first), checked without per-nonce allocation.
    let full_bytes = difficulty / 2;
    if digest[..full_bytes].iter().any(|byte| *byte != 0) {
        return false;
    }
    difficulty.is_multiple_of(2) || digest[full_bytes] & 0xF0 == 0
}

fn solve_pow(input: &str, difficulty: usize, cancel: &CancellationToken) -> Result<String> {
    std::thread::sleep(Duration::from_millis(rand::rng().random_range(200..500)));
    if input.is_empty() || difficulty == 0 {
        bail!("captcha pow failed");
    }
    if difficulty > MAX_POW_DIFFICULTY {
        bail!("captcha pow difficulty too high: {difficulty}");
    }
    let mut source = Vec::with_capacity(input.len() + 8);
    for nonce in 0..=10_000_000u32 {
        if nonce % 4096 == 0 && cancel.is_cancelled() {
            bail!("captcha pow cancelled");
        }
        source.clear();
        source.extend_from_slice(input.as_bytes());
        source.extend_from_slice(nonce.to_string().as_bytes());
        let digest = Sha256::digest(&source);
        if hash_meets_target(&digest, difficulty) {
            return Ok(hex::encode(digest));
        }
    }
    bail!("captcha pow failed")
}

fn base_values(session_token: &str) -> Vec<(&str, &str)> {
    vec![
        ("session_token", session_token),
        ("domain", "vk.com"),
        ("adFp", ""),
        ("access_token", ""),
    ]
}

fn encode_form(values: &[(&str, &str)]) -> String {
    let mut output = String::new();
    for (index, (key, value)) in values.iter().enumerate() {
        if index != 0 {
            output.push('&');
        }
        encode_component(&mut output, key);
        output.push('=');
        encode_component(&mut output, value);
    }
    output
}

fn encode_component(output: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        match byte {
            b' ' => output.push('+'),
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char)
            }
            _ => {
                output.push('%');
                output.push(HEX.get((byte >> 4) as usize).copied().unwrap_or(b'0') as char);
                output.push(HEX.get((byte & 0x0f) as usize).copied().unwrap_or(b'0') as char);
            }
        }
    }
}

fn insert_header(headers: &mut header::HeaderMap, name: &str, value: &str) -> Result<()> {
    headers.insert(
        header::HeaderName::from_bytes(name.as_bytes())?,
        header::HeaderValue::from_str(value)?,
    );
    Ok(())
}

fn string_value(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(value) => value.to_string(),
    }
}

pub(crate) fn response_object(value: &Value) -> Result<&Map<String, Value>> {
    value
        .get("response")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("invalid slider content response: {value}"))
}

pub(crate) fn device_info(saved: Option<&SavedProfile>) -> &str {
    saved
        .filter(|profile| !profile.device_json.trim().is_empty())
        .map(|profile| profile.device_json.as_str())
        .unwrap_or(DEVICE_INFO)
}

pub(crate) fn value_string(value: Option<&Value>) -> String {
    string_value(value)
}

pub(crate) async fn slider_request<'a>(
    session: &CaptchaSession<'a>,
    method: &str,
    values: &[(&str, &str)],
) -> Result<Value> {
    session.request(method, values).await
}

pub(crate) async fn slider_check<'a>(
    session: &CaptchaSession<'a>,
    session_token: &str,
    browser_fp: &str,
    hash: &str,
    answer: &str,
    cursor: &str,
    debug_info: &str,
) -> Result<(String, String)> {
    let check = session
        .perform_check(session_token, browser_fp, hash, answer, cursor, debug_info)
        .await?;
    Ok((check.status, check.success_token))
}

pub(crate) fn slider_saved_profile<'a>(session: &CaptchaSession<'a>) -> Option<&'a SavedProfile> {
    session.saved_profile
}

#[cfg(test)]
mod tests {
    use super::*;

    fn daemon_fixture() -> VkCaptchaError {
        VkCaptchaError::from_json(&serde_json::json!({"error_code":14,
            "redirect_uri":"https://id.vk.com/captcha?session_token=private-session"})).unwrap()
    }

    #[tokio::test]
    async fn daemon_manual_takeover_wins_auto_race_and_result_is_one_use() {
        let solver=CaptchaSolver::new("auto",CancellationToken::new());
        let (id,auto_cancel,receive,_)=solver.begin_daemon_challenge(&daemon_fixture(),Duration::from_secs(60));
        assert!(!solver.daemon_answer(&id,Ok("premature".into())));
        assert!(!solver.daemon_takeover("stale"));
        assert!(solver.daemon_takeover(&id));
        assert!(auto_cancel.is_cancelled());
        assert!(!solver.finish_daemon_auto(&id));
        let public=solver.daemon_pending.lock().unwrap().as_ref().unwrap().public_status();
        assert!(public.get("session_token").is_none());
        assert!(public.get("redirect_uri").is_none());
        assert_eq!(solver.daemon_challenge().unwrap()["session_token"],"private-session");
        assert!(solver.daemon_answer(&id,Ok("solved-token".into())));
        assert_eq!(receive.await.unwrap().unwrap(),"solved-token");
        assert!(!solver.daemon_answer(&id,Ok("duplicate".into())));
        assert!(solver.daemon_challenge().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn daemon_expiry_and_cancel_reject_old_answers() {
        let solver=CaptchaSolver::new("auto",CancellationToken::new());
        let (first,auto_cancel,receive,_)=solver.begin_daemon_challenge(&daemon_fixture(),Duration::from_secs(30));
        assert!(solver.daemon_takeover(&first));
        tokio::time::advance(Duration::from_secs(30)).await;
        assert!(!solver.daemon_answer(&first,Ok("expired".into())));
        assert!(auto_cancel.is_cancelled());
        assert!(receive.await.is_err());
        let (second,auto_cancel,receive,_)=solver.begin_daemon_challenge(&daemon_fixture(),Duration::from_secs(60));
        assert_ne!(first,second);
        assert!(!solver.daemon_takeover(&first));
        assert!(solver.daemon_answer(&second,Err("cancelled".into())));
        assert!(receive.await.unwrap().is_err());
        assert!(auto_cancel.is_cancelled());
        assert!(!solver.daemon_answer(&second,Ok("late".into())));
    }

    #[tokio::test]
    async fn daemon_cleanup_cannot_clear_a_newer_challenge() {
        let solver=CaptchaSolver::new("auto",CancellationToken::new());
        let (old,_,_,_)=solver.begin_daemon_challenge(&daemon_fixture(),Duration::from_secs(60));
        solver.clear_daemon_challenge(&old);
        let (new,_,_,_)=solver.begin_daemon_challenge(&daemon_fixture(),Duration::from_secs(60));
        drop(ChallengeGuard { solver:&solver,id:old });
        assert_eq!(solver.daemon_challenge().unwrap()["id"],new);
        drop(ChallengeGuard { solver:&solver,id:new });
        assert!(solver.daemon_challenge().is_none());
    }

    #[tokio::test]
    async fn daemon_enforces_broker_token_limit_and_published_epoch_expiry() {
        let solver=CaptchaSolver::new("auto",CancellationToken::new());
        let (id,_,receive,_)=solver.begin_daemon_challenge(&daemon_fixture(),Duration::from_secs(60));
        assert!(solver.daemon_takeover(&id));
        assert!(!solver.daemon_answer(&id,Ok("x".repeat(MAX_CAPTCHA_TOKEN_BYTES+1))));
        assert!(solver.daemon_answer(&id,Ok("x".repeat(MAX_CAPTCHA_TOKEN_BYTES))));
        assert_eq!(receive.await.unwrap().unwrap().len(),MAX_CAPTCHA_TOKEN_BYTES);

        let (id,_,receive,_)=solver.begin_daemon_challenge(&daemon_fixture(),Duration::from_secs(60));
        assert!(solver.daemon_takeover(&id));
        // Simulate the published epoch deadline passing before the monotonic
        // deadline (including a forward wall-clock adjustment).
        solver.daemon_pending.lock().unwrap().as_mut().unwrap().expires_at=crate::daemon::now();
        assert!(!solver.daemon_answer(&id,Ok("late".into())));
        assert!(receive.await.is_err());
    }

    #[tokio::test]
    async fn daemon_shutdown_revokes_answers_immediately() {
        let cancel=CancellationToken::new();
        let solver=CaptchaSolver::new("auto",cancel.clone());
        let (id,_,receive,_)=solver.begin_daemon_challenge(&daemon_fixture(),Duration::from_secs(60));
        assert!(solver.daemon_takeover(&id));
        cancel.cancel();
        assert!(!solver.daemon_answer(&id,Ok("late".into())));
        assert!(solver.daemon_challenge().is_none());
        assert!(receive.await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn unclaimed_manual_fallback_is_revoked_for_fresh_auth_after_one_minute() {
        let solver=CaptchaSolver::new("auto",CancellationToken::new());
        let (id,auto_cancel,receive,deadline)=solver.begin_daemon_challenge(&daemon_fixture(),Duration::from_secs(180));
        solver.manual_available(&id);
        assert_eq!(solver.daemon_challenge().unwrap()["human_active"],false);
        assert!(!solver.daemon_answer(&id,Ok("unclaimed-token".into())));
        let started=tokio::time::Instant::now();
        let wait=solver.wait_daemon_answer(&id,receive,deadline,started+FRESH_AUTH_INTERVAL);
        let result=wait.await.unwrap_err();
        assert!(result.downcast_ref::<FreshAuthRequired>().is_some());
        assert_eq!(started.elapsed(),FRESH_AUTH_INTERVAL);
        assert!(auto_cancel.is_cancelled());
        assert!(solver.daemon_challenge().is_none());
        assert!(!solver.daemon_takeover(&id));
        assert!(!solver.daemon_answer(&id,Ok("late-token".into())));
    }

    #[tokio::test(start_paused = true)]
    async fn explicit_human_takeover_protects_existing_expiry_across_soft_retry() {
        let solver=CaptchaSolver::new("auto",CancellationToken::new());
        let (id,_,receive,deadline)=solver.begin_daemon_challenge(&daemon_fixture(),Duration::from_secs(180));
        solver.manual_available(&id);
        assert!(solver.daemon_takeover(&id));
        assert_eq!(solver.daemon_challenge().unwrap()["human_active"],true);
        let waiting=solver.clone(); let request=id.clone();
        let task=tokio::spawn(async move {
            waiting.wait_daemon_answer(&request,receive,deadline,tokio::time::Instant::now()+FRESH_AUTH_INTERVAL).await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        assert!(solver.daemon_answer(&id,Ok("human-token".into())));
        assert_eq!(task.await.unwrap().unwrap(),"human-token");
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_lease_and_pairing_admission_are_mutually_exclusive_and_bounded() {
        let solver=CaptchaSolver::new("auto",CancellationToken::new());
        let (id,_,receive,_)=solver.begin_daemon_challenge(&daemon_fixture(),Duration::from_secs(180));
        solver.manual_available(&id);
        let (lease,_)=solver.daemon_recovery_begin(Some(&id)).unwrap();
        assert!(solver.recovery_in_progress());
        assert!(!solver.daemon_takeover(&id));
        assert_eq!(solver.daemon_recovery_begin(None).unwrap_err(),"recovery_in_progress");
        assert!(!solver.daemon_recovery_end("other-lease"));
        solver.recovery.lock().unwrap().as_mut().unwrap().expires_at = 0;
        assert!(solver.recovery_in_progress());
        assert!(!solver.daemon_takeover(&id));
        tokio::time::advance(Duration::from_secs(90)).await;
        assert!(!solver.recovery_in_progress());
        assert!(!solver.daemon_recovery_end(&lease));
        assert!(solver.daemon_takeover(&id));
        assert_eq!(solver.daemon_recovery_begin(None).unwrap_err(),"human_active");
        assert!(solver.daemon_answer(&id,Err("cancelled".into())));
        assert_eq!(receive.await.unwrap().unwrap_err(), "cancelled");
        let (next,_)=solver.daemon_recovery_begin(None).unwrap();
        assert!(solver.daemon_recovery_end(&next));
    }

    #[tokio::test]
    async fn concurrent_recovery_and_human_takeover_have_exactly_one_winner() {
        let solver=CaptchaSolver::new("auto",CancellationToken::new());
        let (id,_,_,_)=solver.begin_daemon_challenge(&daemon_fixture(),Duration::from_secs(180));
        let barrier=Arc::new(tokio::sync::Barrier::new(3));
        let human_solver=solver.clone(); let human_barrier=barrier.clone();
        let human=tokio::spawn(async move { human_barrier.wait().await; human_solver.daemon_takeover(&id) });
        let recovery_solver=solver.clone(); let recovery_barrier=barrier.clone();
        let recovery=tokio::spawn(async move { recovery_barrier.wait().await; recovery_solver.daemon_recovery_begin(None).is_ok() });
        barrier.wait().await;
        assert_ne!(human.await.unwrap(),recovery.await.unwrap());
    }

    #[test]
    fn extracts_balanced_window_init() {
        let html = r#"<script>window.init = {"data":{"text":"}"},"next":{"x":1}};</script>"#;
        assert_eq!(
            extract_window_init(html).unwrap(),
            r#"{"data":{"text":"}"},"next":{"x":1}}"#
        );
    }

    #[test]
    fn preserves_form_order_and_escaping() {
        assert_eq!(
            encode_form(&[("a", "x y*~"), ("b", "тест")]),
            "a=x+y%2A~&b=%D1%82%D0%B5%D1%81%D1%82"
        );
    }

    #[test]
    fn parses_captcha_error_numbers() {
        let error = VkCaptchaError::from_json(&serde_json::json!({
            "error_code": 14,
            "captcha_sid": 123,
            "captcha_ts": 99,
            "redirect_uri": "https://id.vk.com/captcha?session_token=abc"
        }))
        .unwrap();
        assert_eq!(error.captcha_sid, "123");
        assert_eq!(error.captcha_timestamp, "99");
        assert_eq!(error.session_token, "abc");
    }

    #[test]
    fn accepts_partial_window_init_like_go_json() {
        let html = r#"<script>window.init={"data":{"captcha_settings":[{"type":"pow","settings_key":"pow-value"},{"type":"slider","settings":"slider-value"}]}};</script>"#;
        let page = parse_page(html).unwrap();
        assert_eq!(page.pow_input, "pow-value");
        assert_eq!(page.pow_difficulty, 4);
        let (show_type, settings) = initial_captcha_state(page.init);
        assert_eq!(show_type, "");
        assert_eq!(settings, "slider-value");
    }

    #[test]
    fn slider_init_uses_settings_not_settings_key() {
        let init = serde_json::from_value(serde_json::json!({
            "data": {
                "show_captcha_type": "slider",
                "captcha_settings": [{"type": "slider", "settings_key": "key"}]
            }
        }))
        .unwrap();
        let (show_type, settings) = initial_captcha_state(Some(init));
        assert_eq!(show_type, "slider");
        assert_eq!(settings, "");
    }

    #[test]
    fn parses_obfuscated_pow_settings() {
        let html = r#"<script>(function(_0x1be24c,_0x543e3e,_0x23e37e){})("qEM5I4OpTkTmPKFL",2,"pow_timeout");</script>"#;
        let page = parse_page(html).unwrap();
        assert_eq!(page.pow_input, "qEM5I4OpTkTmPKFL");
        assert_eq!(page.pow_difficulty, 2);
    }

    #[test]
    fn invalid_balanced_window_init_is_not_silently_ignored() {
        assert!(parse_page(r#"<script>window.init={"data":]};</script>"#).is_err());
    }
}
