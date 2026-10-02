//! OneDux Desk: connection telemetry for the hosted-server beta.
//!
//! What is sent: connection metadata only - how a connection was made (direct / relay), whether it
//! worked and how long it took, how long the session lasted and how many bytes it received, the
//! latency to the rendezvous server, the coarse NAT type, whether a public IPv6 address exists,
//! rendezvous reconnects and the kind of network (wifi / cellular / wired) before and after a
//! change - plus client version / OS / architecture
//! and this device's and the peer's RustDesk ID (replaced by an HMAC on the server, never stored).
//! Never sent: session content, input, clipboard, files, or the public IP address (the server infers
//! ISP / region from the source address and drops it).
//!
//! Events are appended to a JSON-lines queue in the config directory (one file per process kind,
//! capped at 1 MiB, events older than 7 days dropped) and sent in batches to the OneDux console
//! every 5 minutes or once 20 are waiting. Every event carries its own uuid and the server stores an
//! event id once, so a batch that is sent twice is harmless - which is what keeps this simple file
//! queue safe across retries and processes.
//!
//! Off switch: the `enable-oneduxdesk-telemetry` option ("N" = off, default on), shown in the
//! general settings; switching it off stops recording and clears the queue. Telemetry never decides
//! whether a connection is allowed and is not used for billing.

use hbb_common::{
    config::{self, Config},
    log,
    tls::{get_cached_tls_type, upsert_tls_cache, TlsType},
    tokio, ResultType,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};

pub const OPTION_ENABLE: &str = "enable-oneduxdesk-telemetry";
/// For testing against another console; empty = DEFAULT_URL.
const OPTION_URL: &str = "oneduxdesk-telemetry-url";
const DEFAULT_URL: &str = "https://console.onedux.com/api/rdh/telemetry";

const MAX_QUEUE_BYTES: u64 = 1 << 20;
/// The console rejects batches of more than 100 events.
const MAX_BATCH: usize = 100;
const SEND_EVERY: Duration = Duration::from_secs(300);
const SEND_AT: usize = 20;
const MAX_BACKOFF: Duration = Duration::from_secs(3600);
const MAX_AGE_SECS: i64 = 7 * 24 * 3600;
/// The rendezvous latency is measured on every register (~every 12 s); one sample per 5 minutes is
/// plenty for the line-quality question and keeps the queue small.
const LATENCY_EVERY: Duration = Duration::from_secs(300);
/// How often the default interface is looked at for network_change.
const NETWORK_CHECK_EVERY: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
enum Queue {
    /// The process that registers with the rendezvous server (the service on Windows).
    Server = 0,
    /// The process that makes outgoing connections (the UI).
    Client = 1,
}

impl Queue {
    fn path(self) -> PathBuf {
        let name = match self {
            Queue::Server => "server",
            Queue::Client => "client",
        };
        Config::path(format!("oneduxdesk-telemetry-{name}.jsonl"))
    }
}

lazy_static::lazy_static! {
    static ref FILE_LOCK: Mutex<()> = Mutex::new(());
    static ref RELAY_UUID: Mutex<HashMap<String, String>> = Default::default();
    static ref LAST_LATENCY: Mutex<Option<Instant>> = Default::default();
    /// peer id -> session uuid of the last successful connect_result, taken by session_started.
    static ref SESSION_UUID: Mutex<HashMap<String, String>> = Default::default();
    /// (last check, (interface kind, IPv4 address)) of the default interface. The address only
    /// tells whether the network changed; it is never sent.
    static ref NETWORK: Mutex<(Option<Instant>, Option<(&'static str, String)>)> = Default::default();
    /// Controlled side: controller address -> (relay uuid, when the relay was requested).
    static ref CONTROLLED_RELAY: Mutex<HashMap<SocketAddr, (String, Instant)>> = Default::default();
}
static SENDER_STARTED: [AtomicBool; 2] = [AtomicBool::new(false), AtomicBool::new(false)];
static PENDING: AtomicUsize = AtomicUsize::new(0);
static APP_START_SENT: AtomicBool = AtomicBool::new(false);

fn enabled() -> bool {
    config::option2bool(OPTION_ENABLE, &Config::get_option(OPTION_ENABLE))
}

// --- events -------------------------------------------------------------------------------------

/// A latency sample to the rendezvous server, in milliseconds. The first one of the process also
/// records `app_start`: by then the NAT test and the IPv6 probe have usually finished.
pub fn hbbs_latency(latency_ms: i64) {
    if latency_ms <= 0 || !enabled() {
        return;
    }
    check_network();
    if !APP_START_SENT.swap(true, Ordering::SeqCst) {
        let nat = match Config::get_nat_type() {
            n @ 0..=2 => n,
            _ => 0,
        };
        record(
            Queue::Server,
            json!({
                "type": "app_start",
                "nat_type": nat,
                "ipv6_available": crate::common::oneduxdesk_has_public_ipv6(),
            }),
        );
    }
    {
        let mut last = LAST_LATENCY.lock().unwrap();
        if last.map(|t| t.elapsed() < LATENCY_EVERY).unwrap_or(false) {
            return;
        }
        *last = Some(Instant::now());
    }
    record(
        Queue::Server,
        json!({"type": "hbbs_latency", "latency_ms": latency_ms}),
    );
}

/// Called from the rendezvous register loop, so it runs while the network is up: a switch made
/// while offline shows up at the first register answer after it.
fn check_network() {
    let mut net = NETWORK.lock().unwrap();
    if net.0.map(|t| t.elapsed() < NETWORK_CHECK_EVERY).unwrap_or(false) {
        return;
    }
    net.0 = Some(Instant::now());
    let Some(now) = default_network() else {
        return;
    };
    if let Some(before) = net.1.as_ref() {
        if *before != now {
            record(
                Queue::Server,
                json!({"type": "network_change", "from": before.0, "to": now.0}),
            );
        }
    }
    net.1 = Some(now);
}

/// (kind, IPv4 address) of the default interface.
#[cfg(not(target_os = "ios"))]
fn default_network() -> Option<(&'static str, String)> {
    use default_net::interface::InterfaceType as T;
    let iface = default_net::get_default_interface().ok()?;
    let kind = match iface.if_type {
        T::Wireless80211 => "wifi",
        T::Wwanpp | T::Wwanpp2 => "cellular",
        T::Ethernet
        | T::GigabitEthernet
        | T::FastEthernetT
        | T::FastEthernetFx
        | T::Ethernet3Megabit => "wired",
        _ => "unknown",
    };
    let addr = iface
        .ipv4
        .first()
        .map(|n| n.addr.to_string())
        .unwrap_or_default();
    Some((kind, addr))
}

// default_net leaves undefined symbols on the iOS simulator (see src/lan.rs).
#[cfg(target_os = "ios")]
fn default_network() -> Option<(&'static str, String)> {
    None
}

/// A controller session that connected; pass it back to session_end when it closes.
pub struct Session {
    uuid: String,
    started: Instant,
}

/// Start of the session loop after a successful connection to `peer`. Its uuid is the one the
/// connect_result for the same connection carried, so the two events can be joined.
pub fn session_started(peer: &str) -> Session {
    Session {
        uuid: SESSION_UUID
            .lock()
            .unwrap()
            .remove(peer)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        started: Instant::now(),
    }
}

/// The session loop ended. `reason`: user / peer / network / error. Only the received byte count
/// is reported (sends are spread over too many call sites); both are the client's view and are
/// only compared with the server-side metering, never billed.
pub fn session_end(session: Session, bytes_rx: u64, reason: &str) {
    record(
        Queue::Client,
        json!({
            "type": "session_end",
            "session_uuid": session.uuid,
            "duration_s": session.started.elapsed().as_secs(),
            "bytes_rx": bytes_rx,
            "reason": reason,
        }),
    );
}

/// The rendezvous server answered again after `attempt` consecutive register timeouts.
pub fn hbbs_reconnect(attempt: i64) {
    record(
        Queue::Server,
        json!({"type": "reconnect", "kind": "hbbs", "attempt": attempt.max(0)}),
    );
}

/// Remember the relay session uuid for `peer`, so the connect_result of a relayed connection
/// carries the same uuid the relay server logs (the console cross-checks the two).
pub fn note_relay_uuid(peer: &str, uuid: &str) {
    RELAY_UUID
        .lock()
        .unwrap()
        .insert(peer.to_owned(), uuid.to_owned());
}

/// One outgoing connection attempt finished: Ok((transport, direct)) or Err(error text).
/// The error text is reduced to a category here; free text is never sent.
pub fn connect_result(peer: &str, outcome: Result<(&str, bool), &str>, elapsed: Duration) {
    let relay_uuid = RELAY_UUID
        .lock()
        .unwrap()
        .remove(peer)
        .filter(|u| uuid::Uuid::parse_str(u).is_ok());
    let mut ev = json!({
        "type": "connect_result",
        "role": "controller",
        "peer": peer.chars().take(32).collect::<String>(),
        "connect_ms": elapsed.as_millis() as u64,
    });
    match outcome {
        Ok((typ, direct)) => {
            let relayed = matches!(typ, "Relay" | "WebSocket");
            ev["success"] = json!(true);
            ev["conn_type"] = json!(typ.chars().take(16).collect::<String>());
            ev["relay_used"] = json!(relayed);
            ev["punch_ok"] = json!(direct);
            let session_uuid = relay_uuid
                .filter(|_| relayed)
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            SESSION_UUID
                .lock()
                .unwrap()
                .insert(peer.to_owned(), session_uuid.clone());
            ev["session_uuid"] = json!(session_uuid);
        }
        Err(err) => {
            ev["success"] = json!(false);
            ev["error"] = json!(error_class(err));
            ev["session_uuid"] =
                json!(relay_uuid.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()));
        }
    }
    record(Queue::Client, ev);
}

// --- controlled side ----------------------------------------------------------------------------
//
// Every incoming connection - relayed, hole-punched or LAN - goes through
// server::create_tcp_connection, which runs the identity handshake and then the whole session.
// A ControlledAttempt spans the handshake: established() records success there, and dropping it
// unfinished (an early return on a handshake error) records the failure, so the upstream
// handshake code stays untouched. The controller's ID is not known yet at that point (it comes
// with the login request), so `peer` is left out.

/// The rendezvous server asked this device to meet `peer_addr` at a relay under `uuid`.
pub fn controlled_relay_requested(peer_addr: SocketAddr, uuid: &str) {
    CONTROLLED_RELAY.lock().unwrap().insert(
        hbb_common::try_into_v4(peer_addr),
        (uuid.to_owned(), Instant::now()),
    );
}

/// The relay connection failed. Records the failure only if it happened before the handshake
/// (otherwise the attempt has already been recorded and this is the session ending).
pub fn controlled_relay_failed(peer_addr: SocketAddr, err: &str) {
    let entry = CONTROLLED_RELAY
        .lock()
        .unwrap()
        .remove(&hbb_common::try_into_v4(peer_addr));
    if let Some((uuid, started)) = entry {
        record(
            Queue::Server,
            json!({
                "type": "connect_result",
                "role": "controlled",
                "session_uuid": uuid_or_new(Some(uuid)),
                "conn_type": "Relay",
                "relay_used": true,
                "success": false,
                "error": error_class(err),
                "connect_ms": started.elapsed().as_millis() as u64,
            }),
        );
    }
}

pub struct ControlledAttempt {
    addr: SocketAddr,
    webrtc: bool,
    started: Instant,
    done: bool,
}

impl ControlledAttempt {
    /// `addr` as create_tcp_connection keys it (already try_into_v4).
    pub fn new(addr: SocketAddr, webrtc: bool) -> Self {
        Self {
            addr,
            webrtc,
            started: Instant::now(),
            done: false,
        }
    }

    pub fn established(mut self) {
        self.done = true;
        self.finish(true);
    }

    fn finish(&self, success: bool) {
        let relay = CONTROLLED_RELAY.lock().unwrap().remove(&self.addr);
        let relayed = relay.is_some();
        let (uuid, started) = match relay {
            Some((uuid, started)) => (Some(uuid), started),
            None => (None, self.started),
        };
        let conn_type = if relayed {
            "Relay"
        } else if self.webrtc {
            "WebRTC"
        } else {
            "Direct"
        };
        let mut ev = json!({
            "type": "connect_result",
            "role": "controlled",
            "session_uuid": uuid_or_new(uuid),
            "conn_type": conn_type,
            "relay_used": relayed,
            "punch_ok": !relayed,
            "success": success,
            "connect_ms": started.elapsed().as_millis() as u64,
        });
        if !success {
            ev["error"] = json!("handshake");
        }
        record(Queue::Server, ev);
    }
}

impl Drop for ControlledAttempt {
    fn drop(&mut self) {
        if !self.done {
            self.finish(false);
        }
    }
}

fn uuid_or_new(uuid: Option<String>) -> String {
    uuid.filter(|u| uuid::Uuid::parse_str(u).is_ok())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

fn error_class(err: &str) -> &'static str {
    let e = err.to_ascii_lowercase();
    if e.contains("offline") {
        "peer_offline"
    } else if e.contains("not exist") {
        "id_not_exist"
    } else if e.contains("timeout") || e.contains("timed out") || e.contains("deadline") {
        "timeout"
    } else if e.contains("key") && (e.contains("mismatch") || e.contains("invalid")) {
        "key_mismatch"
    } else if e.contains("relay") {
        "relay_failed"
    } else if e.contains("refused") || e.contains("reset") || e.contains("unreachable") {
        "network"
    } else {
        "other"
    }
}

// --- queue --------------------------------------------------------------------------------------

fn record(q: Queue, mut ev: Value) {
    if !enabled() {
        return;
    }
    ev["id"] = json!(uuid::Uuid::new_v4().to_string());
    ev["ts"] = json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    {
        let _g = FILE_LOCK.lock().unwrap();
        let path = q.path();
        if fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > MAX_QUEUE_BYTES {
            trim_oldest(&path);
        }
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(mut f) => {
                if let Err(e) = writeln!(f, "{}", ev) {
                    log::debug!("telemetry: failed to queue an event: {}", e);
                    return;
                }
            }
            Err(e) => {
                log::debug!("telemetry: failed to open the queue: {}", e);
                return;
            }
        }
    }
    PENDING.fetch_add(1, Ordering::Relaxed);
    start_sender(q);
}

/// Keep the newest events within 3/4 of the cap. Called with FILE_LOCK held.
fn trim_oldest(path: &PathBuf) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let mut keep = Vec::new();
    let mut size = 0u64;
    for line in text.lines().rev().filter(|l| !l.trim().is_empty()) {
        size += line.len() as u64 + 1;
        if size > MAX_QUEUE_BYTES * 3 / 4 {
            break;
        }
        keep.push(line);
    }
    keep.reverse();
    let _ = fs::write(path, lines_to_text(&keep));
}

fn lines_to_text(lines: &[&str]) -> String {
    let mut s = lines.join("\n");
    if !s.is_empty() {
        s.push('\n');
    }
    s
}

fn read_queue(q: Queue) -> Vec<String> {
    let _g = FILE_LOCK.lock().unwrap();
    fs::read_to_string(q.path())
        .map(|t| {
            t.lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| l.to_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Drop the first `n` events. Events are only ever appended after the ones read for a batch, so
/// the first `n` lines are still the ones that were sent.
fn drop_first(q: Queue, n: usize) {
    let _g = FILE_LOCK.lock().unwrap();
    let path = q.path();
    let Ok(text) = fs::read_to_string(&path) else {
        return;
    };
    let rest: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .skip(n)
        .collect();
    PENDING.store(rest.len(), Ordering::Relaxed);
    let _ = fs::write(&path, lines_to_text(&rest));
}

// --- sending ------------------------------------------------------------------------------------

fn start_sender(q: Queue) {
    if SENDER_STARTED[q as usize].swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                log::error!("telemetry: no runtime for the sender: {}", e);
                return;
            }
        };
        rt.block_on(sender_loop(q));
    });
}

async fn sender_loop(q: Queue) {
    let mut wait = SEND_EVERY;
    let mut last = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let early = wait == SEND_EVERY && PENDING.load(Ordering::Relaxed) >= SEND_AT;
        if last.elapsed() < wait && !early {
            continue;
        }
        last = Instant::now();
        match send_once(q).await {
            Ok(()) => wait = SEND_EVERY,
            Err(e) => {
                log::debug!("telemetry: send failed, retrying later: {}", e);
                wait = (wait * 2).min(MAX_BACKOFF);
            }
        }
    }
}

async fn send_once(q: Queue) -> ResultType<()> {
    let lines = read_queue(q);
    if lines.is_empty() {
        PENDING.store(0, Ordering::Relaxed);
        return Ok(());
    }
    if !enabled() {
        drop_first(q, usize::MAX);
        return Ok(());
    }
    let n = lines.len().min(MAX_BATCH);
    let cutoff = chrono::Utc::now().timestamp() - MAX_AGE_SECS;
    let events: Vec<Value> = lines[..n]
        .iter()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| {
            v["ts"]
                .as_str()
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                .map(|t| t.timestamp() >= cutoff)
                .unwrap_or(false)
        })
        .collect();
    if events.is_empty() {
        drop_first(q, n);
        return Ok(());
    }
    // No server imported yet: keep the events (capped by size and age) until there is one to
    // attribute them to.
    let Some(body) = batch_body(events) else {
        return Ok(());
    };
    let status = post(body).await?;
    if (200..300).contains(&status) || status == 400 || status == 413 {
        // 400 / 413: this batch will never be accepted; dropping it keeps one bad event from
        // blocking the queue forever.
        drop_first(q, n);
        Ok(())
    } else {
        hbb_common::bail!("status {}", status)
    }
}

fn batch_body(events: Vec<Value>) -> Option<String> {
    use sha2::{Digest, Sha256};
    let id_server = Config::get_option("custom-rendezvous-server")
        .trim()
        .to_lowercase();
    let key = Config::get_option("key").trim().to_owned();
    if id_server.is_empty() || !id_server.contains(':') || key.is_empty() {
        return None;
    }
    // Same fingerprint as the console: SHA-256 of the public key's base64 text, first 16 hex.
    let key_fp: String = Sha256::digest(key.as_bytes())
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect();
    let os_version: String = hbb_common::whoami::distro().chars().take(32).collect();
    Some(
        json!({
            "id_server": id_server,
            "key_fp": key_fp,
            "client": {
                "version": client_version().chars().take(32).collect::<String>(),
                "build": option_env!("ONEDUXDESK_BUILD").unwrap_or("dev"),
                "os": std::env::consts::OS,
                "os_version": os_version,
                "arch": std::env::consts::ARCH,
            },
            "device": Config::get_id().chars().take(32).collect::<String>(),
            "events": events,
        })
        .to_string(),
    )
}

/// `<upstream version>-oneduxdesk.<N>`; N is the release number given to a manual CI run
/// (ONEDUXDESK_RELEASE), "dev" for every other build. Also what the About page shows
/// (ui_interface::get_version), so the two never disagree. Display only: protocol, registration and
/// version comparisons keep using crate::VERSION.
pub fn client_version() -> String {
    let n = option_env!("ONEDUXDESK_RELEASE")
        .filter(|n| !n.is_empty())
        .unwrap_or("dev");
    format!("{}-oneduxdesk.{}", crate::VERSION, n)
}

async fn post(body: String) -> ResultType<u16> {
    let mut url = Config::get_option(OPTION_URL);
    if url.is_empty() {
        url = DEFAULT_URL.to_owned();
    }
    let proxy_conf = Config::get_socks();
    let tls_url = crate::hbbs_http::get_url_for_tls(&url, &proxy_conf).to_owned();
    let cached = get_cached_tls_type(&tls_url);
    let tls_type = cached.unwrap_or(TlsType::Rustls);
    let send = |tls: TlsType| {
        crate::hbbs_http::create_http_client_async(tls, false)
            .post(&url)
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(30))
            .body(body.clone())
            .send()
    };
    let resp = match send(tls_type).await {
        Ok(resp) => {
            upsert_tls_cache(&tls_url, tls_type, false);
            resp
        }
        Err(err) if cached.is_none() && err.is_request() => {
            let resp = send(TlsType::NativeTls).await?;
            upsert_tls_cache(&tls_url, TlsType::NativeTls, false);
            resp
        }
        Err(err) => return Err(err.into()),
    };
    Ok(resp.status().as_u16())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_classes_carry_no_free_text() {
        assert_eq!(error_class("Remote desktop is offline"), "peer_offline");
        assert_eq!(error_class("ID does not exist"), "id_not_exist");
        assert_eq!(error_class("deadline has elapsed"), "timeout");
        assert_eq!(error_class("Failed to connect to relay server"), "relay_failed");
        assert_eq!(error_class("something else entirely: 10.0.0.1"), "other");
    }

    #[test]
    fn client_version_fits_the_console_limit() {
        let v = client_version();
        assert!(v.starts_with(&format!("{}-oneduxdesk.", crate::VERSION)));
        assert!(v.len() <= 32, "{v} is longer than the console's 32 characters");
    }

    #[test]
    fn key_fingerprint_matches_the_console() {
        // rdh_telemetry.key_fp: hashlib.sha256(pubkey.encode()).hexdigest()[:16]
        use sha2::{Digest, Sha256};
        let fp: String = Sha256::digest(b"Msxb7qgv2K7k5BMRYexs0vY5LZOn2+oardEcLKX6vwE=")
            .iter()
            .take(8)
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_eq!(fp, "fe02a6c74c8f1380");
    }
}
