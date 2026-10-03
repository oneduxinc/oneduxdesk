//! OneDux Desk: "a new version is available" notice.
//!
//! Replaces the upstream update check, which OneDux Desk locks off (`enable-check-update`) because it
//! asks api.rustdesk.com and its "Update" button installs a RustDesk release. Instead the client asks
//! the OneDux console, GET /api/rdh/latest, at start-up and once a day. The request carries nothing
//! about this device (no ID, no version), so it is not tied to the telemetry switch. The answer only
//! raises a notice on the main window that opens the console's download page in the browser:
//! nothing is downloaded or installed here.

use hbb_common::{
    config::Config,
    get_version_number, log,
    tls::{get_cached_tls_type, upsert_tls_cache, TlsType},
    tokio, ResultType,
};
use serde_json::{json, Value};
use std::{
    sync::{atomic::AtomicBool, atomic::Ordering, Mutex},
    time::Duration,
};

/// For testing against another console; empty = DEFAULT_URL.
const OPTION_URL: &str = "oneduxdesk-update-url";
const DEFAULT_URL: &str = "https://console.onedux.com/api/rdh/latest";
/// The notice only ever opens a page under this prefix, whatever the endpoint answers.
const PAGE_PREFIX: &str = "https://console.onedux.com/";
const DEFAULT_PAGE: &str = "https://console.onedux.com/rdh";
const CHECK_EVERY: Duration = Duration::from_secs(24 * 3600);
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(3600);

lazy_static::lazy_static! {
    /// Some((version, page)) once a newer version has been seen.
    static ref NEWER: Mutex<Option<(String, String)>> = Default::default();
}
static STARTED: AtomicBool = AtomicBool::new(false);

/// For the main window, which polls it: `{"version": …, "page": …}` when a newer version exists,
/// otherwise "". The first call starts the background check.
pub fn newer_version_json() -> String {
    start();
    match NEWER.lock().unwrap().as_ref() {
        Some((version, page)) => json!({"version": version, "page": page}).to_string(),
        None => String::new(),
    }
}

fn start() {
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(|| {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                log::error!("update check: no runtime: {}", e);
                return;
            }
        };
        rt.block_on(async {
            loop {
                let wait = match check().await {
                    Ok(()) => CHECK_EVERY,
                    Err(e) => {
                        log::debug!("update check failed, retrying later: {}", e);
                        RETRY_AFTER_FAILURE
                    }
                };
                tokio::time::sleep(wait).await;
            }
        });
    });
}

async fn check() -> ResultType<()> {
    let body = get().await?;
    let v: Value = serde_json::from_str(&body)?;
    if v["available"].as_bool() != Some(true) {
        return Ok(());
    }
    let Some(latest) = v["version"].as_str() else {
        return Ok(());
    };
    if is_newer(latest, crate::VERSION, own_release()) {
        let page = safe_page(v["page"].as_str());
        *NEWER.lock().unwrap() = Some((latest.chars().take(64).collect(), page.to_owned()));
    }
    Ok(())
}

/// This build's release number N (ONEDUXDESK_RELEASE), 0 for dev builds, which every release is
/// newer than.
fn own_release() -> u64 {
    option_env!("ONEDUXDESK_RELEASE")
        .and_then(|n| n.parse::<u64>().ok())
        .unwrap_or(0)
}

/// The page the notice opens: the endpoint's answer only if it is on the console.
fn safe_page(page: Option<&str>) -> &str {
    page.filter(|p| p.starts_with(PAGE_PREFIX))
        .unwrap_or(DEFAULT_PAGE)
}

/// `latest` is `<upstream>-oneduxdesk.<N>`; newer = higher upstream version, or the same upstream
/// version with a higher N. Anything that does not parse is never newer.
fn is_newer(latest: &str, mine_upstream: &str, mine_n: u64) -> bool {
    let Some((upstream, n)) = latest.split_once("-oneduxdesk.") else {
        return false;
    };
    let Ok(n) = n.parse::<u64>() else {
        return false;
    };
    let (theirs, mine) = (
        get_version_number(upstream),
        get_version_number(mine_upstream),
    );
    theirs > mine || (theirs == mine && n > mine_n)
}

async fn get() -> ResultType<String> {
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
            .get(&url)
            .timeout(Duration::from_secs(30))
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
    if !resp.status().is_success() {
        hbb_common::bail!("status {}", resp.status());
    }
    Ok(resp.text().await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_by_release_number_or_upstream_version() {
        assert!(is_newer("1.5.0-oneduxdesk.2", "1.5.0", 1));
        assert!(!is_newer("1.5.0-oneduxdesk.1", "1.5.0", 1));
        assert!(!is_newer("1.5.0-oneduxdesk.1", "1.5.0", 2));
        assert!(is_newer("1.5.1-oneduxdesk.1", "1.5.0", 9));
        assert!(!is_newer("1.4.9-oneduxdesk.9", "1.5.0", 1));
        // dev builds (N = 0) are older than any release of the same upstream version
        assert!(is_newer("1.5.0-oneduxdesk.1", "1.5.0", 0));
    }

    #[test]
    fn malformed_versions_are_never_newer() {
        for v in ["", "1.5.0", "1.5.0-oneduxdesk.", "1.5.0-oneduxdesk.x", "2.0.0-rustdesk.1"] {
            assert!(!is_newer(v, "1.5.0", 0), "{v}");
        }
    }

    #[test]
    fn notice_never_points_outside_the_console() {
        for (page, want) in [
            (Some("https://console.onedux.com/rdh"), "https://console.onedux.com/rdh"),
            (Some("https://evil.example/rdh"), DEFAULT_PAGE),
            (Some("http://console.onedux.com/rdh"), DEFAULT_PAGE),
            (None, DEFAULT_PAGE),
        ] {
            assert_eq!(safe_page(page), want);
        }
    }
}
