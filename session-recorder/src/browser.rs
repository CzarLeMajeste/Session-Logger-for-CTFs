// browser.rs – Import recent browser history from local SQLite DBs.

use crate::event::EventRecord;
use regex::Regex;
use rusqlite::Connection;
use std::fs;
use std::path::PathBuf;

fn redact_url(url: &str) -> String {
    let re = Regex::new(
        r"(?i)([?&](?:password|passwd|token|secret|api[_\-]?key|access[_\-]?key|auth)[^&#]*)",
    )
    .unwrap();
    re.replace_all(url, "[REDACTED_PARAM]").to_string()
}

fn chromium_candidates(browser: &str) -> Vec<PathBuf> {
    let home = dirs::home_dir().unwrap_or_default();
    let data = dirs::data_dir().unwrap_or_default();
    let local = dirs::data_local_dir().unwrap_or_default();
    match browser {
        "chrome" => vec![
            home.join(".config/google-chrome/Default/History"),
            data.join("Google/Chrome/Default/History"),
            local.join("Google/Chrome/User Data/Default/History"),
        ],
        "chromium" => vec![
            home.join(".config/chromium/Default/History"),
            data.join("Chromium/Default/History"),
        ],
        "edge" => vec![
            home.join(".config/microsoft-edge/Default/History"),
            data.join("Microsoft Edge/Default/History"),
            local.join("Microsoft/Edge/User Data/Default/History"),
        ],
        "brave" => vec![
            home.join(".config/BraveSoftware/Brave-Browser/Default/History"),
            data.join("BraveSoftware/Brave-Browser/Default/History"),
        ],
        _ => vec![],
    }
}

fn firefox_candidates() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let bases = [
        dirs::home_dir()
            .unwrap_or_default()
            .join(".mozilla/firefox"),
        dirs::data_dir()
            .unwrap_or_default()
            .join("Firefox/Profiles"),
    ];
    for base in &bases {
        if base.is_dir() {
            if let Ok(entries) = fs::read_dir(base) {
                for entry in entries.flatten() {
                    let p = entry.path().join("places.sqlite");
                    if p.exists() {
                        paths.push(p);
                    }
                }
            }
        }
    }
    paths
}

fn read_chromium(db: &PathBuf, since_ts: i64, limit: usize) -> Vec<String> {
    let tmp = std::env::temp_dir()
        .join(format!("sr_ch_{}.db", std::process::id()));
    if fs::copy(db, &tmp).is_err() {
        return vec![];
    }
    let result = (|| -> rusqlite::Result<Vec<String>> {
        let conn = Connection::open(&tmp)?;
        // Chrome timestamps: microseconds since 1601-01-01
        let chrome_since = (since_ts + 11_644_473_600) * 1_000_000;
        let mut stmt = conn.prepare(
            "SELECT url FROM urls \
             WHERE last_visit_time > ?1 \
             ORDER BY last_visit_time DESC LIMIT ?2",
        )?;
        stmt.query_map([chrome_since, limit as i64], |r| r.get(0))?
            .collect()
    })();
    let _ = fs::remove_file(&tmp);
    result.unwrap_or_default()
}

fn read_firefox(db: &PathBuf, since_ts: i64, limit: usize) -> Vec<String> {
    let tmp = std::env::temp_dir()
        .join(format!("sr_ff_{}.db", std::process::id()));
    if fs::copy(db, &tmp).is_err() {
        return vec![];
    }
    let result = (|| -> rusqlite::Result<Vec<String>> {
        let conn = Connection::open(&tmp)?;
        // Firefox timestamps: microseconds since Unix epoch
        let ff_since = since_ts * 1_000_000;
        let mut stmt = conn.prepare(
            "SELECT DISTINCT p.url \
             FROM moz_places p \
             JOIN moz_historyvisits v ON p.id = v.place_id \
             WHERE v.visit_date > ?1 \
             ORDER BY v.visit_date DESC LIMIT ?2",
        )?;
        stmt.query_map([ff_since, limit as i64], |r| r.get(0))?
            .collect()
    })();
    let _ = fs::remove_file(&tmp);
    result.unwrap_or_default()
}

/// Import recent browser history as EventRecord objects.
pub fn import_browser_history(
    since_ts: i64,
    do_redact: bool,
    limit: usize,
) -> Vec<EventRecord> {
    let ts = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    let mut events = Vec::new();

    for browser in &["chrome", "chromium", "edge", "brave"] {
        for db in chromium_candidates(browser) {
            if db.exists() {
                for url in read_chromium(&db, since_ts, limit) {
                    let url = if do_redact { redact_url(&url) } else { url };
                    let mut ev =
                        EventRecord::new("browser_url", browser, &url);
                    ev.app = browser.to_string();
                    ev.ts = ts.clone();
                    events.push(ev);
                }
                break;
            }
        }
    }

    for db in firefox_candidates() {
        for url in read_firefox(&db, since_ts, limit) {
            let url = if do_redact { redact_url(&url) } else { url };
            let mut ev = EventRecord::new("browser_url", "firefox", &url);
            ev.app = "firefox".to_string();
            ev.ts = ts.clone();
            events.push(ev);
        }
    }

    events
}
