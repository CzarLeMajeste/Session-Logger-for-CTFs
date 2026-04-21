// config.rs – Recorder configuration (JSON file, sensible defaults).

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub poll_interval: u64,
    pub clipboard_poll_interval: u64,
    pub max_clipboard_length: usize,
    pub exclude_apps: Vec<String>,
    pub exclude_window_patterns: Vec<String>,
    pub browser_history_on_export: bool,
    pub redact: bool,
    pub session_dir: String,
}

impl Default for Config {
    fn default() -> Self {
        let session_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("~/.local/share"))
            .join("session-logger")
            .join("sessions")
            .to_string_lossy()
            .to_string();
        Self {
            poll_interval: 5,
            clipboard_poll_interval: 2,
            max_clipboard_length: 2000,
            exclude_apps: vec![
                "1password".into(), "keepass".into(), "keepassxc".into(),
                "bitwarden".into(), "lastpass".into(), "dashlane".into(),
                "enpass".into(), "gnome-keyring".into(), "kwallet".into(),
                "pass".into(),
            ],
            exclude_window_patterns: vec![
                r"\bpassword\b".into(), r"\bpasswd\b".into(), r"\bpin\b".into(),
                r"\bsecret\b".into(), r"\bpayment\b".into(),
                r"\bcredit.?card\b".into(), r"\bsocial.?security\b".into(),
                r"\bssn\b".into(),
            ],
            browser_history_on_export: true,
            redact: true,
            session_dir,
        }
    }
}

impl Config {
    pub fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("~/.config"))
            .join("session-logger")
            .join("config.json")
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        if path.exists() {
            if let Ok(text) = fs::read_to_string(&path) {
                if let Ok(cfg) = serde_json::from_str(&text) {
                    return cfg;
                }
            }
        }
        Self::default()
    }

    pub fn session_dir_path(&self) -> PathBuf {
        PathBuf::from(&self.session_dir)
    }

    pub fn is_excluded_app(&self, app: &str) -> bool {
        let lower = app.to_lowercase();
        self.exclude_apps.iter().any(|p| lower.contains(p.as_str()))
    }

    pub fn is_excluded_window(&self, title: &str) -> bool {
        for pat in &self.exclude_window_patterns {
            if let Ok(re) = regex::RegexBuilder::new(pat)
                .case_insensitive(true)
                .build()
            {
                if re.is_match(title) {
                    return true;
                }
            }
        }
        false
    }
}
