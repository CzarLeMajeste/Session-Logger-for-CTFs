// event.rs – EventRecord data type and JSONL-backed EventStore.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Mutex;

/// A single captured desktop event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub ts: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub source: String,
    pub data: String,
    #[serde(default)]
    pub app: String,
    #[serde(default)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl EventRecord {
    pub fn new(event_type: &str, source: &str, data: &str) -> Self {
        Self {
            ts: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            event_type: event_type.to_string(),
            source: source.to_string(),
            data: data.to_string(),
            app: String::new(),
            extra: HashMap::new(),
        }
    }

    pub fn with_app(mut self, app: &str) -> Self {
        self.app = app.to_string();
        self
    }

    /// Returns the YYYY-MM-DD date portion of the timestamp.
    pub fn date_str(&self) -> &str {
        &self.ts[..10]
    }
}

/// Appends EventRecord objects to a per-day JSONL file.
pub struct EventStore {
    dir: PathBuf,
    mutex: Mutex<()>,
}

impl EventStore {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            mutex: Mutex::new(()),
        }
    }

    fn path_for(&self, date_str: &str) -> PathBuf {
        let year = &date_str[..4];
        let p = self.dir.join(year).join(format!("{date_str}.jsonl"));
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
        p
    }

    pub fn write(&self, event: &EventRecord) -> io::Result<()> {
        let _guard = self.mutex.lock().unwrap();
        let path = self.path_for(event.date_str());
        let line = serde_json::to_string(event)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(file, "{line}")
    }

    pub fn read(&self, date_str: &str) -> io::Result<Vec<EventRecord>> {
        let path = self.path_for(date_str);
        if !path.exists() {
            return Ok(vec![]);
        }
        let file = fs::File::open(path)?;
        let reader = io::BufReader::new(file);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(ev) = serde_json::from_str::<EventRecord>(line) {
                events.push(ev);
            }
        }
        Ok(events)
    }

    /// Lists all dates for which a JSONL log exists.
    pub fn available_dates(&self) -> Vec<String> {
        let mut dates = Vec::new();
        if let Ok(year_dirs) = fs::read_dir(&self.dir) {
            for year_entry in year_dirs.flatten() {
                if let Ok(day_files) = fs::read_dir(year_entry.path()) {
                    for entry in day_files.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                                dates.push(stem.to_string());
                            }
                        }
                    }
                }
            }
        }
        dates.sort();
        dates
    }
}
