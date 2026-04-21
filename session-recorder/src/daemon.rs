// daemon.rs – Recording loop and PID / pause-file management.

use crate::config::Config;
use crate::event::{EventRecord, EventStore};
use crate::notes;
use crate::platform::{get_active_window, get_clipboard};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// ── File paths ─────────────────────────────────────────────────────────────

fn sr_root() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("session-logger")
}

pub fn pid_file() -> PathBuf {
    sr_root().join("recorder.pid")
}

pub fn pause_file() -> PathBuf {
    sr_root().join("recorder.paused")
}

// ── PID helpers ────────────────────────────────────────────────────────────

pub fn write_pid() {
    let p = pid_file();
    if let Some(parent) = p.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&p, std::process::id().to_string());
}

pub fn remove_pid() {
    let _ = fs::remove_file(pid_file());
}

pub fn read_pid() -> Option<u32> {
    fs::read_to_string(pid_file())
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

pub fn is_running(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    return PathBuf::from(format!("/proc/{pid}")).exists();

    #[cfg(target_os = "macos")]
    return std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    #[cfg(target_os = "windows")]
    {
        let out = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output();
        return matches!(out, Ok(o) if
            String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()));
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    false
}

// ── Daemon ─────────────────────────────────────────────────────────────────

pub struct RecorderDaemon {
    config: Config,
    store: EventStore,
    running: Arc<AtomicBool>,
}

impl RecorderDaemon {
    pub fn new(config: Config, store: EventStore, running: Arc<AtomicBool>) -> Self {
        Self { config, store, running }
    }

    pub fn run(self) {
        write_pid();
        self.emit("system", "recorder", "Recording started");
        eprintln!(
            "[session-recorder] Recording started (PID {})",
            std::process::id()
        );
        eprintln!("[session-recorder] Press Ctrl-C or run 'stop' to end the session.");

        let mut last_window = String::new();
        let mut last_clip = String::new();
        let mut last_clip_check = Instant::now();
        let poll = Duration::from_secs(self.config.poll_interval);
        let clip_poll = Duration::from_secs(self.config.clipboard_poll_interval);

        while self.running.load(Ordering::Relaxed) {
            if !pause_file().exists() {
                // Window tracking
                let (title, app) = get_active_window();
                if !title.is_empty() || !app.is_empty() {
                    if !self.config.is_excluded_app(&app) {
                        let label = if title.is_empty() {
                            app.clone()
                        } else {
                            title.clone()
                        };
                        if !self.config.is_excluded_window(&label) && label != last_window {
                            last_window = label.clone();
                            let ev = EventRecord::new("window", "window_tracker", &label)
                                .with_app(&app);
                            let _ = self.store.write(&ev);
                        }
                    }
                }

                // Clipboard tracking
                if last_clip_check.elapsed() >= clip_poll {
                    let raw = get_clipboard();
                    if !raw.is_empty() && raw != last_clip {
                        let text = if raw.len() > self.config.max_clipboard_length {
                            format!("{} [TRUNCATED]", &raw[..self.config.max_clipboard_length])
                        } else {
                            raw.clone()
                        };
                        let text = if self.config.redact {
                            notes::redact_text(&text)
                        } else {
                            text
                        };
                        last_clip = raw;
                        let ev = EventRecord::new("clipboard", "clipboard_tracker", &text);
                        let _ = self.store.write(&ev);
                    }
                    last_clip_check = Instant::now();
                }
            }

            thread::sleep(poll);
        }

        self.emit("system", "recorder", "Recording stopped");
        remove_pid();
        eprintln!("[session-recorder] Recording stopped.");
    }

    fn emit(&self, event_type: &str, source: &str, data: &str) {
        let ev = EventRecord::new(event_type, source, data);
        let _ = self.store.write(&ev);
    }
}
