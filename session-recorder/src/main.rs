// main.rs – Session Recorder CLI entry point.

mod browser;
mod config;
mod daemon;
mod event;
mod notes;
mod platform;

use crate::config::Config;
use crate::daemon::{is_running, pause_file, read_pid, remove_pid, RecorderDaemon};
use crate::event::EventStore;
use chrono::Local;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Privacy-first background session recorder for CTF sessions.
#[derive(Parser)]
#[command(name = "session-recorder", version)]
struct Cli {
    /// Path to config JSON file
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start recording the current session
    Start {
        /// Fork into the background (Unix only; on Windows use Task Scheduler or run in a new window)
        #[arg(long)]
        daemon: bool,
        /// Window poll interval in seconds
        #[arg(long)]
        poll_interval: Option<u64>,
        /// Directory to store session JSONL files
        #[arg(long)]
        session_dir: Option<String>,
    },
    /// Stop the running recorder daemon
    Stop,
    /// Show current recorder status
    Status,
    /// Pause an active recording
    Pause,
    /// Resume a paused recording
    Resume,
    /// Export a recorded session to a Markdown note
    Export {
        /// Date to export (YYYY-MM-DD; default: today)
        #[arg(long)]
        date: Option<String>,
        /// Override detected tool name
        #[arg(long)]
        tool: Option<String>,
        /// Print the note without writing it
        #[arg(long)]
        preview: bool,
        /// Append to an existing note instead of overwriting
        #[arg(long)]
        append: bool,
        /// Disable automatic redaction of sensitive values
        #[arg(long)]
        no_redact: bool,
        /// Include browser URLs in the note
        #[arg(long)]
        include_urls: bool,
        /// Directory containing session JSONL files
        #[arg(long)]
        session_dir: Option<String>,
        /// Root directory for notes
        #[arg(long, default_value = "notes")]
        output_dir: String,
        /// Import fresh browser history before generating the note
        #[arg(long)]
        browser_history: bool,
        /// Seconds of browser history to import
        #[arg(long, default_value = "86400")]
        history_since: i64,
    },
    /// Print the active configuration
    Config,
}

fn load_config(override_path: Option<&PathBuf>) -> Config {
    if let Some(p) = override_path {
        if p.exists() {
            if let Ok(text) = fs::read_to_string(p) {
                if let Ok(cfg) = serde_json::from_str(&text) {
                    return cfg;
                }
            }
        }
    }
    Config::load()
}

fn main() {
    let cli = Cli::parse();
    let mut cfg = load_config(cli.config.as_ref());

    match cli.command {
        Commands::Start { daemon, poll_interval, session_dir } => {
            if let Some(pid) = read_pid() {
                if is_running(pid) {
                    eprintln!(
                        "[session-recorder] Already running (PID {pid}). \
                         Use 'session-recorder stop' first."
                    );
                    std::process::exit(1);
                }
            }

            if let Some(n) = poll_interval {
                cfg.poll_interval = n;
            }
            if let Some(d) = session_dir {
                cfg.session_dir = d;
            }

            if daemon {
                spawn_daemon();
                return;
            }

            let store = EventStore::new(cfg.session_dir_path());
            let running = Arc::new(AtomicBool::new(true));
            let flag = running.clone();
            ctrlc::set_handler(move || flag.store(false, Ordering::Relaxed))
                .expect("failed to set Ctrl-C handler");
            RecorderDaemon::new(cfg, store, running).run();
        }

        Commands::Stop => {
            let Some(pid) = read_pid() else {
                eprintln!("[session-recorder] Not running (no PID file found).");
                return;
            };
            if !is_running(pid) {
                eprintln!("[session-recorder] Stale PID file (process {pid} not found).");
                remove_pid();
                return;
            }
            terminate_process(pid);
        }

        Commands::Status => match read_pid() {
            None => println!("Status: stopped (no PID file)"),
            Some(pid) => {
                if is_running(pid) {
                    let paused = pause_file().exists();
                    println!(
                        "Status: {} (PID {pid})",
                        if paused { "paused" } else { "running" }
                    );
                } else {
                    println!("Status: stopped (stale PID {pid})");
                    remove_pid();
                }
            }
        },

        Commands::Pause => {
            let pf = pause_file();
            if let Some(parent) = pf.parent() {
                let _ = fs::create_dir_all(parent);
            }
            match fs::write(&pf, b"") {
                Ok(_) => println!("[session-recorder] Paused."),
                Err(e) => eprintln!("[session-recorder] Could not create pause file: {e}"),
            }
        }

        Commands::Resume => {
            let pf = pause_file();
            if pf.exists() {
                match fs::remove_file(&pf) {
                    Ok(_) => println!("[session-recorder] Resumed."),
                    Err(e) => {
                        eprintln!("[session-recorder] Could not remove pause file: {e}")
                    }
                }
            } else {
                println!("[session-recorder] Recorder is not paused.");
            }
        }

        Commands::Export {
            date,
            tool,
            preview,
            append,
            no_redact,
            include_urls,
            session_dir,
            output_dir,
            browser_history,
            history_since,
        } => {
            let do_redact = !no_redact;
            let session_path =
                session_dir.map(PathBuf::from).unwrap_or_else(|| cfg.session_dir_path());
            let date_str =
                date.unwrap_or_else(|| Local::now().format("%Y-%m-%d").to_string());

            let store = EventStore::new(session_path);
            let mut events = match store.read(&date_str) {
                Ok(evs) => evs,
                Err(e) => {
                    eprintln!("[session-recorder] Failed to read session: {e}");
                    std::process::exit(1);
                }
            };

            if browser_history || cfg.browser_history_on_export {
                let since = chrono::Utc::now().timestamp() - history_since;
                events.extend(browser::import_browser_history(since, do_redact, 200));
            }

            let text = notes::events_to_text(&events, include_urls);
            let lines: Vec<String> = text.lines().map(str::to_string).collect();
            let normalised = notes::normalize_lines(&lines);
            let detected = tool
                .or_else(|| notes::detect_tool(&text).map(str::to_string))
                .unwrap_or_else(|| "session".to_string());
            let slug = notes::tool_slug(&detected);
            let buckets = notes::classify_lines(&normalised, do_redact);
            let note = notes::build_note(&slug, &date_str, &buckets);

            if preview {
                print!("{note}");
                return;
            }

            let year = &date_str[..4];
            let dir = PathBuf::from(&output_dir).join(&slug).join(year);
            let _ = fs::create_dir_all(&dir);
            let note_path = dir.join(format!("{date_str}.md"));

            let content = if append && note_path.exists() {
                let mut existing = fs::read_to_string(&note_path).unwrap_or_default();
                existing.push('\n');
                existing.push_str(&note);
                existing
            } else {
                note
            };

            match fs::write(&note_path, content) {
                Ok(_) => {
                    println!("[session-recorder] Note written to {}", note_path.display())
                }
                Err(e) => {
                    eprintln!("[session-recorder] Failed to write note: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Config => {
            println!("Config file: {}", Config::config_path().display());
            match serde_json::to_string_pretty(&cfg) {
                Ok(json) => println!("{json}"),
                Err(e) => eprintln!("Failed to serialize config: {e}"),
            }
        }
    }
}

/// Re-spawn the current executable detached from the terminal (background mode).
///
/// On Unix the child's stdio streams are redirected to /dev/null so it is
/// effectively detached. On Windows the DETACHED_PROCESS flag achieves the
/// same result.
fn spawn_daemon() {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[session-recorder] Cannot find own executable: {e}");
            std::process::exit(1);
        }
    };
    // Strip --daemon / -daemon from the forwarded args so the child does not
    // loop and fork itself again.
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| a != "--daemon" && a != "-daemon")
        .collect();

    #[cfg(unix)]
    {
        use std::process::{Command, Stdio};
        match Command::new(&exe)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => println!(
                "[session-recorder] Recorder started in background (PID {}).",
                child.id()
            ),
            Err(e) => eprintln!("[session-recorder] Failed to spawn daemon: {e}"),
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use std::process::Command;
        // DETACHED_PROCESS (0x8) frees the new process from the calling
        // console. CREATE_NEW_PROCESS_GROUP (0x200) prevents Ctrl-C
        // propagation from the parent.
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        match Command::new(&exe)
            .args(&args)
            .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
            .spawn()
        {
            Ok(child) => println!(
                "[session-recorder] Recorder started in background (PID {}).",
                child.id()
            ),
            Err(e) => eprintln!("[session-recorder] Failed to spawn daemon: {e}"),
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        eprintln!(
            "[session-recorder] Background mode is not supported on this platform. \
             Run without --daemon."
        );
    }
}

/// Send a termination signal to the given PID.
fn terminate_process(pid: u32) {
    #[cfg(unix)]
    {
        use std::process::Command;
        match Command::new("kill").arg(pid.to_string()).status() {
            Ok(s) if s.success() => println!("[session-recorder] Sent SIGTERM to PID {pid}."),
            _ => eprintln!("[session-recorder] Failed to send SIGTERM to PID {pid}."),
        }
    }

    #[cfg(windows)]
    {
        use std::process::Command;
        match Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .status()
        {
            Ok(s) if s.success() => println!("[session-recorder] Terminated PID {pid}."),
            _ => eprintln!("[session-recorder] Failed to terminate PID {pid}."),
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        eprintln!(
            "[session-recorder] Process termination not supported on this platform."
        );
    }
}
