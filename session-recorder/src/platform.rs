// platform.rs – Active-window title and clipboard via subprocess (all platforms).

use std::process::Command;

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ── Active window ──────────────────────────────────────────────────────────

/// Returns `(window_title, app_name)` for the currently focused window.
pub fn get_active_window() -> (String, String) {
    #[cfg(target_os = "linux")]
    return get_active_window_linux();
    #[cfg(target_os = "macos")]
    return get_active_window_macos();
    #[cfg(target_os = "windows")]
    return get_active_window_windows();
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    (String::new(), String::new())
}

#[cfg(target_os = "linux")]
fn get_active_window_linux() -> (String, String) {
    let win_id = match run("xdotool", &["getwindowfocus"]) {
        Some(id) => id,
        None => return (String::new(), String::new()),
    };
    let title = run("xdotool", &["getwindowname", &win_id]).unwrap_or_default();
    let raw_class = run("xprop", &["-id", &win_id, "WM_CLASS"]).unwrap_or_default();
    let app = raw_class
        .split('"')
        .filter(|s| !s.trim_matches(&[' ', '='] as &[char]).is_empty()
            && !s.contains("WM_CLASS"))
        .last()
        .unwrap_or("")
        .to_lowercase();
    (title, app)
}

#[cfg(target_os = "macos")]
fn get_active_window_macos() -> (String, String) {
    let script = concat!(
        r#"tell application "System Events" to get "#,
        r#"{name of first process whose frontmost is true, "#,
        r#"name of front window of first application process whose frontmost is true}"#,
    );
    let raw = run("osascript", &["-e", script]).unwrap_or_default();
    if raw.is_empty() {
        let app_script = concat!(
            r#"tell application "System Events" to "#,
            r#"get name of first process whose frontmost is true"#,
        );
        let app = run("osascript", &["-e", app_script])
            .unwrap_or_default()
            .to_lowercase();
        return (String::new(), app);
    }
    let mut parts = raw.splitn(2, ',').map(str::trim);
    let app = parts.next().unwrap_or("").to_lowercase();
    let title = parts.next().unwrap_or("").to_string();
    (title, app)
}

#[cfg(target_os = "windows")]
fn get_active_window_windows() -> (String, String) {
    // Use PowerShell to get foreground window title and process name.
    let script = r#"
Add-Type @'
using System; using System.Runtime.InteropServices; using System.Text;
using System.Diagnostics;
public class WinHelper {
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
}
'@
$h = [WinHelper]::GetForegroundWindow()
$sb = New-Object System.Text.StringBuilder 512
[WinHelper]::GetWindowText($h, $sb, 512) | Out-Null
$pid = 0u
[WinHelper]::GetWindowThreadProcessId($h, [ref]$pid) | Out-Null
$proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
$app = if ($proc) { $proc.ProcessName.ToLower() } else { "" }
Write-Output "$app`n$($sb.ToString())"
"#;
    let out = run("powershell", &["-NoProfile", "-Command", script]).unwrap_or_default();
    let mut lines = out.lines();
    let app = lines.next().unwrap_or("").to_string();
    let title = lines.next().unwrap_or("").to_string();
    (title, app)
}

// ── Clipboard ─────────────────────────────────────────────────────────────

/// Returns the current clipboard text.
pub fn get_clipboard() -> String {
    #[cfg(target_os = "linux")]
    return run("xclip", &["-selection", "clipboard", "-o"])
        .or_else(|| run("xsel", &["--clipboard", "--output"]))
        .unwrap_or_default();
    #[cfg(target_os = "macos")]
    return run("pbpaste", &[]).unwrap_or_default();
    #[cfg(target_os = "windows")]
    return run("powershell", &["-NoProfile", "-Command", "Get-Clipboard"])
        .unwrap_or_default();
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    String::new()
}
