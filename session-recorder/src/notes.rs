// notes.rs – Note generation pipeline (reimplements dump2note.py in Rust).
//
// Tool detection, redaction, line normalisation/classification, and Markdown
// rendering are all handled here so the binary is fully self-contained.

use crate::event::EventRecord;
use regex::{Regex, RegexSet};
use std::collections::HashSet;
use std::sync::OnceLock;

// ── Static compiled regex sets ─────────────────────────────────────────────

static CMD_SET: OnceLock<RegexSet> = OnceLock::new();
static FINDING_SET: OnceLock<RegexSet> = OnceLock::new();
static FOLLOWUP_SET: OnceLock<RegexSet> = OnceLock::new();
static REDACT_VEC: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();

fn cmd_set() -> &'static RegexSet {
    CMD_SET.get_or_init(|| {
        RegexSet::new([
            r"(?i)^\s*[$#%>]\s+\S",
            r"(?i)^\s*(sudo|su|cd|ls|cat|echo|export|source|chmod|chown|mv|cp|rm|mkdir|touch|wget|curl|python3?|perl|ruby|php|bash|sh|zsh|pwsh|powershell)\b",
            r"(?i)^\s*(nmap|sqlmap|gobuster|hydra|nikto|ffuf|wfuzz|dirb|dirsearch|john|hashcat|crackmapexec|smbclient|enum4linux|bloodhound|mimikatz|feroxbuster|wpscan|aircrack-ng|airodump-ng|tshark|wireshark|msfconsole|msfvenom)\b",
            r"(?i)^\s*(use |set |run$|exploit$|back$|sessions)",
            r"(?i)^\s*>?\s*nc\s+-",
        ]).unwrap()
    })
}

fn finding_set() -> &'static RegexSet {
    FINDING_SET.get_or_init(|| {
        RegexSet::new([
            r"\b\d+/tcp\s+(open|closed|filtered)\b",
            r"(?i)\b(vulnerable|vuln|CVE-\d{4}-\d+)\b",
            r"(?i)\b(found|discovered|detected|identified)\b",
            r"\[\s*[+*!]\s*\]",
            r"(?i)\b200\s+OK\b|HTTP/\d\.\d\s+\d{3}",
            r"(?i)\b(username|password|hash|credential).*:",
            r"(?i)\b(admin|root)\b.*\b(found|valid|correct|success)\b",
            r"(?i)(shell|meterpreter|session)\s*(gained|opened|\d+)",
            r"(?i)\bsql injection\b|\bxss\b|\blfi\b|\brfi\b|\bssrf\b|\brce\b",
        ]).unwrap()
    })
}

fn followup_set() -> &'static RegexSet {
    FOLLOWUP_SET.get_or_init(|| {
        RegexSet::new([
            r"(?i)\b(TODO|FIXME|NOTE|INVESTIGATE|CHECK|VERIFY|FOLLOW.?UP|TBD|REVISIT)\b",
            r"\?\s*$",
            r"(?i)\b(need to|should|must|worth trying|next step)\b",
        ]).unwrap()
    })
}

fn redact_vec() -> &'static Vec<(Regex, &'static str)> {
    REDACT_VEC.get_or_init(|| {
        vec![
            (Regex::new(r"(?i)(-p|--password|--pass)\s+\S+").unwrap(),
             "$1 [REDACTED]"),
            (Regex::new(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+").unwrap(),
             "$1=[REDACTED]"),
            (Regex::new(r"(?i)(Authorization:\s*(?:Basic|Bearer)\s+)\S+").unwrap(),
             "${1}[REDACTED]"),
            (Regex::new(r"(?i)(api[_\-]?key|apikey|token|secret|access[_\-]?key)\s*[=:]\s*\S+").unwrap(),
             "$1=[REDACTED]"),
            (Regex::new(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+").unwrap(),
             "[JWT_REDACTED]"),
            (Regex::new(r"(AKIA|ASIA)[A-Z0-9]{16}").unwrap(),
             "[AWS_KEY_REDACTED]"),
        ]
    })
}

// ── Tool signatures ────────────────────────────────────────────────────────

const TOOL_SIGNATURES: &[(&str, &str)] = &[
    (r"(?i)\bnmap\b|Nmap scan report|PORT\s+STATE\s+SERVICE|Starting Nmap", "nmap"),
    (r"(?i)\bmsfconsole\b|msf\s*[56]?\s*>|Metasploit|exploit\(|meterpreter\s*>", "metasploit"),
    (r"(?i)Burp Suite|\bburp\b", "burpsuite"),
    (r"(?i)\bsqlmap\b|testing for SQL injection", "sqlmap"),
    (r"(?i)\bgobuster\b|Dir Mode:", "gobuster"),
    (r"(?i)\bhydra\b|\[DATA\] attacking", "hydra"),
    (r"(?i)\bnikto\b|Nikto v\d", "nikto"),
    (r"(?i)\btshark\b|\bwireshark\b", "wireshark"),
    (r"(?i)\bjohn\b|John the Ripper", "john"),
    (r"(?i)\bhashcat\b", "hashcat"),
    (r"(?i)\bdirb\b|DIRB v\d", "dirb"),
    (r"(?i)\bffuf\b", "ffuf"),
    (r"(?i)\bwfuzz\b", "wfuzz"),
    (r"(?i)\bnetcat\b|\bnc\s+-[lnvup]", "netcat"),
    (r"(?i)\bdirsearch\b", "dirsearch"),
    (r"(?i)\benum4linux\b", "enum4linux"),
    (r"(?i)\bsmbclient\b", "smbclient"),
    (r"(?i)\bcrackmapexec\b|\bcme\b", "crackmapexec"),
    (r"(?i)\bbloodhound\b|\bSharpHound\b", "bloodhound"),
    (r"(?i)\bmimikatz\b", "mimikatz"),
    (r"(?i)\blinpeas\b|PEASS", "linpeas"),
    (r"(?i)\bwinpeas\b", "winpeas"),
    (r"(?i)\bwpscan\b", "wpscan"),
    (r"(?i)\baircrack-ng\b|\bairodump-ng\b", "aircrack-ng"),
    (r"(?i)\bferoxbuster\b", "feroxbuster"),
    (r"(?i)\bdig\b.*axfr|zone transfer", "dig"),
    (r"(?i)\bpython.*http\.server\b|\bSimpleHTTP\b", "python-http-server"),
    (r"(?i)\bcurl\b", "curl"),
];

// ── Public helpers ─────────────────────────────────────────────────────────

pub fn detect_tool(text: &str) -> Option<&'static str> {
    for (pat, name) in TOOL_SIGNATURES {
        if let Ok(re) = Regex::new(pat) {
            if re.is_match(text) {
                return Some(name);
            }
        }
    }
    None
}

pub fn redact_text(text: &str) -> String {
    let mut out = text.to_string();
    for (re, repl) in redact_vec() {
        out = re.replace_all(&out, *repl).to_string();
    }
    out
}

pub fn normalize_lines(lines: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for line in lines {
        let t = line.trim_end().to_string();
        if seen.insert(t.clone()) {
            deduped.push(t);
        }
    }
    let mut result = Vec::new();
    let mut prev_blank = false;
    for line in deduped {
        let blank = line.trim().is_empty();
        if blank && prev_blank {
            continue;
        }
        result.push(line);
        prev_blank = blank;
    }
    result
}

#[derive(Default)]
pub struct Buckets {
    pub commands: Vec<String>,
    pub findings: Vec<String>,
    pub followups: Vec<String>,
    pub raw: Vec<String>,
}

pub fn classify_lines(lines: &[String], do_redact: bool) -> Buckets {
    let mut b = Buckets::default();
    for line in lines {
        let stripped = line.trim();
        if stripped.is_empty() {
            continue;
        }
        let text = if do_redact { redact_text(stripped) } else { stripped.to_string() };
        if followup_set().is_match(&text) {
            b.followups.push(text);
        } else if cmd_set().is_match(&text) {
            b.commands.push(text);
        } else if finding_set().is_match(&text) {
            b.findings.push(text);
        } else {
            b.raw.push(text);
        }
    }
    b
}

fn fmt_list(items: &[String], fallback: &str) -> String {
    if items.is_empty() {
        format!("- {fallback}")
    } else {
        items.iter().map(|i| format!("- {i}")).collect::<Vec<_>>().join("\n")
    }
}

fn fmt_task_list(items: &[String], fallback: &str) -> String {
    if items.is_empty() {
        format!("- [ ] {fallback}")
    } else {
        items.iter().map(|i| format!("- [ ] {i}")).collect::<Vec<_>>().join("\n")
    }
}

fn build_summary(b: &Buckets) -> String {
    let mut parts = Vec::new();
    if !b.commands.is_empty() {
        parts.push(format!("{} command(s) captured.", b.commands.len()));
    }
    if !b.findings.is_empty() {
        parts.push(format!("{} finding(s) identified.", b.findings.len()));
    }
    if !b.followups.is_empty() {
        parts.push(format!("{} follow-up item(s) noted.", b.followups.len()));
    }
    if parts.is_empty() {
        "No structured content detected from session.".to_string()
    } else {
        parts.join(" ")
    }
}

pub fn build_note(tool: &str, date_str: &str, b: &Buckets) -> String {
    let summary = build_summary(b);
    let raw_section = if b.raw.is_empty() {
        String::new()
    } else {
        format!("\n\n## Raw Notes\n\n{}", fmt_list(&b.raw, "None captured."))
    };
    format!(
        "---\ntool: {tool}\ndate: {date_str}\ntags:\n  - cyber\n  - tool/{tool}\n---\n\n\
# {tool} Notes\n\n- Tool: {tool}\n- Date: {date_str}\n\n\
## Summary\n\n{summary}\n\n\
## Commands / Steps\n\n{}\n\n\
## Findings\n\n{}\n\n\
## Follow-ups\n\n{}{raw_section}\n",
        fmt_list(&b.commands, "None captured."),
        fmt_list(&b.findings, "None captured."),
        fmt_task_list(&b.followups, "None captured."),
    )
}

/// Converts captured EventRecords into a plain-text dump for the pipeline.
pub fn events_to_text(events: &[EventRecord], include_urls: bool) -> String {
    let mut lines = Vec::new();
    for ev in events {
        match ev.event_type.as_str() {
            "window" => lines.push(format!("# Window: {}", ev.data)),
            "clipboard" => {
                let text = ev.data.trim();
                if text.contains('\n') {
                    lines.push(format!("# Clipboard:\n{text}"));
                } else {
                    lines.push(text.to_string());
                }
            }
            "browser_url" if include_urls => {
                lines.push(format!("# URL: {}", ev.data));
            }
            "command" => lines.push(format!("$ {}", ev.data)),
            "system" => lines.push(format!("# [{}]", ev.data)),
            _ => {}
        }
    }
    lines.join("\n")
}

/// Sanitise a tool name into a safe path slug.
pub fn tool_slug(name: &str) -> String {
    let re = Regex::new(r"[^\w.\-]").unwrap();
    re.replace_all(name, "-")
        .to_lowercase()
        .trim_matches('-')
        .to_string()
}
