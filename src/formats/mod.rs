//! Format registry: importers/exporters for each supported password manager
//! export format, plus auto-detection.

pub mod apple_csv;
pub mod bitwarden_csv;
pub mod bitwarden_json;
pub mod canonical_json;
pub mod chrome_csv;
pub mod dashlane_csv;
pub mod firefox_csv;
pub mod keepassxc_csv;
pub mod keeper_csv;
pub mod lastpass_csv;
pub mod nordpass_csv;
pub mod onepassword_csv;
pub mod protonpass_csv;
pub mod protonpass_json;

use crate::model::Vault;
use crate::report::Report;
use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    BitwardenCsv,
    BitwardenJson,
    OnePasswordCsv,
    ProtonPassJson,
    ProtonPassCsv,
    LastPassCsv,
    ChromeCsv,
    FirefoxCsv,
    AppleCsv,
    KeePassXcCsv,
    DashlaneCsv,
    NordPassCsv,
    KeeperCsv,
    CanonicalJson,
}

pub const ALL_FORMATS: &[Format] = &[
    Format::BitwardenCsv,
    Format::BitwardenJson,
    Format::OnePasswordCsv,
    Format::ProtonPassJson,
    Format::ProtonPassCsv,
    Format::LastPassCsv,
    Format::ChromeCsv,
    Format::FirefoxCsv,
    Format::AppleCsv,
    Format::KeePassXcCsv,
    Format::DashlaneCsv,
    Format::NordPassCsv,
    Format::KeeperCsv,
    Format::CanonicalJson,
];

impl Format {
    pub fn id(&self) -> &'static str {
        match self {
            Format::BitwardenCsv => "bitwarden-csv",
            Format::BitwardenJson => "bitwarden-json",
            Format::OnePasswordCsv => "1password-csv",
            Format::ProtonPassJson => "protonpass-json",
            Format::ProtonPassCsv => "protonpass-csv",
            Format::LastPassCsv => "lastpass-csv",
            Format::ChromeCsv => "chrome-csv",
            Format::FirefoxCsv => "firefox-csv",
            Format::AppleCsv => "apple-csv",
            Format::KeePassXcCsv => "keepassxc-csv",
            Format::DashlaneCsv => "dashlane-csv",
            Format::NordPassCsv => "nordpass-csv",
            Format::KeeperCsv => "keeper-csv",
            Format::CanonicalJson => "pwmigrate-json",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Format::BitwardenCsv => "Bitwarden CSV export (logins and secure notes)",
            Format::BitwardenJson => "Bitwarden unencrypted JSON export (all item types, passkeys)",
            Format::OnePasswordCsv => "1Password 8 CSV export/import",
            Format::ProtonPassJson => "Proton Pass JSON export (data.json from the export zip; passkeys)",
            Format::ProtonPassCsv => "Proton Pass CSV export",
            Format::LastPassCsv => "LastPass CSV export",
            Format::ChromeCsv => "Chrome / Edge / Brave / Opera passwords CSV",
            Format::FirefoxCsv => "Firefox passwords CSV",
            Format::AppleCsv => "Apple Passwords / Safari / iCloud Keychain CSV",
            Format::KeePassXcCsv => "KeePassXC CSV export",
            Format::DashlaneCsv => "Dashlane credentials CSV export",
            Format::NordPassCsv => "NordPass CSV export",
            Format::KeeperCsv => "Keeper CSV export (no header row, custom field pairs)",
            Format::CanonicalJson => "pwmigrate canonical JSON (lossless intermediate format)",
        }
    }

    pub fn from_id(id: &str) -> Option<Format> {
        let id = id.to_lowercase();
        let id = id.as_str();
        // Convenience aliases first.
        let alias = match id {
            "bitwarden" => Some(Format::BitwardenJson),
            "1password" | "onepassword" | "onepassword-csv" => Some(Format::OnePasswordCsv),
            "protonpass" | "proton" | "proton-pass" => Some(Format::ProtonPassJson),
            "lastpass" => Some(Format::LastPassCsv),
            "chrome" | "edge-csv" | "edge" | "brave" | "brave-csv" | "opera" | "opera-csv"
            | "google" => Some(Format::ChromeCsv),
            "firefox" => Some(Format::FirefoxCsv),
            "apple" | "safari" | "safari-csv" | "icloud" | "icloud-csv" => Some(Format::AppleCsv),
            "keepass" | "keepassxc" | "keepass-csv" => Some(Format::KeePassXcCsv),
            "dashlane" => Some(Format::DashlaneCsv),
            "nordpass" => Some(Format::NordPassCsv),
            "keeper" => Some(Format::KeeperCsv),
            "canonical" | "pwmigrate" | "canonical-json" => Some(Format::CanonicalJson),
            _ => None,
        };
        alias.or_else(|| ALL_FORMATS.iter().copied().find(|f| f.id() == id))
    }

    pub fn import(&self, data: &str, report: &mut Report) -> Result<Vault> {
        match self {
            Format::BitwardenCsv => bitwarden_csv::import(data, report),
            Format::BitwardenJson => bitwarden_json::import(data, report),
            Format::OnePasswordCsv => onepassword_csv::import(data, report),
            Format::ProtonPassJson => protonpass_json::import(data, report),
            Format::ProtonPassCsv => protonpass_csv::import(data, report),
            Format::LastPassCsv => lastpass_csv::import(data, report),
            Format::ChromeCsv => chrome_csv::import(data, report),
            Format::FirefoxCsv => firefox_csv::import(data, report),
            Format::AppleCsv => apple_csv::import(data, report),
            Format::KeePassXcCsv => keepassxc_csv::import(data, report),
            Format::DashlaneCsv => dashlane_csv::import(data, report),
            Format::NordPassCsv => nordpass_csv::import(data, report),
            Format::KeeperCsv => keeper_csv::import(data, report),
            Format::CanonicalJson => canonical_json::import(data, report),
        }
    }

    pub fn export(&self, vault: &Vault, report: &mut Report) -> Result<String> {
        match self {
            Format::BitwardenCsv => bitwarden_csv::export(vault, report),
            Format::BitwardenJson => bitwarden_json::export(vault, report),
            Format::OnePasswordCsv => onepassword_csv::export(vault, report),
            Format::ProtonPassJson => protonpass_json::export(vault, report),
            Format::ProtonPassCsv => protonpass_csv::export(vault, report),
            Format::LastPassCsv => lastpass_csv::export(vault, report),
            Format::ChromeCsv => chrome_csv::export(vault, report),
            Format::FirefoxCsv => firefox_csv::export(vault, report),
            Format::AppleCsv => apple_csv::export(vault, report),
            Format::KeePassXcCsv => keepassxc_csv::export(vault, report),
            Format::DashlaneCsv => dashlane_csv::export(vault, report),
            Format::NordPassCsv => nordpass_csv::export(vault, report),
            Format::KeeperCsv => keeper_csv::export(vault, report),
            Format::CanonicalJson => canonical_json::export(vault, report),
        }
    }
}

/// Try to detect the format from file content (and file name as a hint).
pub fn detect(data: &str, file_name: &str) -> Result<Format> {
    let trimmed = data.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with('{') {
        let value: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| anyhow::anyhow!("file looks like JSON but does not parse: {e}"))?;
        if value.get("vaults").is_some() {
            return Ok(Format::ProtonPassJson);
        }
        if value.get("pwmigrate").is_some() {
            return Ok(Format::CanonicalJson);
        }
        if value.get("items").is_some() {
            if value.get("encrypted").is_some() || value.get("folders").is_some() {
                return Ok(Format::BitwardenJson);
            }
            return Ok(Format::CanonicalJson);
        }
        bail!("unrecognized JSON structure; specify the format explicitly with --from");
    }

    // CSV: match the header row against known header sets.
    let header_line = trimmed.lines().next().unwrap_or("");
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(header_line.as_bytes());
    let mut headers: Vec<String> = Vec::new();
    if let Some(Ok(record)) = rdr.records().next() {
        headers = record.iter().map(|h| h.trim().to_lowercase()).collect();
    }
    let has = |name: &str| headers.iter().any(|h| h == name);

    if has("login_uri") && has("login_username") {
        return Ok(Format::BitwardenCsv);
    }
    if has("otpauth") && has("title") {
        // 1Password and Apple share Title/OTPAuth; 1Password has Tags/Archived.
        if has("tags") || has("archived") || has("favorite") {
            return Ok(Format::OnePasswordCsv);
        }
        return Ok(Format::AppleCsv);
    }
    if has("createtime") && has("vault") {
        return Ok(Format::ProtonPassCsv);
    }
    if has("grouping") && has("extra") {
        return Ok(Format::LastPassCsv);
    }
    if has("formactionorigin") || has("httprealm") {
        return Ok(Format::FirefoxCsv);
    }
    if has("group") && has("title") && has("username") {
        return Ok(Format::KeePassXcCsv);
    }
    if has("otpsecret") || (has("username2") && has("username3")) {
        return Ok(Format::DashlaneCsv);
    }
    if has("cardholdername") || has("expirydate") {
        return Ok(Format::NordPassCsv);
    }
    if has("name") && has("url") && has("username") && has("password") {
        return Ok(Format::ChromeCsv);
    }
    if has("title") && has("url") && has("username") && has("password") {
        return Ok(Format::AppleCsv);
    }

    if file_name.to_lowercase().ends_with(".csv") {
        bail!(
            "could not detect the CSV dialect from the header row ({:?}); \
             specify the format explicitly with --from (note: Keeper CSV has no header row \
             and always needs --from keeper-csv)",
            headers
        );
    }
    bail!("could not detect the file format; specify it explicitly with --from");
}

// ---- shared helpers for the format modules ----

/// Empty-trimmed string to Option.
pub(crate) fn opt(s: impl Into<String>) -> Option<String> {
    let s = s.into();
    if s.trim().is_empty() {
        None
    } else {
        Some(s)
    }
}

pub(crate) fn parse_bool(s: &str) -> bool {
    matches!(s.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "y")
}

/// Derive a display title from a URL when the source format has none.
pub(crate) fn title_from_url(url: &str) -> String {
    let stripped = url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("www.");
    let host = stripped.split(['/', ':', '?']).next().unwrap_or(stripped);
    if host.is_empty() {
        "Untitled".to_string()
    } else {
        host.to_string()
    }
}

/// Parsed CSV with by-name column access and capture of unknown columns.
pub(crate) struct CsvTable {
    pub headers: csv::StringRecord,
    lower: Vec<String>,
    pub records: Vec<csv::StringRecord>,
}

impl CsvTable {
    pub fn parse(data: &str) -> Result<Self> {
        let data = data.trim_start_matches('\u{feff}');
        let mut rdr = csv::ReaderBuilder::new()
            .flexible(true)
            .from_reader(data.as_bytes());
        let headers = rdr.headers()?.clone();
        let lower = headers.iter().map(|h| h.trim().to_lowercase()).collect();
        let mut records = Vec::new();
        for rec in rdr.records() {
            records.push(rec?);
        }
        Ok(CsvTable {
            headers,
            lower,
            records,
        })
    }

    /// Value of column `name` (case-insensitive) in `rec`, or "".
    pub fn get<'a>(&self, rec: &'a csv::StringRecord, name: &str) -> &'a str {
        self.lower
            .iter()
            .position(|h| h == name)
            .and_then(|i| rec.get(i))
            .unwrap_or("")
            .trim()
    }

    /// Non-empty values of columns that are not in `known`, as custom fields.
    pub fn unknown_columns(
        &self,
        rec: &csv::StringRecord,
        known: &[&str],
    ) -> Vec<crate::model::CustomField> {
        let mut out = Vec::new();
        for (i, h) in self.lower.iter().enumerate() {
            if h.is_empty() || known.contains(&h.as_str()) {
                continue;
            }
            if let Some(v) = rec.get(i) {
                if !v.trim().is_empty() {
                    out.push(crate::model::CustomField::new(
                        self.headers.get(i).unwrap_or(h).trim(),
                        v.trim(),
                    ));
                }
            }
        }
        out
    }
}

/// Verify a CSV header row contains the required columns; report unknown ones.
pub(crate) fn check_headers(
    headers: &csv::StringRecord,
    required: &[&str],
    known: &[&str],
    format_name: &str,
    report: &mut Report,
) -> Result<()> {
    let lower: Vec<String> = headers.iter().map(|h| h.trim().to_lowercase()).collect();
    for req in required {
        if !lower.iter().any(|h| h == req) {
            bail!(
                "{format_name}: required column '{req}' is missing from the header row \
                 (found: {lower:?})"
            );
        }
    }
    for h in &lower {
        if !h.is_empty() && !known.contains(&h.as_str()) {
            report.warn(
                None,
                format!("{format_name}: unrecognized column '{h}' — its values will be kept as a custom field where possible"),
            );
        }
    }
    Ok(())
}
