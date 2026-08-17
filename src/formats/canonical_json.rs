//! pwmigrate canonical JSON — a lossless dump of the internal model.
//!
//! Use this as an intermediate or archival format: every field pwmigrate
//! understands (including passkeys with provider blobs) survives a
//! round-trip. `{"pwmigrate": 1, "items": [...]}`.

use crate::model::Vault;
use crate::report::Report;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct File {
    pwmigrate: u32,
    #[serde(flatten)]
    vault: Vault,
}

pub fn import(data: &str, _report: &mut Report) -> Result<Vault> {
    // Accept both the wrapped form and a bare canonical Vault.
    let data = data.trim_start_matches('\u{feff}');
    if let Ok(f) = serde_json::from_str::<File>(data) {
        return Ok(f.vault);
    }
    let vault: Vault =
        serde_json::from_str(data).context("pwmigrate-json: not a canonical vault file")?;
    Ok(vault)
}

pub fn export(vault: &Vault, _report: &mut Report) -> Result<String> {
    let f = File {
        pwmigrate: 1,
        vault: vault.clone(),
    };
    Ok(serde_json::to_string_pretty(&f)?)
}
