//! Firefox passwords CSV.
//!
//! Header: url,username,password,httpRealm,formActionOrigin,guid,timeCreated,
//! timeLastUsed,timePasswordChanged  (timestamps in milliseconds).

use super::{check_headers, opt, CsvTable};
use crate::model::{Item, ItemType, Login, Vault};
use crate::report::Report;
use anyhow::Result;

const KNOWN: &[&str] = &[
    "url", "username", "password", "httprealm", "formactionorigin", "guid", "timecreated",
    "timelastused", "timepasswordchanged",
];
const REQUIRED: &[&str] = &["url", "username", "password"];

pub fn import(data: &str, report: &mut Report) -> Result<Vault> {
    let table = CsvTable::parse(data)?;
    check_headers(&table.headers, REQUIRED, KNOWN, "firefox-csv", report)?;

    let mut vault = Vault::default();
    for rec in &table.records {
        let url = table.get(rec, "url");
        let ms = |name: &str| -> Option<i64> {
            table.get(rec, name).parse::<i64>().ok().map(|t| t / 1000)
        };
        vault.items.push(Item {
            title: super::title_from_url(url),
            item_type: ItemType::Login,
            login: Some(Login {
                username: opt(table.get(rec, "username")),
                password: opt(table.get(rec, "password")),
                uris: opt(url).into_iter().collect(),
                ..Default::default()
            }),
            fields: table.unknown_columns(rec, KNOWN),
            created: ms("timecreated"),
            modified: ms("timepasswordchanged"),
            ..Default::default()
        });
    }
    Ok(vault)
}

pub fn export(vault: &Vault, report: &mut Report) -> Result<String> {
    let mut wtr = csv::Writer::from_writer(Vec::new());
    wtr.write_record([
        "url", "username", "password", "httpRealm", "formActionOrigin", "guid", "timeCreated",
        "timeLastUsed", "timePasswordChanged",
    ])?;

    for item in &vault.items {
        if item.item_type != ItemType::Login {
            report.warn(
                Some(&item.title),
                "Firefox CSV only holds website logins; non-login item was skipped",
            );
            continue;
        }
        let login = item.login.clone().unwrap_or_default();
        if login.totp.is_some() || !item.fields.is_empty() || item.notes.is_some() {
            report.warn(
                Some(&item.title),
                "Firefox CSV has no notes/TOTP/custom field columns; that data was dropped for this target (consider bitwarden-json or pwmigrate-json)",
            );
        }
        for pk in &login.passkeys {
            report.warn(
                Some(&item.title),
                format!(
                    "passkey for '{}' cannot travel through Firefox CSV",
                    pk.rp_id.as_deref().unwrap_or("unknown site")
                ),
            );
        }
        let created_ms = item.created.map(|t| (t * 1000).to_string()).unwrap_or_default();
        let modified_ms = item.modified.map(|t| (t * 1000).to_string()).unwrap_or_default();
        wtr.write_record([
            login.uris.first().map(String::as_str).unwrap_or(""),
            login.username_or_email().unwrap_or(""),
            login.password.as_deref().unwrap_or(""),
            "",
            login.uris.first().map(String::as_str).unwrap_or(""),
            "",
            &created_ms,
            &created_ms,
            &modified_ms,
        ])?;
    }
    Ok(String::from_utf8(wtr.into_inner()?)?)
}
