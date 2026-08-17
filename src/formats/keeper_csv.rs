//! Keeper CSV export/import.
//!
//! Keeper's CSV has **no header row**. Columns:
//!   folder, title, login, password, login_url, notes, shared_folder,
//!   then alternating custom-field name/value pairs (variable length).
//! Because there is no header, this format cannot be auto-detected — pass
//! `--from keeper-csv` explicitly.

use super::opt;
use crate::model::{CustomField, Item, ItemType, Login, Vault};
use crate::report::Report;
use anyhow::Result;

pub fn import(data: &str, report: &mut Report) -> Result<Vault> {
    let data = data.trim_start_matches('\u{feff}');
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(data.as_bytes());

    let mut vault = Vault::default();
    for (i, rec) in rdr.records().enumerate() {
        let rec = rec?;
        if rec.len() < 4 {
            report.warn(
                Some(&format!("row {}", i + 1)),
                "keeper-csv: row has fewer than 4 columns; skipped",
            );
            continue;
        }
        let get = |idx: usize| rec.get(idx).unwrap_or("").trim();
        // Heuristic guard: if the first row looks like a header, reject.
        if i == 0 && (get(1).eq_ignore_ascii_case("title") || get(2).eq_ignore_ascii_case("login"))
        {
            anyhow::bail!(
                "keeper-csv: the first row looks like a CSV header, but Keeper exports have none — is this really a Keeper file?"
            );
        }
        let mut fields = Vec::new();
        let mut totp = None;
        let mut idx = 7;
        while idx + 1 < rec.len() {
            let name = get(idx);
            let value = get(idx + 1);
            if !name.is_empty() || !value.is_empty() {
                if name.eq_ignore_ascii_case("totp")
                    || name.eq_ignore_ascii_case("two-factor code")
                    || value.starts_with("otpauth://")
                {
                    totp = Some(value.to_string());
                } else {
                    fields.push(CustomField::new(name, value));
                }
            }
            idx += 2;
        }
        if let Some(shared) = opt(get(6)) {
            fields.push(CustomField::new("shared folder", shared));
        }
        let login = Login {
            username: opt(get(2)),
            password: opt(get(3)),
            totp,
            uris: opt(get(4)).into_iter().collect(),
            ..Default::default()
        };
        let item_type = if login.is_empty() {
            ItemType::SecureNote
        } else {
            ItemType::Login
        };
        vault.items.push(Item {
            title: opt(get(1)).unwrap_or_else(|| "Untitled".into()),
            folder: opt(get(0)),
            notes: opt(get(5)),
            item_type,
            login: Some(login),
            fields,
            ..Default::default()
        });
    }
    Ok(vault)
}

pub fn export(vault: &Vault, report: &mut Report) -> Result<String> {
    let mut wtr = csv::WriterBuilder::new()
        .flexible(true)
        .from_writer(Vec::new());

    for item in &vault.items {
        let login = item.login.clone().unwrap_or_default();
        let mut row: Vec<String> = vec![
            item.folder.clone().unwrap_or_default(),
            item.title.clone(),
            login.username_or_email().unwrap_or("").to_string(),
            login.password.clone().unwrap_or_default(),
            login.uris.first().cloned().unwrap_or_default(),
            item.notes.clone().unwrap_or_default(),
            String::new(), // shared_folder
        ];
        let mut fields = item.fields.clone();
        if matches!(item.item_type, ItemType::Card | ItemType::Identity) {
            fields.extend(crate::extras::card_identity_fields(item));
            report.warn(
                Some(&item.title),
                "Keeper CSV cannot hold structured card/identity items; details exported as custom fields",
            );
        }
        if let Some(totp) = &login.totp {
            row.push("TOTP".into());
            row.push(totp.clone());
        }
        if !item.tags.is_empty() {
            fields.push(CustomField::new("tags", item.tags.join(", ")));
        }
        for uri in login.uris.iter().skip(1) {
            fields.push(CustomField::new("url", uri.clone()));
        }
        for f in &fields {
            row.push(f.name.clone());
            row.push(f.value.clone());
        }
        for pk in &login.passkeys {
            report.warn(
                Some(&item.title),
                format!(
                    "passkey for '{}' cannot travel through Keeper CSV; re-register it after import",
                    pk.rp_id.as_deref().unwrap_or("unknown site")
                ),
            );
        }
        wtr.write_record(&row)?;
    }
    Ok(String::from_utf8(wtr.into_inner()?)?)
}
