//! LastPass CSV export/import.
//!
//! Header: url,username,password,totp,extra,name,grouping,fav
//! (older exports omit `totp`). Secure notes use url == "http://sn" with the
//! note body in `extra`.

use super::{check_headers, opt, parse_bool, CsvTable};
use crate::model::{Item, ItemType, Login, Vault};
use crate::report::Report;
use anyhow::Result;

const KNOWN: &[&str] = &[
    "url", "username", "password", "totp", "extra", "name", "grouping", "fav",
];
const REQUIRED: &[&str] = &["url", "username", "password", "name"];

pub fn import(data: &str, report: &mut Report) -> Result<Vault> {
    let table = CsvTable::parse(data)?;
    check_headers(&table.headers, REQUIRED, KNOWN, "lastpass-csv", report)?;

    let mut vault = Vault::default();
    for rec in &table.records {
        let url = table.get(rec, "url");
        let is_note = url == "http://sn";
        let (notes, mut fields) =
            crate::extras::unfold_from_notes(opt(table.get(rec, "extra")).as_deref());
        fields.extend(table.unknown_columns(rec, KNOWN));
        let recovered = crate::extras::recover_special_fields(&mut fields);
        let mut uris: Vec<String> = if is_note {
            Vec::new()
        } else {
            opt(url).into_iter().collect()
        };
        uris.extend(recovered.urls);

        let login = Login {
            username: opt(table.get(rec, "username")),
            email: recovered.email,
            password: opt(table.get(rec, "password")),
            totp: opt(table.get(rec, "totp")).or(recovered.totp),
            uris,
            ..Default::default()
        };
        vault.items.push(Item {
            title: opt(table.get(rec, "name")).unwrap_or_else(|| "Untitled".into()),
            folder: opt(table.get(rec, "grouping")),
            favorite: parse_bool(table.get(rec, "fav")),
            notes,
            item_type: if is_note {
                ItemType::SecureNote
            } else {
                ItemType::Login
            },
            login: Some(login),
            fields,
            tags: recovered.tags,
            ..Default::default()
        });
    }
    Ok(vault)
}

pub fn export(vault: &Vault, report: &mut Report) -> Result<String> {
    let mut wtr = csv::Writer::from_writer(Vec::new());
    wtr.write_record([
        "url", "username", "password", "totp", "extra", "name", "grouping", "fav",
    ])?;

    for item in &vault.items {
        let login = item.login.clone().unwrap_or_default();
        let mut extras = item.fields.clone();
        if !item.tags.is_empty() {
            extras.push(crate::model::CustomField::new("tags", item.tags.join(", ")));
        }
        for uri in login.uris.iter().skip(1) {
            extras.push(crate::model::CustomField::new("url", uri.clone()));
        }
        if matches!(item.item_type, ItemType::Card | ItemType::Identity) {
            extras.extend(crate::extras::card_identity_fields(item));
            report.warn(
                Some(&item.title),
                "LastPass CSV cannot hold card/identity details; folded into the note",
            );
        }
        for pk in &login.passkeys {
            report.warn(
                Some(&item.title),
                format!(
                    "passkey for '{}' cannot travel through LastPass CSV; re-register it after import",
                    pk.rp_id.as_deref().unwrap_or("unknown site")
                ),
            );
        }
        let notes = crate::extras::fold_into_notes(item.notes.as_deref(), &extras);
        let is_note = item.item_type == ItemType::SecureNote;

        wtr.write_record([
            if is_note {
                "http://sn"
            } else {
                login.uris.first().map(String::as_str).unwrap_or("")
            },
            login.username_or_email().unwrap_or(""),
            login.password.as_deref().unwrap_or(""),
            login.totp.as_deref().unwrap_or(""),
            notes.as_deref().unwrap_or(""),
            &item.title,
            item.folder.as_deref().unwrap_or(""),
            if item.favorite { "1" } else { "0" },
        ])?;
    }
    Ok(String::from_utf8(wtr.into_inner()?)?)
}
