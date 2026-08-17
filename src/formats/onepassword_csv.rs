//! 1Password 8 CSV import/export.
//!
//! Header: Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes
//!
//! 1Password CSV has no custom-field or folder columns; extras are folded
//! into a structured notes block (see `crate::extras`) and folders become
//! tags. Passkeys cannot travel through any 1Password CSV; 1Password itself
//! only imports them via its own cloud sync / 1PUX.

use super::{check_headers, opt, parse_bool, CsvTable};
use crate::model::{Item, ItemType, Login, Vault};
use crate::report::Report;
use anyhow::Result;

const KNOWN: &[&str] = &[
    "title", "url", "username", "password", "otpauth", "favorite", "archived", "tags", "notes",
];
const REQUIRED: &[&str] = &["title", "username", "password"];

pub fn import(data: &str, report: &mut Report) -> Result<Vault> {
    let table = CsvTable::parse(data)?;
    check_headers(&table.headers, REQUIRED, KNOWN, "1password-csv", report)?;

    let mut vault = Vault::default();
    for rec in &table.records {
        let (notes, mut fields) =
            crate::extras::unfold_from_notes(opt(table.get(rec, "notes")).as_deref());
        fields.extend(table.unknown_columns(rec, KNOWN));

        // Recover folder/totp/urls from a previous lossy export, if present.
        let recovered = crate::extras::recover_special_fields(&mut fields);
        let mut uris: Vec<String> = opt(table.get(rec, "url")).into_iter().collect();
        uris.extend(recovered.urls);

        let mut tags: Vec<String> = table
            .get(rec, "tags")
            .split(&[';', ','][..])
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        for t in recovered.tags {
            if !tags.contains(&t) {
                tags.push(t);
            }
        }

        let login = Login {
            username: opt(table.get(rec, "username")),
            email: recovered.email,
            password: opt(table.get(rec, "password")),
            totp: opt(table.get(rec, "otpauth")).or(recovered.totp),
            uris,
            passkeys: Vec::new(),
        };
        let item_type = if login.is_empty() && notes.is_some() {
            ItemType::SecureNote
        } else {
            ItemType::Login
        };
        vault.items.push(Item {
            title: opt(table.get(rec, "title")).unwrap_or_else(|| "Untitled".into()),
            folder: recovered.folder,
            favorite: parse_bool(table.get(rec, "favorite")),
            notes,
            item_type,
            login: Some(login),
            fields,
            tags,
            ..Default::default()
        });
    }
    Ok(vault)
}

pub fn export(vault: &Vault, report: &mut Report) -> Result<String> {
    let mut wtr = csv::Writer::from_writer(Vec::new());
    wtr.write_record([
        "Title", "Url", "Username", "Password", "OTPAuth", "Favorite", "Archived", "Tags", "Notes",
    ])?;

    for item in &vault.items {
        let mut extras = item.fields.clone();
        if matches!(item.item_type, ItemType::Card | ItemType::Identity) {
            extras.extend(crate::extras::card_identity_fields(item));
            report.warn(
                Some(&item.title),
                "1Password CSV cannot represent card/identity items; details moved into the notes block",
            );
        }
        let login = item.login.clone().unwrap_or_default();
        for uri in login.uris.iter().skip(1) {
            extras.push(crate::model::CustomField::new("url", uri.clone()));
        }
        if let (Some(u), Some(e)) = (&login.username, &login.email) {
            if !u.is_empty() && !e.is_empty() && u != e {
                extras.push(crate::model::CustomField::new("email", e.clone()));
            }
        }
        for pk in &login.passkeys {
            report.warn(
                Some(&item.title),
                format!(
                    "passkey for '{}' cannot travel through 1Password CSV; re-register it in 1Password after import",
                    pk.rp_id.as_deref().unwrap_or("unknown site")
                ),
            );
        }
        if !extras.is_empty() {
            report.info(
                Some(&item.title),
                format!("{} extra field(s) folded into the notes block", extras.len()),
            );
        }

        // Folders map to 1Password tags (its closest concept).
        let mut tags = item.tags.clone();
        if let Some(folder) = &item.folder {
            if !folder.is_empty() && !tags.contains(folder) {
                tags.push(folder.clone());
            }
        }

        let notes = crate::extras::fold_into_notes(item.notes.as_deref(), &extras);
        wtr.write_record([
            item.title.as_str(),
            login.uris.first().map(String::as_str).unwrap_or(""),
            login.username_or_email().unwrap_or(""),
            login.password.as_deref().unwrap_or(""),
            login.totp.as_deref().unwrap_or(""),
            if item.favorite { "true" } else { "" },
            "",
            &tags.join(";"),
            notes.as_deref().unwrap_or(""),
        ])?;
    }
    Ok(String::from_utf8(wtr.into_inner()?)?)
}
