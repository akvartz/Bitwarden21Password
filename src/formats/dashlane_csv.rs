//! Dashlane credentials CSV export/import.
//!
//! Header: username,username2,username3,title,password,note,url,category,
//! otpSecret

use super::{check_headers, opt, CsvTable};
use crate::model::{CustomField, Item, ItemType, Login, Vault};
use crate::report::Report;
use anyhow::Result;

const KNOWN: &[&str] = &[
    "username",
    "username2",
    "username3",
    "title",
    "password",
    "note",
    "url",
    "category",
    "otpsecret",
    "otpurl",
];
const REQUIRED: &[&str] = &["username", "title", "password"];

pub fn import(data: &str, report: &mut Report) -> Result<Vault> {
    let table = CsvTable::parse(data)?;
    check_headers(&table.headers, REQUIRED, KNOWN, "dashlane-csv", report)?;

    let mut vault = Vault::default();
    for rec in &table.records {
        let (notes, mut fields) =
            crate::extras::unfold_from_notes(opt(table.get(rec, "note")).as_deref());
        fields.extend(table.unknown_columns(rec, KNOWN));
        let recovered = crate::extras::recover_special_fields(&mut fields);
        for extra_user in ["username2", "username3"] {
            if let Some(u) = opt(table.get(rec, extra_user)) {
                fields.push(CustomField::new("alternate username", u));
            }
        }
        let url = table.get(rec, "url");
        let mut uris: Vec<String> = opt(url).into_iter().collect();
        uris.extend(recovered.urls);
        vault.items.push(Item {
            title: opt(table.get(rec, "title")).unwrap_or_else(|| super::title_from_url(url)),
            folder: opt(table.get(rec, "category")).or(recovered.folder),
            notes,
            item_type: ItemType::Login,
            login: Some(Login {
                username: opt(table.get(rec, "username")),
                email: recovered.email,
                password: opt(table.get(rec, "password")),
                totp: opt(table.get(rec, "otpsecret"))
                    .or_else(|| opt(table.get(rec, "otpurl")))
                    .or(recovered.totp),
                uris,
                ..Default::default()
            }),
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
        "username",
        "username2",
        "username3",
        "title",
        "password",
        "note",
        "url",
        "category",
        "otpSecret",
    ])?;

    for item in &vault.items {
        let login = item.login.clone().unwrap_or_default();
        let mut extras: Vec<CustomField> = item
            .fields
            .iter()
            .filter(|f| f.name != "alternate username")
            .cloned()
            .collect();
        let alt_users: Vec<String> = item
            .fields
            .iter()
            .filter(|f| f.name == "alternate username")
            .map(|f| f.value.clone())
            .collect();
        if !item.tags.is_empty() {
            extras.push(CustomField::new("tags", item.tags.join(", ")));
        }
        for uri in login.uris.iter().skip(1) {
            extras.push(CustomField::new("url", uri.clone()));
        }
        if matches!(item.item_type, ItemType::Card | ItemType::Identity) {
            extras.extend(crate::extras::card_identity_fields(item));
            report.warn(
                Some(&item.title),
                "Dashlane credentials CSV cannot hold card/identity details; folded into the note",
            );
        }
        for pk in &login.passkeys {
            report.warn(
                Some(&item.title),
                format!(
                    "passkey for '{}' cannot travel through Dashlane CSV; re-register it after import",
                    pk.rp_id.as_deref().unwrap_or("unknown site")
                ),
            );
        }
        let notes = crate::extras::fold_into_notes(item.notes.as_deref(), &extras);
        wtr.write_record([
            login.username_or_email().unwrap_or(""),
            alt_users.first().map(String::as_str).unwrap_or(""),
            alt_users.get(1).map(String::as_str).unwrap_or(""),
            &item.title,
            login.password.as_deref().unwrap_or(""),
            notes.as_deref().unwrap_or(""),
            login.uris.first().map(String::as_str).unwrap_or(""),
            item.folder.as_deref().unwrap_or(""),
            login.totp.as_deref().unwrap_or(""),
        ])?;
    }
    Ok(String::from_utf8(wtr.into_inner()?)?)
}
