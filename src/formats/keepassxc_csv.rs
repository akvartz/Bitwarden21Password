//! KeePassXC CSV export/import.
//!
//! Header: "Group","Title","Username","Password","URL","Notes","TOTP","Icon",
//! "Last Modified","Created"  (KeePassXC ≥ 2.7). Groups may be nested with
//! '/' separators; they map to folders.

use super::{check_headers, opt, CsvTable};
use crate::model::{Item, ItemType, Login, Vault};
use crate::report::Report;
use anyhow::Result;

const KNOWN: &[&str] = &[
    "group",
    "title",
    "username",
    "password",
    "url",
    "notes",
    "totp",
    "icon",
    "last modified",
    "created",
];
const REQUIRED: &[&str] = &["title", "username", "password"];

pub fn import(data: &str, report: &mut Report) -> Result<Vault> {
    let table = CsvTable::parse(data)?;
    check_headers(&table.headers, REQUIRED, KNOWN, "keepassxc-csv", report)?;

    let mut vault = Vault::default();
    for rec in &table.records {
        let (notes, mut fields) =
            crate::extras::unfold_from_notes(opt(table.get(rec, "notes")).as_deref());
        fields.extend(table.unknown_columns(rec, KNOWN));
        let recovered = crate::extras::recover_special_fields(&mut fields);

        // Strip the database root ("Root/Web" -> "Web").
        let group = table.get(rec, "group");
        let folder = group
            .split_once('/')
            .map(|(_, rest)| rest.to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| opt(group).filter(|g| g != "Root"));

        let mut uris: Vec<String> = opt(table.get(rec, "url")).into_iter().collect();
        uris.extend(recovered.urls);
        let login = Login {
            username: opt(table.get(rec, "username")),
            email: recovered.email,
            password: opt(table.get(rec, "password")),
            totp: opt(table.get(rec, "totp")).or(recovered.totp),
            uris,
            ..Default::default()
        };
        let item_type = if login.is_empty() && notes.is_some() {
            ItemType::SecureNote
        } else {
            ItemType::Login
        };
        vault.items.push(Item {
            title: opt(table.get(rec, "title")).unwrap_or_else(|| "Untitled".into()),
            folder,
            notes,
            item_type,
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
        "Group",
        "Title",
        "Username",
        "Password",
        "URL",
        "Notes",
        "TOTP",
        "Icon",
        "Last Modified",
        "Created",
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
                "KeePassXC CSV cannot hold card/identity details; folded into the notes",
            );
        }
        for pk in &login.passkeys {
            report.warn(
                Some(&item.title),
                format!(
                    "passkey for '{}' cannot travel through KeePassXC CSV; re-register it after import",
                    pk.rp_id.as_deref().unwrap_or("unknown site")
                ),
            );
        }
        let notes = crate::extras::fold_into_notes(item.notes.as_deref(), &extras);
        let group = match &item.folder {
            Some(f) if !f.is_empty() => format!("Root/{f}"),
            _ => "Root".to_string(),
        };
        wtr.write_record([
            &group,
            &item.title,
            login.username_or_email().unwrap_or(""),
            login.password.as_deref().unwrap_or(""),
            login.uris.first().map(String::as_str).unwrap_or(""),
            notes.as_deref().unwrap_or(""),
            login.totp.as_deref().unwrap_or(""),
            "0",
            "",
            "",
        ])?;
    }
    Ok(String::from_utf8(wtr.into_inner()?)?)
}
