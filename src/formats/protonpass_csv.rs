//! Proton Pass CSV export/import.
//!
//! Header: type,name,url,email,username,password,note,totp,createTime,
//! modifyTime,vault
//!
//! Proton's CSV only fully covers logins and notes (its own CSV export drops
//! card numbers, identities, custom fields and passkeys) — prefer
//! protonpass-json when migrating out of Proton Pass.

use super::{check_headers, opt, CsvTable};
use crate::model::{Item, ItemType, Login, Vault};
use crate::report::Report;
use anyhow::Result;

const KNOWN: &[&str] = &[
    "type",
    "name",
    "url",
    "email",
    "username",
    "password",
    "note",
    "totp",
    "createtime",
    "modifytime",
    "vault",
];
const REQUIRED: &[&str] = &["name", "password", "note"];

pub fn import(data: &str, report: &mut Report) -> Result<Vault> {
    let table = CsvTable::parse(data)?;
    check_headers(&table.headers, REQUIRED, KNOWN, "protonpass-csv", report)?;

    let mut vault = Vault::default();
    for rec in &table.records {
        let type_str = table.get(rec, "type").to_lowercase();
        let item_type = match type_str.as_str() {
            "note" => ItemType::SecureNote,
            "creditcard" => ItemType::Card,
            "identity" => ItemType::Identity,
            _ => ItemType::Login, // login, alias, custom
        };
        let (notes, mut fields) =
            crate::extras::unfold_from_notes(opt(table.get(rec, "note")).as_deref());
        fields.extend(table.unknown_columns(rec, KNOWN));
        let recovered = crate::extras::recover_special_fields(&mut fields);
        if type_str == "alias" {
            fields.push(crate::model::CustomField::new(
                "proton alias",
                table.get(rec, "email"),
            ));
        }
        let mut uris: Vec<String> = opt(table.get(rec, "url")).into_iter().collect();
        uris.extend(recovered.urls);
        let login = Login {
            username: opt(table.get(rec, "username")),
            email: opt(table.get(rec, "email")).or(recovered.email),
            password: opt(table.get(rec, "password")),
            totp: opt(table.get(rec, "totp")).or(recovered.totp),
            uris,
            passkeys: Vec::new(),
        };
        vault.items.push(Item {
            title: opt(table.get(rec, "name")).unwrap_or_else(|| "Untitled".into()),
            folder: opt(table.get(rec, "vault")).or(recovered.folder),
            notes,
            item_type,
            login: if login.is_empty() && item_type != ItemType::Login {
                None
            } else {
                Some(login)
            },
            fields,
            tags: recovered.tags,
            created: table.get(rec, "createtime").parse().ok(),
            modified: table.get(rec, "modifytime").parse().ok(),
            ..Default::default()
        });
    }
    Ok(vault)
}

pub fn export(vault: &Vault, report: &mut Report) -> Result<String> {
    let mut wtr = csv::Writer::from_writer(Vec::new());
    wtr.write_record([
        "type",
        "name",
        "url",
        "email",
        "username",
        "password",
        "note",
        "totp",
        "createTime",
        "modifyTime",
        "vault",
    ])?;

    for item in &vault.items {
        let type_str = match item.item_type {
            ItemType::Login => "login",
            ItemType::SecureNote => "note",
            ItemType::Card => "creditCard",
            ItemType::Identity => "identity",
        };
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
                "Proton Pass CSV cannot hold card/identity details; they were folded into the note (use protonpass-json for structured import)",
            );
        }
        for pk in &login.passkeys {
            report.warn(
                Some(&item.title),
                format!(
                    "passkey for '{}' cannot travel through Proton Pass CSV; use protonpass-json or re-register it",
                    pk.rp_id.as_deref().unwrap_or("unknown site")
                ),
            );
        }
        let notes = crate::extras::fold_into_notes(item.notes.as_deref(), &extras);

        wtr.write_record([
            type_str,
            &item.title,
            login.uris.first().map(String::as_str).unwrap_or(""),
            login.email.as_deref().unwrap_or(""),
            login.username.as_deref().unwrap_or(""),
            login.password.as_deref().unwrap_or(""),
            notes.as_deref().unwrap_or(""),
            login.totp.as_deref().unwrap_or(""),
            &item.created.map(|t| t.to_string()).unwrap_or_default(),
            &item.modified.map(|t| t.to_string()).unwrap_or_default(),
            item.folder.as_deref().unwrap_or("Personal"),
        ])?;
    }
    Ok(String::from_utf8(wtr.into_inner()?)?)
}
