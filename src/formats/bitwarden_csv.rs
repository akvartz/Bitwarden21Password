//! Bitwarden CSV export/import.
//!
//! Header: folder,favorite,type,name,notes,fields,reprompt,login_uri,
//! login_username,login_password,login_totp
//!
//! The `fields` column holds custom fields as newline-separated `name: value`
//! pairs. Bitwarden CSV only carries logins and secure notes; cards,
//! identities and passkeys require the JSON export.

use super::{check_headers, opt, CsvTable};
use crate::model::{CustomField, Item, ItemType, Login, Vault};
use crate::report::Report;
use anyhow::Result;

const KNOWN: &[&str] = &[
    "folder",
    "favorite",
    "type",
    "name",
    "notes",
    "fields",
    "reprompt",
    "login_uri",
    "login_username",
    "login_password",
    "login_totp",
];
const REQUIRED: &[&str] = &["name", "login_username", "login_password"];

pub fn import(data: &str, report: &mut Report) -> Result<Vault> {
    let table = CsvTable::parse(data)?;
    check_headers(&table.headers, REQUIRED, KNOWN, "bitwarden-csv", report)?;

    let mut vault = Vault::default();
    for rec in &table.records {
        let name = table.get(rec, "name");
        let type_field = table.get(rec, "type").to_lowercase();
        let item_type = match type_field.as_str() {
            "note" => ItemType::SecureNote,
            "card" => ItemType::Card,
            "identity" => ItemType::Identity,
            _ => ItemType::Login,
        };

        let mut fields: Vec<CustomField> = parse_fields_column(table.get(rec, "fields"));
        fields.extend(table.unknown_columns(rec, KNOWN));

        let login = Login {
            username: opt(table.get(rec, "login_username")),
            email: None,
            password: opt(table.get(rec, "login_password")),
            totp: opt(table.get(rec, "login_totp")),
            uris: table
                .get(rec, "login_uri")
                .split(',')
                .map(|u| u.trim().to_string())
                .filter(|u| !u.is_empty())
                .collect(),
            passkeys: Vec::new(),
        };

        vault.items.push(Item {
            title: if name.is_empty() {
                "Untitled".into()
            } else {
                name.to_string()
            },
            folder: opt(table.get(rec, "folder")),
            favorite: super::parse_bool(table.get(rec, "favorite")),
            notes: opt(table.get(rec, "notes")),
            item_type,
            login: if login.is_empty() && item_type != ItemType::Login {
                None
            } else {
                Some(login)
            },
            reprompt: super::parse_bool(table.get(rec, "reprompt")),
            fields,
            ..Default::default()
        });
    }
    Ok(vault)
}

pub fn export(vault: &Vault, report: &mut Report) -> Result<String> {
    let mut wtr = csv::Writer::from_writer(Vec::new());
    wtr.write_record([
        "folder",
        "favorite",
        "type",
        "name",
        "notes",
        "fields",
        "reprompt",
        "login_uri",
        "login_username",
        "login_password",
        "login_totp",
    ])?;

    for item in &vault.items {
        let type_field = match item.item_type {
            ItemType::SecureNote => "note",
            _ => "login",
        };
        let mut all_fields = item.fields.clone();
        if !item.tags.is_empty() {
            all_fields.push(CustomField::new("tags", item.tags.join(", ")));
        }
        if let Some(l) = &item.login {
            if let (Some(u), Some(e)) = (&l.username, &l.email) {
                if !u.is_empty() && !e.is_empty() && u != e {
                    all_fields.push(CustomField::new("email", e.clone()));
                }
            }
        }
        // CSV cannot hold cards/identities as structured data: flatten them.
        if matches!(item.item_type, ItemType::Card | ItemType::Identity) {
            all_fields.extend(crate::extras::card_identity_fields(item));
            report.warn(
                Some(&item.title),
                "Bitwarden CSV cannot represent card/identity items; exported as a login with the details in custom fields (use bitwarden-json to keep structure)",
            );
        }

        let (username, password, totp, uris) = match &item.login {
            Some(l) => {
                for pk in &l.passkeys {
                    report.warn(
                        Some(&item.title),
                        format!(
                            "passkey for '{}' cannot be represented in Bitwarden CSV — use bitwarden-json",
                            pk.rp_id.as_deref().unwrap_or("unknown site")
                        ),
                    );
                }
                (
                    l.username_or_email().unwrap_or("").to_string(),
                    l.password.clone().unwrap_or_default(),
                    l.totp.clone().unwrap_or_default(),
                    l.uris.join(","),
                )
            }
            None => (String::new(), String::new(), String::new(), String::new()),
        };

        wtr.write_record([
            item.folder.as_deref().unwrap_or(""),
            if item.favorite { "1" } else { "" },
            type_field,
            &item.title,
            item.notes.as_deref().unwrap_or(""),
            &fields_column(&all_fields),
            if item.reprompt { "1" } else { "0" },
            &uris,
            &username,
            &password,
            &totp,
        ])?;
    }
    Ok(String::from_utf8(wtr.into_inner()?)?)
}

fn parse_fields_column(raw: &str) -> Vec<CustomField> {
    raw.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            match line.split_once(": ") {
                Some((n, v)) => Some(CustomField::new(n, v)),
                None => match line.split_once(':') {
                    Some((n, v)) => Some(CustomField::new(n.trim(), v.trim())),
                    None => Some(CustomField::new(line, "")),
                },
            }
        })
        .collect()
}

fn fields_column(fields: &[CustomField]) -> String {
    fields
        .iter()
        .map(|f| format!("{}: {}", f.name, f.value.replace('\n', " ")))
        .collect::<Vec<_>>()
        .join("\n")
}
