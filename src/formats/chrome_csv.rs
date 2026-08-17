//! Chrome / Edge / Brave / Opera passwords CSV (Google Password Manager).
//!
//! Header: name,url,username,password,note  (`note` since Chrome ~101; Edge
//! omits it). Only login entries exist in this format.

use super::{check_headers, opt, CsvTable};
use crate::model::{Item, ItemType, Login, Vault};
use crate::report::Report;
use anyhow::Result;

const KNOWN: &[&str] = &["name", "url", "username", "password", "note"];
const REQUIRED: &[&str] = &["url", "username", "password"];

pub fn import(data: &str, report: &mut Report) -> Result<Vault> {
    let table = CsvTable::parse(data)?;
    check_headers(&table.headers, REQUIRED, KNOWN, "chrome-csv", report)?;

    let mut vault = Vault::default();
    for rec in &table.records {
        let (notes, mut fields) =
            crate::extras::unfold_from_notes(opt(table.get(rec, "note")).as_deref());
        fields.extend(table.unknown_columns(rec, KNOWN));
        let recovered = crate::extras::recover_special_fields(&mut fields);
        let url = table.get(rec, "url");
        let mut uris: Vec<String> = opt(url).into_iter().collect();
        uris.extend(recovered.urls);
        vault.items.push(Item {
            title: opt(table.get(rec, "name"))
                .unwrap_or_else(|| super::title_from_url(url)),
            folder: recovered.folder,
            notes,
            item_type: ItemType::Login,
            login: Some(Login {
                username: opt(table.get(rec, "username")),
                email: recovered.email,
                password: opt(table.get(rec, "password")),
                totp: recovered.totp,
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
    wtr.write_record(["name", "url", "username", "password", "note"])?;

    for item in &vault.items {
        if item.item_type != ItemType::Login {
            report.warn(
                Some(&item.title),
                "browser password CSV only holds logins; exported as a note-only login entry",
            );
        }
        let login = item.login.clone().unwrap_or_default();
        let extras = crate::extras::overflow_fields(item, false, false);
        for pk in &login.passkeys {
            report.warn(
                Some(&item.title),
                format!(
                    "passkey for '{}' cannot travel through a browser CSV; re-register it after import",
                    pk.rp_id.as_deref().unwrap_or("unknown site")
                ),
            );
        }
        let notes = crate::extras::fold_into_notes(item.notes.as_deref(), &extras);

        wtr.write_record([
            &item.title,
            login.uris.first().map(String::as_str).unwrap_or(""),
            login.username_or_email().unwrap_or(""),
            login.password.as_deref().unwrap_or(""),
            notes.as_deref().unwrap_or(""),
        ])?;
    }
    Ok(String::from_utf8(wtr.into_inner()?)?)
}
