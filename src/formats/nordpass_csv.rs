//! NordPass CSV export/import.
//!
//! Header: name,url,username,password,note,cardholdername,cardnumber,cvc,
//! expirydate,zipcode,folder,full_name,phone_number,email,address1,address2,
//! city,country,state,type
//!
//! `type` is one of password | credit_card | note | identity (older exports
//! omit the column; rows are then treated as logins).

use super::{check_headers, opt, CsvTable};
use crate::model::{Card, Identity, Item, ItemType, Login, Vault};
use crate::report::Report;
use anyhow::Result;

const KNOWN: &[&str] = &[
    "name", "url", "username", "password", "note", "cardholdername", "cardnumber", "cvc",
    "expirydate", "zipcode", "folder", "full_name", "phone_number", "email", "address1",
    "address2", "city", "country", "state", "type", "custom_fields",
];
const REQUIRED: &[&str] = &["name", "url", "username", "password"];

pub fn import(data: &str, report: &mut Report) -> Result<Vault> {
    let table = CsvTable::parse(data)?;
    check_headers(&table.headers, REQUIRED, KNOWN, "nordpass-csv", report)?;

    let mut vault = Vault::default();
    for rec in &table.records {
        let type_str = table.get(rec, "type").to_lowercase();
        let item_type = match type_str.as_str() {
            "credit_card" => ItemType::Card,
            "note" => ItemType::SecureNote,
            "identity" => ItemType::Identity,
            _ => ItemType::Login,
        };
        let (notes, mut fields) =
            crate::extras::unfold_from_notes(opt(table.get(rec, "note")).as_deref());
        fields.extend(table.unknown_columns(rec, KNOWN));
        let recovered = crate::extras::recover_special_fields(&mut fields);

        let (exp_month, exp_year) = match table.get(rec, "expirydate").split_once('/') {
            Some((m, y)) => (opt(m.trim()), opt(y.trim())),
            None => (None, opt(table.get(rec, "expirydate"))),
        };
        let card = if item_type == ItemType::Card {
            Some(Card {
                cardholder_name: opt(table.get(rec, "cardholdername")),
                number: opt(table.get(rec, "cardnumber")),
                brand: None,
                exp_month,
                exp_year,
                code: opt(table.get(rec, "cvc")),
            })
        } else {
            None
        };
        let identity = if item_type == ItemType::Identity {
            Some(Identity {
                full_name: opt(table.get(rec, "full_name")),
                email: opt(table.get(rec, "email")),
                phone: opt(table.get(rec, "phone_number")),
                address1: opt(table.get(rec, "address1")),
                address2: opt(table.get(rec, "address2")),
                city: opt(table.get(rec, "city")),
                state: opt(table.get(rec, "state")),
                zip: opt(table.get(rec, "zipcode")),
                country: opt(table.get(rec, "country")),
            })
        } else {
            None
        };
        let login = if item_type == ItemType::Login {
            let mut uris: Vec<String> = opt(table.get(rec, "url")).into_iter().collect();
            uris.extend(recovered.urls);
            Some(Login {
                username: opt(table.get(rec, "username")),
                email: opt(table.get(rec, "email")).or(recovered.email),
                password: opt(table.get(rec, "password")),
                totp: recovered.totp,
                uris,
                ..Default::default()
            })
        } else {
            None
        };
        vault.items.push(Item {
            title: opt(table.get(rec, "name")).unwrap_or_else(|| "Untitled".into()),
            folder: opt(table.get(rec, "folder")).or(recovered.folder),
            notes,
            item_type,
            login,
            card,
            identity,
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
        "name", "url", "username", "password", "note", "cardholdername", "cardnumber", "cvc",
        "expirydate", "zipcode", "folder", "full_name", "phone_number", "email", "address1",
        "address2", "city", "country", "state", "type",
    ])?;

    for item in &vault.items {
        let login = item.login.clone().unwrap_or_default();
        let card = item.card.clone().unwrap_or_default();
        let id = item.identity.clone().unwrap_or_default();
        let type_str = match item.item_type {
            ItemType::Login => "password",
            ItemType::Card => "credit_card",
            ItemType::SecureNote => "note",
            ItemType::Identity => "identity",
        };
        let mut extras = item.fields.clone();
        if !item.tags.is_empty() {
            extras.push(crate::model::CustomField::new("tags", item.tags.join(", ")));
        }
        for uri in login.uris.iter().skip(1) {
            extras.push(crate::model::CustomField::new("url", uri.clone()));
        }
        if let Some(totp) = &login.totp {
            extras.push(crate::model::CustomField::new("totp", totp.clone()));
            report.warn(
                Some(&item.title),
                "NordPass CSV has no TOTP column; the TOTP secret was folded into the note",
            );
        }
        for pk in &login.passkeys {
            report.warn(
                Some(&item.title),
                format!(
                    "passkey for '{}' cannot travel through NordPass CSV; re-register it after import",
                    pk.rp_id.as_deref().unwrap_or("unknown site")
                ),
            );
        }
        let notes = crate::extras::fold_into_notes(item.notes.as_deref(), &extras);
        let expiry = match (&card.exp_month, &card.exp_year) {
            (Some(m), Some(y)) => format!("{m}/{y}"),
            (None, Some(y)) => y.clone(),
            _ => String::new(),
        };
        wtr.write_record([
            item.title.as_str(),
            login.uris.first().map(String::as_str).unwrap_or(""),
            login.username.as_deref().unwrap_or(""),
            login.password.as_deref().unwrap_or(""),
            notes.as_deref().unwrap_or(""),
            card.cardholder_name.as_deref().unwrap_or(""),
            card.number.as_deref().unwrap_or(""),
            card.code.as_deref().unwrap_or(""),
            &expiry,
            id.zip.as_deref().unwrap_or(""),
            item.folder.as_deref().unwrap_or(""),
            id.full_name.as_deref().unwrap_or(""),
            id.phone.as_deref().unwrap_or(""),
            login.email.as_deref().or(id.email.as_deref()).unwrap_or(""),
            id.address1.as_deref().unwrap_or(""),
            id.address2.as_deref().unwrap_or(""),
            id.city.as_deref().unwrap_or(""),
            id.country.as_deref().unwrap_or(""),
            id.state.as_deref().unwrap_or(""),
            type_str,
        ])?;
    }
    Ok(String::from_utf8(wtr.into_inner()?)?)
}
