//! Bitwarden unencrypted JSON export/import (`.json`, "Export vault" →
//! ".json"). This is the richest Bitwarden format: folders, all four item
//! types, typed custom fields and FIDO2 passkeys (`login.fido2Credentials`).

use crate::model::{Card, CustomField, Identity, Item, ItemType, Login, Passkey, Vault};
use crate::report::Report;
use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

pub fn import(data: &str, report: &mut Report) -> Result<Vault> {
    let root: Value = serde_json::from_str(data.trim_start_matches('\u{feff}'))
        .context("bitwarden-json: not valid JSON")?;

    if root.get("encrypted").and_then(Value::as_bool) == Some(true) {
        bail!(
            "bitwarden-json: this is an *encrypted* Bitwarden export; \
             re-export from Bitwarden choosing the plain '.json' option"
        );
    }
    let items = root
        .get("items")
        .and_then(Value::as_array)
        .context("bitwarden-json: missing 'items' array")?;

    // folderId -> folder name
    let mut folders = std::collections::HashMap::new();
    if let Some(fs) = root.get("folders").and_then(Value::as_array) {
        for f in fs {
            if let (Some(id), Some(name)) = (str_of(f, "id"), str_of(f, "name")) {
                folders.insert(id.to_string(), name.to_string());
            }
        }
    }

    let mut vault = Vault::default();
    for raw in items {
        let title = str_of(raw, "name").unwrap_or("Untitled").to_string();
        let type_num = raw.get("type").and_then(Value::as_i64).unwrap_or(1);
        let item_type = match type_num {
            2 => ItemType::SecureNote,
            3 => ItemType::Card,
            4 => ItemType::Identity,
            _ => ItemType::Login,
        };

        let mut fields = Vec::new();
        if let Some(fs) = raw.get("fields").and_then(Value::as_array) {
            for f in fs {
                let name = str_of(f, "name").unwrap_or("").to_string();
                let value = str_of(f, "value").unwrap_or("").to_string();
                let ftype = f.get("type").and_then(Value::as_i64).unwrap_or(0);
                if ftype == 3 {
                    // Linked fields reference the username/password; skip value-less links.
                    continue;
                }
                fields.push(CustomField {
                    concealed: ftype == 1 || crate::model::looks_concealed(&name),
                    name,
                    value,
                });
            }
        }

        let login = raw.get("login").map(|l| {
            let mut uris = Vec::new();
            if let Some(us) = l.get("uris").and_then(Value::as_array) {
                for u in us {
                    if let Some(uri) = str_of(u, "uri") {
                        uris.push(uri.to_string());
                    }
                }
            }
            let mut passkeys = Vec::new();
            if let Some(creds) = l.get("fido2Credentials").and_then(Value::as_array) {
                for c in creds {
                    passkeys.push(passkey_from_json(c));
                }
            }
            Login {
                username: str_of(l, "username").map(String::from),
                email: None,
                password: str_of(l, "password").map(String::from),
                totp: str_of(l, "totp").map(String::from),
                uris,
                passkeys,
            }
        });

        let card = raw.get("card").map(|c| Card {
            cardholder_name: str_of(c, "cardholderName").map(String::from),
            number: str_of(c, "number").map(String::from),
            brand: str_of(c, "brand").map(String::from),
            exp_month: str_of(c, "expMonth").map(String::from),
            exp_year: str_of(c, "expYear").map(String::from),
            code: str_of(c, "code").map(String::from),
        });

        let identity = raw.get("identity").map(|i| {
            let full_name = match (str_of(i, "firstName"), str_of(i, "lastName")) {
                (Some(f), Some(l)) => Some(format!("{f} {l}")),
                (Some(f), None) => Some(f.to_string()),
                (None, Some(l)) => Some(l.to_string()),
                (None, None) => None,
            };
            Identity {
                full_name,
                email: str_of(i, "email").map(String::from),
                phone: str_of(i, "phone").map(String::from),
                address1: str_of(i, "address1").map(String::from),
                address2: str_of(i, "address2").map(String::from),
                city: str_of(i, "city").map(String::from),
                state: str_of(i, "state").map(String::from),
                zip: str_of(i, "postalCode").map(String::from),
                country: str_of(i, "country").map(String::from),
            }
        });

        vault.items.push(Item {
            title,
            folder: raw
                .get("folderId")
                .and_then(Value::as_str)
                .and_then(|id| folders.get(id).cloned()),
            favorite: raw.get("favorite").and_then(Value::as_bool).unwrap_or(false),
            notes: str_of(raw, "notes").map(String::from),
            item_type,
            login,
            card,
            identity,
            fields,
            tags: Vec::new(),
            created: None,
            modified: None,
            reprompt: raw.get("reprompt").and_then(Value::as_i64).unwrap_or(0) == 1,
        });
    }

    let n_passkeys: usize = vault
        .items
        .iter()
        .filter_map(|i| i.login.as_ref())
        .map(|l| l.passkeys.len())
        .sum();
    if n_passkeys > 0 {
        report.info(None, format!("imported {n_passkeys} passkey(s) with private key material"));
    }
    Ok(vault)
}

pub fn export(vault: &Vault, report: &mut Report) -> Result<String> {
    // Collect folders and assign deterministic ids.
    let mut folder_names: Vec<String> = Vec::new();
    for item in &vault.items {
        if let Some(f) = &item.folder {
            if !f.is_empty() && !folder_names.contains(f) {
                folder_names.push(f.clone());
            }
        }
    }
    let folder_id = |name: &str| -> String {
        let idx = folder_names.iter().position(|n| n == name).unwrap_or(0);
        format!("00000000-0000-0000-0000-{idx:012}")
    };

    let folders: Vec<Value> = folder_names
        .iter()
        .map(|n| json!({"id": folder_id(n), "name": n}))
        .collect();

    let mut items = Vec::new();
    for (idx, item) in vault.items.iter().enumerate() {
        let type_num = match item.item_type {
            ItemType::Login => 1,
            ItemType::SecureNote => 2,
            ItemType::Card => 3,
            ItemType::Identity => 4,
        };
        let mut obj = Map::new();
        obj.insert("id".into(), json!(format!("00000000-0000-0000-0001-{idx:012}")));
        obj.insert("organizationId".into(), Value::Null);
        obj.insert(
            "folderId".into(),
            match &item.folder {
                Some(f) if !f.is_empty() => json!(folder_id(f)),
                _ => Value::Null,
            },
        );
        obj.insert("type".into(), json!(type_num));
        obj.insert("reprompt".into(), json!(if item.reprompt { 1 } else { 0 }));
        obj.insert("name".into(), json!(item.title));
        let mut notes = item.notes.clone();
        if !item.tags.is_empty() {
            let tag_line = format!("tags: {}", item.tags.join(", "));
            notes = Some(match notes {
                Some(n) => format!("{n}\n{tag_line}"),
                None => tag_line,
            });
            report.info(
                Some(&item.title),
                "Bitwarden has no tags; tag list appended to notes",
            );
        }
        obj.insert("notes".into(), notes.map(Value::from).unwrap_or(Value::Null));
        obj.insert("favorite".into(), json!(item.favorite));

        if !item.fields.is_empty() {
            let fields: Vec<Value> = item
                .fields
                .iter()
                .map(|f| {
                    json!({
                        "name": f.name,
                        "value": f.value,
                        "type": if f.concealed { 1 } else { 0 },
                        "linkedId": Value::Null,
                    })
                })
                .collect();
            obj.insert("fields".into(), Value::Array(fields));
        }

        match item.item_type {
            ItemType::Login => {
                let login = item.login.clone().unwrap_or_default();
                let uris: Vec<Value> = login
                    .uris
                    .iter()
                    .map(|u| json!({"match": Value::Null, "uri": u}))
                    .collect();
                let mut l = Map::new();
                l.insert("uris".into(), Value::Array(uris));
                l.insert(
                    "username".into(),
                    login
                        .username_or_email()
                        .map(|s| Value::from(s.to_string()))
                        .unwrap_or(Value::Null),
                );
                l.insert(
                    "password".into(),
                    login.password.clone().map(Value::from).unwrap_or(Value::Null),
                );
                l.insert("totp".into(), login.totp.clone().map(Value::from).unwrap_or(Value::Null));
                let mut creds = Vec::new();
                for pk in &login.passkeys {
                    if pk.has_portable_key() {
                        creds.push(passkey_to_json(pk));
                    } else {
                        report.warn(
                            Some(&item.title),
                            format!(
                                "passkey for '{}' has no portable private key (source provider stores it in a proprietary blob); it was NOT exported — re-register the passkey after migrating",
                                pk.rp_id.as_deref().unwrap_or("unknown site")
                            ),
                        );
                    }
                }
                if !creds.is_empty() {
                    l.insert("fido2Credentials".into(), Value::Array(creds));
                }
                obj.insert("login".into(), Value::Object(l));
            }
            ItemType::SecureNote => {
                obj.insert("secureNote".into(), json!({"type": 0}));
            }
            ItemType::Card => {
                let card = item.card.clone().unwrap_or_default();
                obj.insert(
                    "card".into(),
                    json!({
                        "cardholderName": card.cardholder_name,
                        "brand": card.brand,
                        "number": card.number,
                        "expMonth": card.exp_month,
                        "expYear": card.exp_year,
                        "code": card.code,
                    }),
                );
            }
            ItemType::Identity => {
                let id = item.identity.clone().unwrap_or_default();
                let (first, last) = split_name(id.full_name.as_deref());
                obj.insert(
                    "identity".into(),
                    json!({
                        "title": Value::Null,
                        "firstName": first,
                        "middleName": Value::Null,
                        "lastName": last,
                        "address1": id.address1,
                        "address2": id.address2,
                        "address3": Value::Null,
                        "city": id.city,
                        "state": id.state,
                        "postalCode": id.zip,
                        "country": id.country,
                        "company": Value::Null,
                        "email": id.email,
                        "phone": id.phone,
                        "ssn": Value::Null,
                        "username": Value::Null,
                        "passportNumber": Value::Null,
                        "licenseNumber": Value::Null,
                    }),
                );
            }
        }
        obj.insert("collectionIds".into(), Value::Null);
        items.push(Value::Object(obj));
    }

    let out = json!({
        "encrypted": false,
        "folders": folders,
        "items": items,
    });
    Ok(serde_json::to_string_pretty(&out)?)
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn passkey_from_json(c: &Value) -> Passkey {
    // Bitwarden serializes counter and discoverable as strings.
    let counter = c.get("counter").and_then(|v| match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    });
    let discoverable = c.get("discoverable").and_then(|v| match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => s.parse().ok(),
        _ => None,
    });
    Passkey {
        credential_id: str_of(c, "credentialId").map(String::from),
        rp_id: str_of(c, "rpId").map(String::from),
        rp_name: str_of(c, "rpName").map(String::from),
        user_name: str_of(c, "userName").map(String::from),
        user_display_name: str_of(c, "userDisplayName").map(String::from),
        user_handle: str_of(c, "userHandle").map(String::from),
        key_type: str_of(c, "keyType").map(String::from),
        key_algorithm: str_of(c, "keyAlgorithm").map(String::from),
        key_curve: str_of(c, "keyCurve").map(String::from),
        key_value: str_of(c, "keyValue").map(String::from),
        counter,
        discoverable,
        creation_date: str_of(c, "creationDate").map(String::from),
        provider: Some("bitwarden".into()),
        provider_data: Some(c.clone()),
    }
}

fn passkey_to_json(pk: &Passkey) -> Value {
    // If this passkey came from a Bitwarden export, round-trip it verbatim.
    if pk.provider.as_deref() == Some("bitwarden") {
        if let Some(raw) = &pk.provider_data {
            return raw.clone();
        }
    }
    json!({
        "credentialId": pk.credential_id,
        "keyType": pk.key_type.clone().unwrap_or_else(|| "public-key".into()),
        "keyAlgorithm": pk.key_algorithm.clone().unwrap_or_else(|| "ECDSA".into()),
        "keyCurve": pk.key_curve.clone().unwrap_or_else(|| "P-256".into()),
        "keyValue": pk.key_value,
        "rpId": pk.rp_id,
        "userHandle": pk.user_handle,
        "userName": pk.user_name,
        "counter": pk.counter.unwrap_or(0).to_string(),
        "rpName": pk.rp_name,
        "userDisplayName": pk.user_display_name,
        "discoverable": pk.discoverable.unwrap_or(true).to_string(),
        "creationDate": pk.creation_date.clone().unwrap_or_else(|| "1970-01-01T00:00:00.000Z".into()),
    })
}

fn split_name(full: Option<&str>) -> (Value, Value) {
    match full {
        None => (Value::Null, Value::Null),
        Some(s) => match s.split_once(' ') {
            Some((f, l)) => (json!(f), json!(l)),
            None => (json!(s), Value::Null),
        },
    }
}
