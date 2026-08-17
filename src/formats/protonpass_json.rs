//! Proton Pass JSON export/import.
//!
//! Proton Pass "Export" produces a zip containing `Proton Pass/data.json`
//! (choose the non-PGP option). This module reads/writes that `data.json`.
//! Structure: `{ version, userId, vaults: { <shareId>: { name, items: [...] } } }`
//! with per-item `data.metadata`, `data.type` ("login" | "note" | "creditCard"
//! | "identity" | "alias"), `data.content` and `data.extraFields`.
//!
//! Passkeys live in `data.content.passkeys[]`. Proton stores the credential's
//! private key inside a proprietary encoded `content` blob; we preserve the
//! whole record verbatim (`Passkey::provider_data`) so Proton→Proton
//! round-trips are lossless, and surface the metadata for other targets.

use crate::model::{Card, CustomField, Identity, Item, ItemType, Login, Passkey, Vault};
use crate::report::Report;
use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

pub fn import(data: &str, report: &mut Report) -> Result<Vault> {
    let root: Value = serde_json::from_str(data.trim_start_matches('\u{feff}')).context(
        "protonpass-json: not valid JSON (note: pass the data.json extracted from the export zip)",
    )?;
    if root.get("encrypted").and_then(Value::as_bool) == Some(true) {
        bail!("protonpass-json: this export is PGP-encrypted; re-export without PGP encryption");
    }
    let vaults = root
        .get("vaults")
        .and_then(Value::as_object)
        .context("protonpass-json: missing 'vaults' object")?;

    let mut vault = Vault::default();
    for (_share_id, v) in vaults {
        let vault_name = v.get("name").and_then(Value::as_str).unwrap_or("Personal");
        let items = v
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for raw in &items {
            if raw.get("state").and_then(Value::as_i64) == Some(2) {
                // Trashed item — import it anyway but flag it.
                report.info(None, "imported an item from Proton Pass trash");
            }
            let data_obj = raw.get("data").cloned().unwrap_or(Value::Null);
            let meta = data_obj.get("metadata").cloned().unwrap_or(Value::Null);
            let title = meta
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("Untitled")
                .to_string();
            let notes = meta
                .get("note")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(String::from);
            let type_str = data_obj
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("login");
            let content = data_obj.get("content").cloned().unwrap_or(Value::Null);

            let mut fields = Vec::new();
            if let Some(extra) = data_obj.get("extraFields").and_then(Value::as_array) {
                for f in extra {
                    let name = f
                        .get("fieldName")
                        .and_then(Value::as_str)
                        .unwrap_or("field")
                        .to_string();
                    let ftype = f.get("type").and_then(Value::as_str).unwrap_or("text");
                    let fdata = f.get("data").cloned().unwrap_or(Value::Null);
                    let value = fdata
                        .get("content")
                        .or_else(|| fdata.get("totpUri"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    fields.push(CustomField {
                        concealed: ftype == "hidden" || crate::model::looks_concealed(&name),
                        name,
                        value,
                    });
                }
            }

            let mut item = Item {
                title,
                folder: Some(vault_name.to_string()),
                notes,
                fields,
                created: raw.get("createTime").and_then(Value::as_i64),
                modified: raw.get("modifyTime").and_then(Value::as_i64),
                favorite: raw.get("pinned").and_then(Value::as_bool).unwrap_or(false),
                ..Default::default()
            };

            match type_str {
                "note" => {
                    item.item_type = ItemType::SecureNote;
                    // Note body may be in metadata.note only.
                }
                "creditCard" => {
                    item.item_type = ItemType::Card;
                    let (exp_month, exp_year) = split_expiration(
                        content
                            .get("expirationDate")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                    );
                    item.card = Some(Card {
                        cardholder_name: nes(&content, "cardholderName"),
                        number: nes(&content, "number"),
                        brand: None,
                        exp_month,
                        exp_year,
                        code: nes(&content, "verificationNumber"),
                    });
                    if let Some(pin) = nes(&content, "pin") {
                        item.fields.push(CustomField {
                            name: "PIN".into(),
                            value: pin,
                            concealed: true,
                        });
                    }
                }
                "identity" => {
                    item.item_type = ItemType::Identity;
                    item.identity = Some(Identity {
                        full_name: nes(&content, "fullName"),
                        email: nes(&content, "email"),
                        phone: nes(&content, "phoneNumber"),
                        address1: nes(&content, "streetAddress"),
                        address2: nes(&content, "floor"),
                        city: nes(&content, "city"),
                        state: nes(&content, "stateOrProvince"),
                        zip: nes(&content, "zipOrPostalCode"),
                        country: nes(&content, "countryOrRegion"),
                    });
                }
                "alias" => {
                    item.item_type = ItemType::Login;
                    let alias = raw.get("aliasEmail").and_then(Value::as_str).unwrap_or("");
                    item.login = Some(Login {
                        email: if alias.is_empty() {
                            None
                        } else {
                            Some(alias.to_string())
                        },
                        ..Default::default()
                    });
                    item.fields.push(CustomField::new("proton alias", alias));
                }
                _ => {
                    item.item_type = ItemType::Login;
                    let uris: Vec<String> = content
                        .get("urls")
                        .and_then(Value::as_array)
                        .map(|us| {
                            us.iter()
                                .filter_map(Value::as_str)
                                .map(String::from)
                                .collect()
                        })
                        .unwrap_or_default();
                    let mut passkeys = Vec::new();
                    if let Some(pks) = content.get("passkeys").and_then(Value::as_array) {
                        for pk in pks {
                            passkeys.push(Passkey {
                                credential_id: nes(pk, "credentialId"),
                                rp_id: nes(pk, "rpId"),
                                rp_name: nes(pk, "rpName"),
                                user_name: nes(pk, "userName"),
                                user_display_name: nes(pk, "userDisplayName"),
                                user_handle: nes(pk, "userHandle"),
                                creation_date: pk
                                    .get("createTime")
                                    .and_then(Value::as_i64)
                                    .map(|t| t.to_string()),
                                provider: Some("protonpass".into()),
                                provider_data: Some(pk.clone()),
                                ..Default::default()
                            });
                        }
                    }
                    item.login = Some(Login {
                        username: nes(&content, "itemUsername"),
                        email: nes(&content, "itemEmail"),
                        password: nes(&content, "password"),
                        totp: nes(&content, "totpUri"),
                        uris,
                        passkeys,
                    });
                }
            }
            vault.items.push(item);
        }
    }

    let n_passkeys: usize = vault
        .items
        .iter()
        .filter_map(|i| i.login.as_ref())
        .map(|l| l.passkeys.len())
        .sum();
    if n_passkeys > 0 {
        report.info(
            None,
            format!(
                "imported {n_passkeys} Proton Pass passkey(s); they round-trip losslessly back to protonpass-json, but their private keys use Proton's internal encoding and cannot be exported to other managers"
            ),
        );
    }
    Ok(vault)
}

pub fn export(vault: &Vault, report: &mut Report) -> Result<String> {
    // Group items into vaults by folder (Proton has vaults, not folders).
    let mut vault_names: Vec<String> = Vec::new();
    for item in &vault.items {
        let name = item.folder.clone().unwrap_or_else(|| "Personal".into());
        if !vault_names.contains(&name) {
            vault_names.push(name);
        }
    }
    if vault_names.is_empty() {
        vault_names.push("Personal".into());
    }

    let mut vaults = Map::new();
    for (vidx, vname) in vault_names.iter().enumerate() {
        let mut items = Vec::new();
        for (idx, item) in vault
            .items
            .iter()
            .enumerate()
            .filter(|(_, i)| i.folder.as_deref().unwrap_or("Personal") == vname)
        {
            let mut extra_fields = Vec::new();
            for f in &item.fields {
                extra_fields.push(json!({
                    "fieldName": f.name,
                    "type": if f.concealed { "hidden" } else { "text" },
                    "data": {"content": f.value},
                }));
            }
            if !item.tags.is_empty() {
                extra_fields.push(json!({
                    "fieldName": "tags",
                    "type": "text",
                    "data": {"content": item.tags.join(", ")},
                }));
            }

            let (type_str, content) = match item.item_type {
                ItemType::SecureNote => ("note", json!({})),
                ItemType::Card => {
                    let c = item.card.clone().unwrap_or_default();
                    let expiration = match (&c.exp_month, &c.exp_year) {
                        (Some(m), Some(y)) => format!("{:0>2}-{}", m, four_digit_year(y)),
                        _ => String::new(),
                    };
                    (
                        "creditCard",
                        json!({
                            "cardholderName": c.cardholder_name.unwrap_or_default(),
                            "cardType": 0,
                            "number": c.number.unwrap_or_default(),
                            "verificationNumber": c.code.unwrap_or_default(),
                            "expirationDate": expiration,
                            "pin": "",
                        }),
                    )
                }
                ItemType::Identity => {
                    let id = item.identity.clone().unwrap_or_default();
                    (
                        "identity",
                        json!({
                            "fullName": id.full_name.unwrap_or_default(),
                            "email": id.email.unwrap_or_default(),
                            "phoneNumber": id.phone.unwrap_or_default(),
                            "streetAddress": id.address1.unwrap_or_default(),
                            "floor": id.address2.unwrap_or_default(),
                            "city": id.city.unwrap_or_default(),
                            "stateOrProvince": id.state.unwrap_or_default(),
                            "zipOrPostalCode": id.zip.unwrap_or_default(),
                            "countryOrRegion": id.country.unwrap_or_default(),
                        }),
                    )
                }
                ItemType::Login => {
                    let l = item.login.clone().unwrap_or_default();
                    let mut passkeys = Vec::new();
                    for pk in &l.passkeys {
                        if pk.provider.as_deref() == Some("protonpass") {
                            if let Some(raw) = &pk.provider_data {
                                passkeys.push(raw.clone());
                                continue;
                            }
                        }
                        report.warn(
                            Some(&item.title),
                            format!(
                                "passkey for '{}' comes from another provider and cannot be converted into Proton Pass's internal key encoding; re-register it after migrating",
                                pk.rp_id.as_deref().unwrap_or("unknown site")
                            ),
                        );
                    }
                    (
                        "login",
                        json!({
                            "itemEmail": l.email.clone().unwrap_or_default(),
                            "itemUsername": l.username.clone().unwrap_or_default(),
                            "password": l.password.clone().unwrap_or_default(),
                            "urls": l.uris,
                            "totpUri": l.totp.clone().unwrap_or_default(),
                            "passkeys": passkeys,
                        }),
                    )
                }
            };

            items.push(json!({
                "itemId": format!("pwmigrate-item-{idx:08}"),
                "shareId": format!("pwmigrate-share-{vidx:08}"),
                "data": {
                    "metadata": {
                        "name": item.title,
                        "note": item.notes.clone().unwrap_or_default(),
                        "itemUuid": format!("{idx:08}"),
                    },
                    "extraFields": extra_fields,
                    "type": type_str,
                    "content": content,
                },
                "state": 1,
                "aliasEmail": Value::Null,
                "contentFormatVersion": 6,
                "createTime": item.created.unwrap_or(0),
                "modifyTime": item.modified.or(item.created).unwrap_or(0),
                "pinned": item.favorite,
            }));
        }
        vaults.insert(
            format!("pwmigrate-share-{vidx:08}"),
            json!({
                "name": vname,
                "description": "",
                "display": {"color": 0, "icon": 0},
                "items": items,
            }),
        );
    }

    let out = json!({
        "version": "1.0.0-pwmigrate",
        "userId": "pwmigrate",
        "encrypted": false,
        "vaults": vaults,
    });
    Ok(serde_json::to_string_pretty(&out)?)
}

/// Non-empty string field of a JSON object.
fn nes(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// Proton stores card expiration as "MM-YYYY" (older exports "MMYYYY").
fn split_expiration(s: &str) -> (Option<String>, Option<String>) {
    let s = s.trim();
    if s.is_empty() {
        return (None, None);
    }
    if let Some((m, y)) = s.split_once(['-', '/']) {
        return (
            Some(m.trim_start_matches('0').to_string()),
            Some(y.to_string()),
        );
    }
    if s.len() == 6 && s.chars().all(|c| c.is_ascii_digit()) {
        return (
            Some(s[..2].trim_start_matches('0').to_string()),
            Some(s[2..].to_string()),
        );
    }
    (Some(s.to_string()), None)
}

fn four_digit_year(y: &str) -> String {
    if y.len() == 2 {
        format!("20{y}")
    } else {
        y.to_string()
    }
}
