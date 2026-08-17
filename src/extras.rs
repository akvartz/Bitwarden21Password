//! Structured handling of "misc" data that a target format cannot hold.
//!
//! When exporting to a format without custom-field support (most CSV formats),
//! leftover data is appended to the item's notes as a clearly delimited block:
//!
//! ```text
//! ---- pwmigrate extras ----
//! Member number: 12345
//! Security question: first pet
//! ```
//!
//! Importers parse this block back out into proper custom fields, so a
//! round-trip through a lossy format still recovers the data structurally.
//! This is deliberately deterministic — vault contents are secrets and are
//! never sent through an LLM or any external service.

use crate::model::{CustomField, Item};

pub const EXTRAS_HEADER: &str = "---- pwmigrate extras ----";

/// Serialize custom fields (and other unrepresentable scraps) into a notes
/// appendix. Returns the combined notes value.
pub fn fold_into_notes(notes: Option<&str>, extras: &[CustomField]) -> Option<String> {
    let base = notes.unwrap_or("").trim_end().to_string();
    if extras.is_empty() {
        return if base.is_empty() { None } else { Some(base) };
    }
    let mut out = base;
    if !out.is_empty() {
        out.push_str("\n\n");
    }
    out.push_str(EXTRAS_HEADER);
    for f in extras {
        out.push('\n');
        // Escape newlines inside values so the block stays line-oriented.
        let value = f.value.replace('\n', "\\n");
        out.push_str(&format!("{}: {}", f.name, value));
    }
    Some(out)
}

/// Split a notes value into (plain notes, parsed custom fields), undoing
/// `fold_into_notes`. Notes without an extras block pass through unchanged.
pub fn unfold_from_notes(notes: Option<&str>) -> (Option<String>, Vec<CustomField>) {
    let Some(notes) = notes else {
        return (None, Vec::new());
    };
    let Some(pos) = notes.find(EXTRAS_HEADER) else {
        let trimmed = notes.trim_end();
        return (
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            },
            Vec::new(),
        );
    };
    let (head, tail) = notes.split_at(pos);
    let mut fields = Vec::new();
    for line in tail[EXTRAS_HEADER.len()..].lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(": ") {
            fields.push(CustomField::new(name, value.replace("\\n", "\n")));
        } else if let Some((name, value)) = line.split_once(':') {
            fields.push(CustomField::new(
                name.trim(),
                value.trim().replace("\\n", "\n"),
            ));
        } else {
            fields.push(CustomField::new("note", line));
        }
    }
    let head = head.trim_end();
    (
        if head.is_empty() {
            None
        } else {
            Some(head.to_string())
        },
        fields,
    )
}

/// Well-known field names produced by `overflow_fields`, pulled back out of a
/// parsed extras block on import so lossy round-trips restore structure.
#[derive(Debug, Default)]
pub struct Recovered {
    pub folder: Option<String>,
    pub totp: Option<String>,
    pub email: Option<String>,
    pub urls: Vec<String>,
    pub tags: Vec<String>,
}

pub fn recover_special_fields(fields: &mut Vec<CustomField>) -> Recovered {
    let mut r = Recovered::default();
    fields.retain(|f| match f.name.as_str() {
        "folder" if r.folder.is_none() => {
            r.folder = Some(f.value.clone());
            false
        }
        "totp" if r.totp.is_none() => {
            r.totp = Some(f.value.clone());
            false
        }
        "email" if r.email.is_none() => {
            r.email = Some(f.value.clone());
            false
        }
        "url" => {
            r.urls.push(f.value.clone());
            false
        }
        "tags" => {
            r.tags.extend(
                f.value
                    .split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty()),
            );
            false
        }
        _ => true,
    });
    r
}

/// Collect everything on `item` that a plain login-CSV format cannot express,
/// as custom fields destined for the notes appendix.
pub fn overflow_fields(
    item: &Item,
    target_has_folder: bool,
    target_has_totp: bool,
) -> Vec<CustomField> {
    let mut extras: Vec<CustomField> = item.fields.clone();

    if !item.tags.is_empty() {
        extras.push(CustomField::new("tags", item.tags.join(", ")));
    }
    if !target_has_folder {
        if let Some(folder) = &item.folder {
            if !folder.is_empty() {
                extras.push(CustomField::new("folder", folder.clone()));
            }
        }
    }
    if let Some(login) = &item.login {
        if !target_has_totp {
            if let Some(totp) = &login.totp {
                extras.push(CustomField::new("totp", totp.clone()));
            }
        }
        // Secondary URLs beyond the first.
        for uri in login.uris.iter().skip(1) {
            extras.push(CustomField::new("url", uri.clone()));
        }
        // Distinct email alongside username.
        if login.username.as_deref().is_some_and(|u| !u.is_empty()) {
            if let Some(email) = &login.email {
                if !email.is_empty() && Some(email.as_str()) != login.username.as_deref() {
                    extras.push(CustomField::new("email", email.clone()));
                }
            }
        }
    }
    extras.extend(card_identity_fields(item));
    extras
}

/// Flatten card and identity details into custom fields, for formats that
/// only understand logins.
pub fn card_identity_fields(item: &Item) -> Vec<CustomField> {
    let mut extras = Vec::new();
    if let Some(card) = &item.card {
        for (name, v) in [
            ("cardholder name", &card.cardholder_name),
            ("card number", &card.number),
            ("card brand", &card.brand),
            ("card exp month", &card.exp_month),
            ("card exp year", &card.exp_year),
            ("card security code", &card.code),
        ] {
            if let Some(v) = v {
                if !v.is_empty() {
                    extras.push(CustomField::new(name, v.clone()));
                }
            }
        }
    }
    if let Some(id) = &item.identity {
        for (name, v) in [
            ("full name", &id.full_name),
            ("identity email", &id.email),
            ("phone", &id.phone),
            ("address line 1", &id.address1),
            ("address line 2", &id.address2),
            ("city", &id.city),
            ("state", &id.state),
            ("zip", &id.zip),
            ("country", &id.country),
        ] {
            if let Some(v) = v {
                if !v.is_empty() {
                    extras.push(CustomField::new(name, v.clone()));
                }
            }
        }
    }
    extras
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_notes_extras() {
        let fields = vec![
            CustomField::new("Member number", "12345"),
            CustomField::new("PIN", "9876"),
            CustomField::new("multi", "line one\nline two"),
        ];
        let folded = fold_into_notes(Some("my note"), &fields).unwrap();
        let (notes, parsed) = unfold_from_notes(Some(&folded));
        assert_eq!(notes.as_deref(), Some("my note"));
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].name, "Member number");
        assert_eq!(parsed[0].value, "12345");
        assert!(parsed[1].concealed, "PIN should be classified as concealed");
        assert_eq!(parsed[2].value, "line one\nline two");
    }

    #[test]
    fn plain_notes_pass_through() {
        let (notes, parsed) = unfold_from_notes(Some("just a note"));
        assert_eq!(notes.as_deref(), Some("just a note"));
        assert!(parsed.is_empty());
    }
}
