//! Canonical vault model.
//!
//! Every importer parses its source format into this model and every exporter
//! serializes from it. Anything a password manager can hold should be
//! representable here; format-specific extras that have no canonical home are
//! kept in `CustomField`s or in `Passkey::provider_data` so that round-trips
//! are as lossless as possible.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Vault {
    pub items: Vec<Item>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ItemType {
    #[default]
    Login,
    SecureNote,
    Card,
    Identity,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Item {
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub item_type: ItemType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<Login>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<Card>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<CustomField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Unix timestamp (seconds), if the source format provides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<i64>,
    /// Bitwarden-style "master password reprompt" flag.
    #[serde(default)]
    pub reprompt: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Login {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Some managers (Proton Pass) distinguish email from username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// TOTP as an otpauth:// URI or a bare base32 secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uris: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passkeys: Vec<Passkey>,
}

impl Login {
    pub fn is_empty(&self) -> bool {
        self.username.is_none()
            && self.email.is_none()
            && self.password.is_none()
            && self.totp.is_none()
            && self.uris.is_empty()
            && self.passkeys.is_empty()
    }

    /// Username with email as a fallback, for formats with a single field.
    pub fn username_or_email(&self) -> Option<&str> {
        self.username
            .as_deref()
            .filter(|s| !s.is_empty())
            .or(self.email.as_deref())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    /// Should be masked in UIs (PINs, secret answers, keys...).
    #[serde(default)]
    pub concealed: bool,
}

impl CustomField {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        let concealed = looks_concealed(&name);
        CustomField {
            name,
            value: value.into(),
            concealed,
        }
    }
}

/// Heuristic classification of a custom field name as secret-bearing.
/// Deterministic on purpose: secrets must never be piped through an LLM.
pub fn looks_concealed(name: &str) -> bool {
    let n = name.to_lowercase();
    const HINTS: &[&str] = &[
        "password",
        "passwort",
        "passphrase",
        "pin",
        "secret",
        "token",
        "cvv",
        "cvc",
        "security code",
        "private key",
        "api key",
        "apikey",
        "recovery",
        "seed",
        "backup code",
        "otp",
        "2fa",
        "totp",
        "mfa",
    ];
    HINTS.iter().any(|h| n.contains(h))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Card {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cardholder_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brand: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp_month: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp_year: Option<String>,
    /// CVV / CVC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Identity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address1: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address2: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// A WebAuthn passkey (discoverable FIDO2 credential).
///
/// The normalized fields follow Bitwarden's unencrypted JSON export
/// (`fido2Credentials`), which stores the private key as base64url PKCS#8 in
/// `key_value`. Other providers (e.g. Proton Pass) wrap the key material in a
/// proprietary blob; that blob is preserved verbatim in `provider_data` so a
/// same-format round-trip is lossless even when cross-provider transfer of the
/// private key is not possible.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Passkey {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    /// Relying party ID, e.g. "github.com".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_curve: Option<String>,
    /// Base64url-encoded PKCS#8 private key (Bitwarden convention).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discoverable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<String>,
    /// Which provider `provider_data` came from ("protonpass", ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Raw provider-specific passkey record, preserved for lossless
    /// same-provider round-trips.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_data: Option<serde_json::Value>,
}

impl Passkey {
    /// True when the portable private key material is present (Bitwarden style).
    pub fn has_portable_key(&self) -> bool {
        self.key_value.as_deref().is_some_and(|k| !k.is_empty())
    }
}
