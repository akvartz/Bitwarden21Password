//! Semantic validation of an imported vault, used by `pwmigrate verify`.
//!
//! Format/structure errors are caught by the importers themselves; this pass
//! checks the *content*: empty credentials, malformed URLs and TOTP secrets,
//! duplicates, and passkey completeness.

use crate::model::{ItemType, Vault};
use crate::report::Report;
use std::collections::HashMap;

pub fn validate(vault: &Vault, report: &mut Report) {
    let mut seen: HashMap<(String, String, String), usize> = HashMap::new();

    for item in &vault.items {
        let ctx = if item.title.is_empty() {
            "<untitled>"
        } else {
            item.title.as_str()
        };

        if item.title.trim().is_empty() {
            report.warn(None, "item has an empty title");
        }

        if let Some(login) = &item.login {
            if item.item_type == ItemType::Login {
                let has_secret = login.password.is_some() || !login.passkeys.is_empty();
                if !has_secret {
                    report.warn(Some(ctx), "login has neither a password nor a passkey");
                }
                if login.username_or_email().is_none() && login.password.is_some() {
                    report.info(Some(ctx), "login has a password but no username/email");
                }
            }
            for uri in &login.uris {
                if let Some(problem) = url_problem(uri) {
                    report.warn(Some(ctx), format!("suspicious URL '{uri}': {problem}"));
                }
            }
            if let Some(totp) = &login.totp {
                if let Some(problem) = totp_problem(totp) {
                    report.warn(Some(ctx), format!("TOTP value looks invalid: {problem}"));
                }
            }
            for pk in &login.passkeys {
                if pk.rp_id.is_none() {
                    report.warn(Some(ctx), "passkey is missing its relying party (rpId)");
                }
                if !pk.has_portable_key() && pk.provider_data.is_none() {
                    report.warn(
                        Some(ctx),
                        "passkey has no private key material at all; it will not work after import anywhere",
                    );
                }
            }

            // Duplicate detection on (title, username, first url).
            let key = (
                item.title.to_lowercase(),
                login.username_or_email().unwrap_or("").to_lowercase(),
                login
                    .uris
                    .first()
                    .map(|u| u.to_lowercase())
                    .unwrap_or_default(),
            );
            *seen.entry(key.clone()).or_insert(0) += 1;
            if seen[&key] == 2 {
                report.warn(
                    Some(ctx),
                    "duplicate entry (same title, username and URL appear more than once)",
                );
            }
        }

        if item.item_type == ItemType::Card {
            if let Some(card) = &item.card {
                if let Some(n) = &card.number {
                    let digits: String = n.chars().filter(|c| c.is_ascii_digit()).collect();
                    if digits.len() >= 12 && !luhn_ok(&digits) {
                        report.warn(Some(ctx), "card number fails the Luhn checksum");
                    }
                }
            }
        }
    }

    report.info(None, format!("validated {} item(s)", vault.items.len()));
}

fn url_problem(url: &str) -> Option<&'static str> {
    let u = url.trim();
    if u.is_empty() {
        return Some("empty");
    }
    if u.chars().any(char::is_whitespace) {
        return Some("contains whitespace");
    }
    if let Some((scheme, rest)) = u.split_once("://") {
        if scheme.is_empty() || rest.is_empty() {
            return Some("malformed scheme");
        }
        return None;
    }
    if u.starts_with("androidapp:") || u.contains('.') || u == "localhost" {
        return None;
    }
    Some("no scheme and no dot — probably not a URL")
}

fn totp_problem(totp: &str) -> Option<&'static str> {
    let t = totp.trim();
    if t.is_empty() {
        return Some("empty");
    }
    if let Some(rest) = t.strip_prefix("otpauth://") {
        if !rest.starts_with("totp/") && !rest.starts_with("hotp/") {
            return Some("otpauth URI is neither totp nor hotp");
        }
        if !rest.contains("secret=") {
            return Some("otpauth URI has no secret parameter");
        }
        return None;
    }
    if t.starts_with("steam://") {
        return None;
    }
    // Bare secret: base32 (spaces tolerated, '=' padding allowed at the end).
    let cleaned: String = t
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let core = cleaned.trim_end_matches('=');
    if core.is_empty() {
        return Some("empty after cleanup");
    }
    if !core
        .chars()
        .all(|c| c.is_ascii_alphabetic() && c.is_ascii_uppercase() || ('2'..='7').contains(&c))
    {
        // Try lowercase base32 too before flagging.
        if !core
            .to_uppercase()
            .chars()
            .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c))
        {
            return Some("not an otpauth:// URI and not base32");
        }
    }
    None
}

fn luhn_ok(digits: &str) -> bool {
    let mut sum = 0u32;
    for (i, c) in digits.chars().rev().enumerate() {
        let mut d = c.to_digit(10).unwrap_or(0);
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_checks() {
        assert!(totp_problem("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").is_none());
        assert!(totp_problem("JBSWY3DPEHPK3PXP").is_none());
        assert!(totp_problem("jbsw y3dp ehpk 3pxp").is_none());
        assert!(totp_problem("otpauth://totp/x?issuer=y").is_some());
        assert!(totp_problem("not!base32").is_some());
    }

    #[test]
    fn luhn() {
        assert!(luhn_ok("4111111111111111"));
        assert!(!luhn_ok("4111111111111112"));
    }

    #[test]
    fn url_checks() {
        assert!(url_problem("https://example.com").is_none());
        assert!(url_problem("example.com/login").is_none());
        assert!(url_problem("has space.com").is_some());
        assert!(url_problem("garbage").is_some());
    }
}
