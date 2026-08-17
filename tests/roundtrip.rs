//! End-to-end tests: import fixtures, convert between formats, and verify
//! that data survives (or is reported when it can't).

use pwmigrate::formats::{detect, Format};
use pwmigrate::model::{ItemType, Vault};
use pwmigrate::report::Report;
use pwmigrate::verify;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn import(format: Format, data: &str) -> (Vault, Report) {
    let mut report = Report::new();
    let vault = format.import(data, &mut report).expect("import failed");
    (vault, report)
}

fn export(format: Format, vault: &Vault) -> (String, Report) {
    let mut report = Report::new();
    let out = format.export(vault, &mut report).expect("export failed");
    (out, report)
}

#[test]
fn detects_formats() {
    assert_eq!(
        detect(&fixture("bitwarden.csv"), "x.csv").unwrap(),
        Format::BitwardenCsv
    );
    assert_eq!(
        detect(&fixture("bitwarden.json"), "x.json").unwrap(),
        Format::BitwardenJson
    );
    assert_eq!(
        detect(&fixture("protonpass.json"), "x.json").unwrap(),
        Format::ProtonPassJson
    );
    assert_eq!(
        detect(&fixture("lastpass.csv"), "x.csv").unwrap(),
        Format::LastPassCsv
    );
    assert_eq!(
        detect(&fixture("chrome.csv"), "x.csv").unwrap(),
        Format::ChromeCsv
    );
}

#[test]
fn bitwarden_csv_import() {
    let (vault, _) = import(Format::BitwardenCsv, &fixture("bitwarden.csv"));
    assert_eq!(vault.items.len(), 3);
    let gh = &vault.items[0];
    assert_eq!(gh.title, "GitHub");
    assert_eq!(gh.folder.as_deref(), Some("Work"));
    assert!(gh.favorite);
    assert_eq!(gh.fields.len(), 2);
    assert_eq!(gh.fields[0].name, "employee id");
    assert!(gh.fields[1].concealed, "PIN should be concealed");
    let login = gh.login.as_ref().unwrap();
    assert_eq!(login.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    assert_eq!(vault.items[2].item_type, ItemType::SecureNote);
}

#[test]
fn bitwarden_csv_to_1password_and_back() {
    let (vault, _) = import(Format::BitwardenCsv, &fixture("bitwarden.csv"));
    let (op_csv, _) = export(Format::OnePasswordCsv, &vault);
    let (back, _) = import(Format::OnePasswordCsv, &op_csv);

    assert_eq!(back.items.len(), 3);
    let gh = &back.items[0];
    assert_eq!(gh.title, "GitHub");
    let login = gh.login.as_ref().unwrap();
    assert_eq!(login.username.as_deref(), Some("octocat"));
    assert_eq!(login.password.as_deref(), Some("hunter2"));
    assert_eq!(login.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    assert_eq!(login.uris, vec!["https://github.com".to_string()]);
    // Custom fields survive the trip through the notes block.
    assert!(gh
        .fields
        .iter()
        .any(|f| f.name == "employee id" && f.value == "4711"));
    assert!(gh
        .fields
        .iter()
        .any(|f| f.name == "PIN" && f.value == "1234"));
    // Original notes survive too.
    assert_eq!(gh.notes.as_deref(), Some("my work account"));
    // Folder came back via 1Password tags.
    assert!(gh.tags.contains(&"Work".to_string()));
}

#[test]
fn bitwarden_json_passkey_roundtrip() {
    let (vault, _) = import(Format::BitwardenJson, &fixture("bitwarden.json"));
    assert_eq!(vault.items.len(), 2);
    let gh = &vault.items[0];
    let login = gh.login.as_ref().unwrap();
    assert_eq!(login.passkeys.len(), 1);
    let pk = &login.passkeys[0];
    assert_eq!(pk.rp_id.as_deref(), Some("github.com"));
    assert!(pk.has_portable_key());
    assert_eq!(pk.counter, Some(0));
    assert_eq!(pk.discoverable, Some(true));

    // Card item parsed structurally.
    assert_eq!(vault.items[1].item_type, ItemType::Card);
    let card = vault.items[1].card.as_ref().unwrap();
    assert_eq!(card.number.as_deref(), Some("4111111111111111"));

    // Round-trip: passkey must survive byte-identical in meaning.
    let (json, report) = export(Format::BitwardenJson, &vault);
    assert!(
        !report
            .notes
            .iter()
            .any(|n| n.message.contains("NOT exported")),
        "portable passkey must not be dropped"
    );
    let (back, _) = import(Format::BitwardenJson, &json);
    let pk2 = &back.items[0].login.as_ref().unwrap().passkeys[0];
    assert_eq!(pk2.key_value, pk.key_value);
    assert_eq!(pk2.credential_id, pk.credential_id);
    assert_eq!(pk2.user_handle, pk.user_handle);
}

#[test]
fn protonpass_json_import_and_roundtrip() {
    let (vault, _) = import(Format::ProtonPassJson, &fixture("protonpass.json"));
    assert_eq!(vault.items.len(), 3);
    let gh = &vault.items[0];
    assert_eq!(gh.title, "GitHub");
    assert!(gh.favorite, "pinned should map to favorite");
    let login = gh.login.as_ref().unwrap();
    assert_eq!(login.username.as_deref(), Some("octocat"));
    assert_eq!(login.email.as_deref(), Some("octo@example.com"));
    assert_eq!(login.uris.len(), 2);
    assert_eq!(login.passkeys.len(), 1);
    assert!(gh
        .fields
        .iter()
        .any(|f| f.name == "recovery code" && f.concealed));

    // Card expiration is split.
    let card = vault.items[2].card.as_ref().unwrap();
    assert_eq!(card.exp_month.as_deref(), Some("4"));
    assert_eq!(card.exp_year.as_deref(), Some("2030"));
    // Card PIN preserved as concealed custom field.
    assert!(vault.items[2]
        .fields
        .iter()
        .any(|f| f.name == "PIN" && f.value == "9876"));

    // Proton -> Proton keeps the passkey blob verbatim.
    let (json, _) = export(Format::ProtonPassJson, &vault);
    let (back, _) = import(Format::ProtonPassJson, &json);
    let pk = &back.items[0].login.as_ref().unwrap().passkeys[0];
    assert_eq!(pk.provider.as_deref(), Some("protonpass"));
    assert_eq!(
        pk.provider_data.as_ref().unwrap()["content"],
        serde_json::json!("cHJvdG9uLXBhc3NrZXktYmxvYg==")
    );
}

#[test]
fn proton_passkey_to_bitwarden_warns_and_drops() {
    let (vault, _) = import(Format::ProtonPassJson, &fixture("protonpass.json"));
    let (json, report) = export(Format::BitwardenJson, &vault);
    // Proton's passkey private key is in a proprietary blob: must warn.
    assert!(report
        .notes
        .iter()
        .any(|n| n.message.contains("passkey") && n.message.contains("NOT exported")));
    let (back, _) = import(Format::BitwardenJson, &json);
    assert!(back.items[0].login.as_ref().unwrap().passkeys.is_empty());
    // Everything else made it.
    let login = back.items[0].login.as_ref().unwrap();
    assert_eq!(login.password.as_deref(), Some("hunter2"));
    assert!(login.totp.as_deref().unwrap().starts_with("otpauth://"));
}

#[test]
fn lastpass_secure_note() {
    let (vault, _) = import(Format::LastPassCsv, &fixture("lastpass.csv"));
    assert_eq!(vault.items.len(), 3);
    assert_eq!(vault.items[1].item_type, ItemType::SecureNote);
    assert_eq!(vault.items[1].notes.as_deref(), Some("my secure note body"));
    let (lp, _) = export(Format::LastPassCsv, &vault);
    assert!(lp.contains("http://sn"));
}

#[test]
fn chrome_lossy_roundtrip_recovers_extras() {
    let (vault, _) = import(Format::BitwardenCsv, &fixture("bitwarden.csv"));
    let (chrome, _) = export(Format::ChromeCsv, &vault);
    let (back, _) = import(Format::ChromeCsv, &chrome);
    let gh = &back.items[0];
    // Folder and TOTP have no Chrome columns but come back via the notes block.
    assert_eq!(gh.folder.as_deref(), Some("Work"));
    assert_eq!(
        gh.login.as_ref().unwrap().totp.as_deref(),
        Some("JBSWY3DPEHPK3PXP")
    );
    assert!(gh.fields.iter().any(|f| f.name == "employee id"));
}

#[test]
fn all_formats_roundtrip_core_login() {
    // A minimal login must survive a round-trip through every format.
    let (vault, _) = import(Format::ChromeCsv, &fixture("chrome.csv"));
    for format in pwmigrate::formats::ALL_FORMATS {
        let (data, _) = export(*format, &vault);
        let (back, _) = import(*format, &data);
        assert_eq!(back.items.len(), 2, "item count changed in {}", format.id());
        let login = back.items[0].login.as_ref().unwrap_or_else(|| {
            panic!("{}: login lost", format.id());
        });
        assert_eq!(
            login.username_or_email(),
            Some("octocat"),
            "{}",
            format.id()
        );
        assert_eq!(
            login.password.as_deref(),
            Some("hunter2"),
            "{}",
            format.id()
        );
        assert_eq!(
            login.uris.first().map(String::as_str),
            Some("https://github.com"),
            "{}",
            format.id()
        );
    }
}

#[test]
fn keeper_csv_roundtrip() {
    let (vault, _) = import(Format::BitwardenCsv, &fixture("bitwarden.csv"));
    let (keeper, _) = export(Format::KeeperCsv, &vault);
    let (back, _) = import(Format::KeeperCsv, &keeper);
    let gh = &back.items[0];
    assert_eq!(gh.title, "GitHub");
    assert_eq!(gh.folder.as_deref(), Some("Work"));
    let login = gh.login.as_ref().unwrap();
    assert_eq!(login.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    assert!(gh.fields.iter().any(|f| f.name == "employee id"));
}

#[test]
fn canonical_json_is_lossless() {
    let (vault, _) = import(Format::ProtonPassJson, &fixture("protonpass.json"));
    let (json, _) = export(Format::CanonicalJson, &vault);
    let (back, _) = import(Format::CanonicalJson, &json);
    assert_eq!(back.items.len(), vault.items.len());
    let pk_before = &vault.items[0].login.as_ref().unwrap().passkeys[0];
    let pk_after = &back.items[0].login.as_ref().unwrap().passkeys[0];
    assert_eq!(pk_before.provider_data, pk_after.provider_data);
    assert_eq!(back.items[0].created, vault.items[0].created);
}

#[test]
fn verify_flags_problems() {
    let bad = "\
name,url,username,password,note
No Password,https://ok.example.com,alice,,
Bad Url,http site.com,bob,pw,
Bad Totp,https://c.example.com,carol,pw,
";
    let (mut vault, _) = import(Format::ChromeCsv, bad);
    vault.items[2].login.as_mut().unwrap().totp = Some("not!!base32".into());
    let mut report = Report::new();
    verify::validate(&vault, &mut report);
    let text = report.render().unwrap();
    assert!(text.contains("neither a password nor a passkey"));
    assert!(text.contains("suspicious URL"));
    assert!(text.contains("TOTP"));
}

#[test]
fn verify_flags_duplicates_and_luhn() {
    let dup = "\
name,url,username,password,note
Same,https://x.example.com,alice,pw,
Same,https://x.example.com,alice,pw2,
";
    let (vault, _) = import(Format::ChromeCsv, dup);
    let mut report = Report::new();
    verify::validate(&vault, &mut report);
    assert!(report.render().unwrap().contains("duplicate"));

    let (vault, _) = import(Format::BitwardenJson, &fixture("bitwarden.json"));
    let mut report = Report::new();
    verify::validate(&vault, &mut report);
    // Fixture card number is Luhn-valid: no card warnings.
    assert!(!report.render().unwrap_or_default().contains("Luhn"));
}
