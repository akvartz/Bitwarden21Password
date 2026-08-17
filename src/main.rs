//! pwmigrate — universal password manager migration tool.
//!
//! Converts vault export files between popular password manager formats
//! through a canonical internal model, verifies files before import, and
//! reports exactly what could and could not be carried over.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use pwmigrate::formats::{self, Format, ALL_FORMATS};
use pwmigrate::model::ItemType;
use pwmigrate::report::{self, Report};
use pwmigrate::verify;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "pwmigrate",
    version,
    about = "Universal password manager migration: convert, verify and inspect vault exports.",
    after_help = "Run `pwmigrate formats` to list supported formats.\n\
                  SECURITY: exported files contain your secrets in plain text — \
                  keep them on an encrypted disk and delete them (securely) after migrating."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Convert a vault export from one format to another.
    Convert {
        /// Input file (a password manager export).
        #[arg(short, long)]
        input: PathBuf,
        /// Output file to write.
        #[arg(short, long)]
        output: PathBuf,
        /// Source format (auto-detected when omitted). See `pwmigrate formats`.
        #[arg(short = 'f', long = "from")]
        from: Option<String>,
        /// Target format. See `pwmigrate formats`.
        #[arg(short = 't', long = "to")]
        to: String,
        /// Also run content validation on the imported data.
        #[arg(long)]
        verify: bool,
    },
    /// Check that a file is a well-formed export and sanity-check its contents.
    Verify {
        /// File to verify.
        #[arg(short, long)]
        input: PathBuf,
        /// Format (auto-detected when omitted).
        #[arg(short = 'f', long = "from")]
        from: Option<String>,
    },
    /// Summarize what a vault export contains (no secrets are printed).
    Inspect {
        /// File to inspect.
        #[arg(short, long)]
        input: PathBuf,
        /// Format (auto-detected when omitted).
        #[arg(short = 'f', long = "from")]
        from: Option<String>,
    },
    /// List supported formats.
    Formats,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Convert {
            input,
            output,
            from,
            to,
            verify,
        } => cmd_convert(&input, &output, from.as_deref(), &to, verify),
        Command::Verify { input, from } => cmd_verify(&input, from.as_deref()),
        Command::Inspect { input, from } => cmd_inspect(&input, from.as_deref()),
        Command::Formats => {
            println!("supported formats (use with --from / --to):\n");
            for f in ALL_FORMATS {
                println!("  {:<16} {}", f.id(), f.description());
            }
            println!(
                "\nAliases like 'bitwarden', 'proton', 'chrome', 'edge', 'safari', 'keepass' \
                 also work. Passkeys travel via bitwarden-json, protonpass-json and \
                 pwmigrate-json only."
            );
            Ok(())
        }
    }
}

fn load(input: &Path, from: Option<&str>) -> Result<(Format, String)> {
    let data = std::fs::read_to_string(input)
        .with_context(|| format!("cannot read {}", input.display()))?;
    let format = match from {
        Some(id) => Format::from_id(id)
            .with_context(|| format!("unknown format '{id}' — run `pwmigrate formats`"))?,
        None => {
            let f = formats::detect(&data, &input.to_string_lossy())?;
            eprintln!("detected input format: {}", f.id());
            f
        }
    };
    Ok((format, data))
}

fn cmd_convert(
    input: &Path,
    output: &Path,
    from: Option<&str>,
    to: &str,
    run_verify: bool,
) -> Result<()> {
    let target = Format::from_id(to)
        .with_context(|| format!("unknown target format '{to}' — run `pwmigrate formats`"))?;
    let (source, data) = load(input, from)?;

    let mut report = Report::new();
    let vault = source
        .import(&data, &mut report)
        .with_context(|| format!("failed to import {} as {}", input.display(), source.id()))?;

    if run_verify {
        verify::validate(&vault, &mut report);
    }

    let out = target
        .export(&vault, &mut report)
        .with_context(|| format!("failed to export as {}", target.id()))?;
    std::fs::write(output, out).with_context(|| format!("cannot write {}", output.display()))?;

    if let Some(rendered) = report.render() {
        eprint!("{rendered}");
    }
    eprintln!(
        "converted {} item(s): {} ({}) -> {} ({}){}",
        vault.items.len(),
        input.display(),
        source.id(),
        output.display(),
        target.id(),
        summarize_severities(&report),
    );
    eprintln!(
        "reminder: {} contains plain-text secrets — delete it after importing.",
        output.display()
    );
    Ok(())
}

fn cmd_verify(input: &Path, from: Option<&str>) -> Result<()> {
    let (format, data) = load(input, from)?;
    let mut report = Report::new();
    match format.import(&data, &mut report) {
        Ok(vault) => {
            verify::validate(&vault, &mut report);
            if let Some(rendered) = report.render() {
                print!("{rendered}");
            }
            let warnings = report.count(report::Severity::Warning);
            if warnings > 0 {
                println!(
                    "{}: structure OK as {} ({} items, {} warning(s))",
                    input.display(),
                    format.id(),
                    vault.items.len(),
                    warnings
                );
            } else {
                println!(
                    "{}: OK as {} ({} items)",
                    input.display(),
                    format.id(),
                    vault.items.len()
                );
            }
            Ok(())
        }
        Err(e) => {
            if let Some(rendered) = report.render() {
                print!("{rendered}");
            }
            println!("{}: INVALID as {}: {e:#}", input.display(), format.id());
            std::process::exit(2);
        }
    }
}

fn cmd_inspect(input: &Path, from: Option<&str>) -> Result<()> {
    let (format, data) = load(input, from)?;
    let mut report = Report::new();
    let vault = format.import(&data, &mut report)?;

    let count = |t: ItemType| vault.items.iter().filter(|i| i.item_type == t).count();
    let logins = count(ItemType::Login);
    let notes = count(ItemType::SecureNote);
    let cards = count(ItemType::Card);
    let identities = count(ItemType::Identity);
    let with_totp = vault
        .items
        .iter()
        .filter(|i| i.login.as_ref().and_then(|l| l.totp.as_ref()).is_some())
        .count();
    let passkeys: usize = vault
        .items
        .iter()
        .filter_map(|i| i.login.as_ref())
        .map(|l| l.passkeys.len())
        .sum();
    let custom_fields: usize = vault.items.iter().map(|i| i.fields.len()).sum();
    let mut folders: Vec<&str> = vault
        .items
        .iter()
        .filter_map(|i| i.folder.as_deref())
        .collect();
    folders.sort_unstable();
    folders.dedup();

    println!("{} ({})", input.display(), format.id());
    println!("  items:          {}", vault.items.len());
    println!("    logins:       {logins}");
    println!("    secure notes: {notes}");
    println!("    cards:        {cards}");
    println!("    identities:   {identities}");
    println!("  with TOTP:      {with_totp}");
    println!("  passkeys:       {passkeys}");
    println!("  custom fields:  {custom_fields}");
    println!("  folders/vaults: {}", folders.len());
    for f in folders {
        println!("    - {f}");
    }
    if let Some(rendered) = report.render() {
        eprint!("{rendered}");
    }
    Ok(())
}

fn summarize_severities(report: &Report) -> String {
    let w = report.count(report::Severity::Warning);
    let i = report.count(report::Severity::Info);
    if w == 0 && i == 0 {
        String::new()
    } else {
        format!(" — {w} warning(s), {i} note(s)")
    }
}
