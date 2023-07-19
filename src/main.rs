use serde::{Deserialize, Serialize};
use structopt::StructOpt;
use csv::{Reader};

use std::process;

#[derive(Debug, Deserialize, Serialize)]
struct Bitwarden {
    folder: Option<String>,
    favorite: Option<String>,
    #[serde(rename = "type")]
    type_field: Option<String>,
    name: Option<String>,
    notes: Option<String>,
    fields: Option<String>,
    reprompt: Option<String>,
    login_uri: Option<String>,
    login_username: Option<String>,
    login_password: Option<String>,
    login_totp: Option<String>,
    extras: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct OnePassword {
    Title: Option<String>,
    Url: Option<String>,
    Username: Option<String>,
    Password: Option<String>,
    OTPAuth: Option<String>,
    Favorite: Option<String>,
    Archived: Option<String>,
    Tags: Option<String>,
    Notes: Option<String>,
    extras: Option<String>,
}

#[derive(Debug, StructOpt)]
#[structopt(name = "csv-converter", about = "Converts CSV files from Bitwarden format to 1Password format.")]
struct Opt {
    /// Input file
    #[structopt(short = "i", long = "input", parse(from_os_str))]
    input: std::path::PathBuf,

    /// Output file
    #[structopt(short = "o", long = "output", parse(from_os_str))]
    output: std::path::PathBuf,

    /// Reverse the conversion direction. If true, convert from 1Password to Bitwarden. By default, convert from Bitwarden to 1Password.
    #[structopt(short = "r", long = "reverse")]
    reverse: bool,
}

fn main() {
    // Parse command-line arguments
    let opt = Opt::from_args();

    // Read CSV file
    let mut reader = Reader::from_path(&opt.input).unwrap_or_else(|err| {
        eprintln!("Problem opening the file: {:?}", err);
        process::exit(1);
    });

    // Write CSV file
    let mut writer = csv::Writer::from_path(&opt.output).unwrap_or_else(|err| {
        eprintln!("Problem opening the file: {:?}", err);
        process::exit(1);
    });

    // Convert records
    if opt.reverse {
        // Convert from 1Password to Bitwarden
        for result in reader.deserialize() {
            let record: OnePassword = result.unwrap();
            let converted = convert_1password_to_bitwarden(record);
            writer.serialize(converted).unwrap();
        }
    } else {
        // Convert from Bitwarden to 1Password
        for result in reader.deserialize() {
            let record: Bitwarden = result.unwrap();
            let converted = convert_bitwarden_to_1password(record);
            writer.serialize(converted).unwrap();
        }
    }

    writer.flush().unwrap();
}

fn convert_bitwarden_to_1password(record: Bitwarden) -> OnePassword {
    let mut extras = vec![
        record.favorite.map(|f| format!("[favourite:{}]", f)),
        record.reprompt.map(|r| format!("[reprompt:{}]", r)),
    ];
    extras.retain(|e| e.is_some());
    let extras = extras.into_iter().map(|e| e.unwrap()).collect::<Vec<String>>().join(", ");

    OnePassword {
        Title: record.name,
        Url: record.login_uri,
        Username: record.login_username,
        Password: record.login_password,
        OTPAuth: record.login_totp,
        Favorite: None,
        Archived: None,
        Tags: record.folder,
        Notes: record.notes,
        extras: Some(extras),
    }
}

fn convert_1password_to_bitwarden(record: OnePassword) -> Bitwarden {
    let mut extras = vec![
        record.extras,
    ];
    extras.retain(|e| e.is_some());
    let extras = extras.into_iter().map(|e| e.unwrap()).collect::<Vec<String>>().join(", ");

    Bitwarden {
        folder: record.Tags,
        favorite: Some(record.Favorite.unwrap_or_default()),
        type_field: None,
        name: record.Title,
        notes: record.Notes,
        fields: None,
        reprompt: None,
        login_uri: record.Url,
        login_username: record.Username,
        login_password: record.Password,
        login_totp: record.OTPAuth,
        extras: Some(extras),
    }
}
