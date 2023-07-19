# Bitwarden to 1Password CSV Converter

This is a command-line tool that converts CSV files from Bitwarden format to 1Password format. It provides a simple way to migrate your password data from Bitwarden to 1Password.

## Features

- Converts CSV files from Bitwarden format to 1Password format.
- Supports reverse conversion from 1Password to Bitwarden.
- Maps Bitwarden fields to corresponding 1Password fields.
- Matches fields according to the provided mapping
- Handles additional fields through the `extras` field.
- Preserves the original structure and order of records in the CSV file.

## Usage

To use the Bitwarden to 1Password CSV converter, follow these steps:

1. Ensure you have Rust installed on your machine.
2. Clone this repository
3. Open a terminal and navigate to the project directory.

### Compilation

To compile the program, use the following command:

```
cargo build --release

```

### Conversion

To convert a Bitwarden CSV file to 1Password format, use the following command:

```
./target/release/csv-converter -i <input_file.csv> -o <output_file.csv>

```

Replace `<input_file.csv>` with the path to your Bitwarden CSV file, and `<output_file.csv>` with the desired path and name for the converted 1Password CSV file.

By default, the program converts from Bitwarden to 1Password format. To perform a reverse conversion from 1Password to Bitwarden, use the `-r` or `--reverse` flag:

```
./target/release/csv-converter -i <input_file.csv> -o <output_file.csv> -r

```

### Field Mapping

The program maps the following Bitwarden fields to 1Password fields:

- `folder` maps to `Tags`
- `favorite` maps to `Favorite`
- `type` does not have a direct mapping (included in `Extras` field)
- `name` maps to `Title`
- `notes` maps to `Notes`
- `fields` does not have a direct mapping (included in `Extras` field)
- `reprompt` does not have a direct mapping (included in `Extras` field)
- `login_uri` maps to `Url`
- `login_username` maps to `Username`
- `login_password` maps to `Password`
- `login_totp` maps to `OTPAuth`

Any unmatched fields from the Bitwarden CSV file are merged into the `Extras` field using square brackets in the format `[field_name: field_value]`. 

