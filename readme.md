# OTP-Cli
- [OTP-Cli](#otp-cli)
  - [Building](#building)
  - [Installing](#installing)
  - [Usage](#usage)
    - [Import from tokens list](#import-from-tokens-list)
    - [Import from FreeOTP backup](#import-from-freeotp-backup)
    - [Import from Google Authenticator backup](#import-from-google-authenticator-backup)
  - [Development tips](#development-tips)

Tired of grabbing your phone every time you need to enter OTP code? OTP-cli to the rescue!
This app allows you to parse backup file with OTP tokens from authenticator (or directly add token urls) to local database and then print OTP codes in terminal.

Supported authenticators:
- ☑ FreeOTP
- ☑ Google Authenticator

## Building
You will need the following to build the app:
- Rust with Cargo (https://www.rust-lang.org/)

Run `cargo build --release` to build the app, this will produce executable binary `./target/release/otp-cli` (or `otp-cli.exe` for Windows).

## Installing
You may build the project & place executable binary to desired location or run `cargo install --path .` from app directory to build & install it in one step, this way binary will be placed in directory specified by cargo settings (usually `$HOME/.cargo`).

## Usage
First you'll need to add OTP tokens to local database, that will be created in specified location as file in TOML format. You may add tokens from authenticator backup (see supported authenticators) or from list of token urls (`otpauth://...`) using `convert` command with parameters specific for backup type (see below).

For adding tokens app will ask you to provide master password for securing token keys in database, you'll need to provide this password every time you want to use OTP token.

If database exists on specified path, app will try to open it and update with new tokens. Note that it will not check if master password is correct for existing tokens, so be sure to use the same password for all tokens in file.

You may open database via text editor and leave only those tokens you are interested in, change token names to convenient ones for futher invocation: each token is placed in config section `[token.{name}]`, change the `{name}` as you wish.

To print OTP code invoke `use` command specifying token name, for example: 
```
otp-cli ./otp-keys.toml use -t my_token_name
```

Also you may use interactive mode that allows you to list existing tokens and get codes from them without entering password every time:
```
otp-cli ./otp-keys.toml start
```

Below are instructions for ingesting tokens from different backup types.

### Import from tokens list
You can add new tokens urls directly to database. Scan token's QR to obtain token url (starts with `otpauth://...`), then create text file somewhere (for example with name `new_tokens.txt`) and copy url here - you may add as many urls as you want, each on new line. Then provide this file to app:

```
otp-cli ./otp-keys.toml convert -t tokens-list -i new_tokens.txt
```

### Import from FreeOTP backup
FreeOTP allows to download backup file via menu, usually named `externalBackup`. Copy this file somewhere and provide it to app:

```
otp-cli ./otp-keys.toml convert -t free-otp -i externalBackup
```

### Import from Google Authenticator backup
Google authenticator allows doing backups of tokens via QR codes. Scan QR code to retrieve data, you should see string that looks like this: `otpauth-migration://offline?data={some_base64_encoded_data}`. Create text file somewhere (for example with name `google_auth_tokens.txt`) and copy this string here - you may copy as many strings as you want, each on new line. Then provide this file to app:

```
otp-cli ./otp-keys.toml convert -t google-auth -i google_auth_tokens.txt
```

## Development tips
- to add support for importing another authenticator backup type you may have a look to Aegis (https://github.com/beemdevelopment/Aegis): they support a lot of them