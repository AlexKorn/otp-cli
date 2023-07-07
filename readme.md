# OTP-Cli
- [OTP-Cli](#otp-cli)
  - [Building](#building)
  - [Installing](#installing)
  - [Usage](#usage)
    - [New token](#new-token)
    - [FreeOTP backup](#freeotp-backup)
    - [Google authenticator backup](#google-authenticator-backup)
  - [Development tips](#development-tips)

Tired of grabbing your phone every time you need to enter otp code? Otp-cli to the rescue!
This app allows you to parse backup file with otp keys from authenticator to local database and then print otp codes in terminal.

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
First you'll need to convert backup file from authenticator to app's config format wih `convert` command, for example:
```
otp-cli convert -t free-otp -i externalBackup -o ./otp-keys.toml
```

After parsing the backup file app will ask you to provide master password for securing token keys in config, you'll need to provide this password every time you want to use otp token.

If speficied config file exists, app will try to open it and update with new keys. Note that it will not check if master password is correct for existing keys, so be sure to use the same password for all keys in file.

Then you may open config file and leave only those keys you are interested in, and change token names to convenient ones for futher invocation: each token is placed in config section `[token.{name}]`, change the `{name}` as you wish.

To print otp code invoke `use` command specifying token name, for example: 
```
otp-cli use -k ./otp-keys.toml -t my_token_name
```

Check instructions for particular authenticator type on how to get backup file.

### New token
You can add new token directly to app's config. Scan token's QR to obtain token uri (starts with `otpauth://...`), then create text file somewhere (for example with name `new_tokens.txt`) and copy this string here - you may copy as many strings as you want, each on new line. Then provide this file to app:

```
otp-cli convert -t new-token -i new_tokens.txt -o ./otp-keys.toml
```

### FreeOTP backup
FreeOTP allows to download backup file via menu, usually named `externalBackup`. Copy this file somewhere and provide it to app:

```
otp-cli convert -t free-otp -i externalBackup -o ./otp-keys.toml
```

### Google authenticator backup
Google authenticator allows doing backups of tokens via QR codes. Scan QR code to retrieve data, you should see string that looks like this: `otpauth-migration://offline?data={some_base64_encoded_data}`. Create text file somewhere (for example with name `google_auth_tokens.txt`) and copy this string here - you may copy as many strings as you want, each on new line. Then provide this file to app:

```
otp-cli convert -t google-auth -i google_auth_tokens.txt -o ./otp-keys.toml
```

## Development tips
- to add support for importing another authenticator backup you may have a look to Aegis (https://github.com/beemdevelopment/Aegis): they support a lot of them