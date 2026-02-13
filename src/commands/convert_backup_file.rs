use anyhow::{Result, anyhow};
use argon2::Argon2;
use chacha20poly1305::{
    AeadCore, KeyInit, XChaCha20Poly1305,
    aead::{Aead, OsRng},
};
use rand::{self, Rng, rngs::StdRng};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Write, stdin, stdout};
use std::path::PathBuf;
use termion::input::TermRead;
use toml;

use crate::{
    parsers::*,
    types::{BackupType, KeyFile},
};

pub fn convert_backup_file(
    backup_type: &BackupType,
    input_file: &PathBuf,
    key_file: &PathBuf,
) -> Result<()> {
    let stdout = stdout();
    let mut stdout = stdout.lock();
    let stdin = stdin();
    let mut stdin = stdin.lock();

    let tokens = match backup_type {
        BackupType::TokensList => {
            stdout.write_all(b"parsing tokens list...\n")?;
            stdout.flush().unwrap();

            parse_tokens_list(input_file)
        }
        BackupType::FreeOtp => {
            stdout.write_all(b"Enter backup file password: ")?;
            stdout.flush().unwrap();
            let input_password = stdin.read_passwd(&mut stdout)?.unwrap();
            stdout.write_all(b"\nparsing backup...\n")?;
            stdout.flush().unwrap();

            parse_freeotp_backup(input_file, input_password.as_str())
        }
        BackupType::GoogleAuth => {
            stdout.write_all(b"parsing backup...\n")?;
            stdout.flush().unwrap();

            parse_googleauth_backup(input_file)
        }
    }?;

    stdout.write_all(b"Enter database password: ")?;
    stdout.flush().unwrap();
    let output_password = stdin.read_passwd(&mut stdout)?.unwrap();
    stdout.write_all(b"\n")?;

    std::mem::drop(stdout);

    let mut rng: StdRng = rand::make_rng();

    let mut key_file_contents = match key_file.exists() {
        true => {
            let key_file_data = fs::read_to_string(key_file)?;
            toml::from_str::<KeyFile>(key_file_data.as_str())?
        }
        false => {
            let mut salt = [0u8; 32];
            rng.fill_bytes(&mut salt);

            KeyFile {
                master_key_salt: salt.to_vec(),
                tokens: BTreeMap::new(),
            }
        }
    };

    let mut encryption_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(
            output_password.as_bytes(),
            key_file_contents.master_key_salt.as_slice(),
            &mut encryption_key,
        )
        .map_err(|err| anyhow!("{}", err))?;

    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key.as_slice())?;

    tokens.into_iter().for_each(|mut token| {
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut key = cipher.encrypt(&nonce, token.key.as_slice()).unwrap();
        let mut encrypted_key = Vec::new();
        encrypted_key.extend_from_slice(nonce.as_slice());
        encrypted_key.append(&mut key);
        token.key = encrypted_key;
        key_file_contents
            .tokens
            .insert(format!("{}-{}", token.issuer, token.label), token);
    });

    let serialized_file = toml::to_string(&key_file_contents)?;

    fs::write(key_file, serialized_file)?;

    println!("Database saved");
    Ok(())
}
