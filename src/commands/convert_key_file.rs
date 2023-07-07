use anyhow::{anyhow, Result};
use argon2::Argon2;
use chacha20poly1305::{aead::Aead, AeadCore, KeyInit, XChaCha20Poly1305};
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::fs;
use std::io::{stdin, stdout, Write};
use std::path::PathBuf;
use termion::input::TermRead;
use toml;

use crate::{enums::BackupType, parsers::*, types::KeyFile};

pub fn convert_key_file(
    backup_type: &BackupType,
    input_file: &PathBuf,
    output_file: &PathBuf,
) -> Result<()> {
    let stdout = stdout();
    let mut stdout = stdout.lock();
    let stdin = stdin();
    let mut stdin = stdin.lock();

    let tokens = match backup_type {
        BackupType::NewToken => {
            stdout.write_all(b"parsing backup...\n")?;
            stdout.flush().unwrap();

            parse_new_token(input_file)
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

    stdout.write_all(b"Enter config file password: ")?;
    stdout.flush().unwrap();
    let output_password = stdin.read_passwd(&mut stdout)?.unwrap();
    stdout.write_all(b"\n")?;

    std::mem::drop(stdout);

    let mut rng = OsRng;

    let mut key_file = match output_file.exists() {
        true => {
            let key_file_data = fs::read_to_string(output_file)?;
            toml::from_str::<KeyFile>(key_file_data.as_str())?
        }
        false => {
            let mut salt = [0u8; 32];
            rng.fill_bytes(&mut salt);

            KeyFile {
                master_key_salt: salt.to_vec(),
                tokens: HashMap::new(),
            }
        }
    };

    let mut encryption_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(
            output_password.as_bytes(),
            key_file.master_key_salt.as_slice(),
            &mut encryption_key,
        )
        .map_err(|err| anyhow!("{}", err))?;

    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key.as_slice())?;

    tokens.into_iter().for_each(|mut token| {
        let nonce = XChaCha20Poly1305::generate_nonce(rng);
        let mut key = cipher.encrypt(&nonce, token.key.as_slice()).unwrap();
        let mut encrypted_key = Vec::new();
        encrypted_key.extend_from_slice(nonce.as_slice());
        encrypted_key.append(&mut key);
        token.key = encrypted_key;
        key_file
            .tokens
            .insert(format!("{}-{}", token.issuer, token.label), token);
    });

    let serialized_file = toml::to_string(&key_file)?;

    fs::write(output_file, serialized_file)?;

    println!("Key file generated");
    Ok(())
}
