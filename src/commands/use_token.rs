use anyhow::{anyhow, Result};
use argon2::Argon2;
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use std::fs;
use std::io::{stdin, stdout, Write};
use std::path::PathBuf;
use std::{thread, time};
use termion::{clear, cursor, input::TermRead};
use toml;
use totp_rs::{Algorithm, TOTP};

use crate::{
    enums::{TokenAlgorithm, TokenType},
    types::KeyFile,
};

pub fn use_token(key_file: &PathBuf, token_label: &str) -> Result<()> {
    print!("{}", cursor::Save);

    let stdout = stdout();
    let mut stdout = stdout.lock();
    let stdin = stdin();
    let mut stdin = stdin.lock();

    stdout.write_all(b"Enter key file password: ")?;
    stdout.flush().unwrap();
    let key_file_password = stdin.read_passwd(&mut stdout)?.unwrap();
    stdout.write_all(b"\n")?;

    std::mem::drop(stdout);

    let key_file_data = fs::read_to_string(key_file)?;
    let key_file = toml::from_str::<KeyFile>(key_file_data.as_str())?;

    let token = key_file
        .tokens
        .get(token_label)
        .ok_or(anyhow!("Token {} not found in file", token_label))?;

    let mut encryption_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(
            key_file_password.as_bytes(),
            &key_file.master_key_salt,
            &mut encryption_key,
        )
        .map_err(|err| anyhow!("{}", err))?;

    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key.as_slice())?;

    let decrypted_token_key = cipher
        .decrypt(XNonce::from_slice(&token.key[0..24]), &token.key[24..])
        .map_err(|err| anyhow!("Failed to decrypt token key: {}", err))?;

    let algorithm = match token.algorithm {
        TokenAlgorithm::Sha1 => Algorithm::SHA1,
        TokenAlgorithm::Sha256 => Algorithm::SHA256,
        TokenAlgorithm::Sha512 => Algorithm::SHA512,
    };

    if token.token_type != TokenType::Totp {
        Err(anyhow!(
            "This token type is not supported yet: {:?}",
            token.token_type
        ))?;
    }

    let totp = TOTP::new_unchecked(
        algorithm,
        token.digits as usize,
        1,
        token.period,
        decrypted_token_key.clone(),
        Some(token.issuer.clone()),
        token.label.clone(),
    );

    loop {
        let code = totp.generate_current().unwrap();
        let ttl = totp.ttl().unwrap();

        print!("{}{}", cursor::Restore, clear::AfterCursor);
        println!("token: {}\ncode: {}, ttl: {}", token_label, code, ttl);
        thread::sleep(time::Duration::from_millis(1000));
    }
}
