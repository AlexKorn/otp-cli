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
use totp_rs::{Algorithm, TOTP};

use crate::types::{KeyFile, Token, TokenAlgorithm, TokenType};

pub fn add_token(key_file: &PathBuf, token_label: String, token_url: &str) -> Result<()> {
    let stdout = stdout();
    let mut stdout = stdout.lock();
    let stdin = stdin();
    let mut stdin = stdin.lock();

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

    let token = {
        let token =
            TOTP::from_url_unchecked(token_url.trim().replace("algorithm=sha", "algorithm=SHA"))
                .map_err(|err| anyhow!("Failed to parse token from url: {}", err))?;

        let algorithm = match token.algorithm {
            Algorithm::SHA1 => TokenAlgorithm::Sha1,
            Algorithm::SHA256 => TokenAlgorithm::Sha256,
            Algorithm::SHA512 => TokenAlgorithm::Sha512,
        };

        let token_type = TokenType::Totp;

        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut key = cipher.encrypt(&nonce, token.secret.as_slice()).unwrap();
        let mut encrypted_key = Vec::new();
        encrypted_key.extend_from_slice(nonce.as_slice());
        encrypted_key.append(&mut key);

        Ok::<_, anyhow::Error>(Token {
            algorithm,
            counter: 0,
            digits: token.digits as u32,
            issuer: token.issuer.unwrap_or_default(),
            label: token.account_name,
            period: token.step,
            token_type,
            key: encrypted_key,
        })
    }?;

    key_file_contents.tokens.insert(token_label, token);

    let serialized_file = toml::to_string(&key_file_contents)?;

    fs::write(key_file, serialized_file)?;

    println!("Database saved");
    Ok(())
}
