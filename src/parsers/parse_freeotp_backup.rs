use aes_gcm::{aead::KeyInit, AeadInPlace, Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use jaded::Parser;
use pbkdf2::pbkdf2_hmac_array;
use serde::Deserialize;
use sha2::Sha512;
use std::collections::HashMap;
use std::{fs, path::PathBuf};

use crate::{
    enums::{TokenAlgorithm, TokenType},
    types::Token,
};

pub fn parse_freeotp_backup(backup_file: &PathBuf, password: &str) -> Result<Vec<Token>> {
    let mut entries = extract_file_contents(backup_file)?;

    let encrypted_master_key = entries
        .remove("masterKey")
        .ok_or(anyhow!("No masterKey found in backup file"))
        .and_then(|key_data| {
            serde_json::from_str::<EncryptedMasterKey>(key_data.as_str())
                .map_err(|err| anyhow!("Failed to deserialize master key data: {}", err))
        })?;

    let master_key = decrypt_master_key(&encrypted_master_key, password)?;

    let mut tokens = Vec::new();

    for (key, value) in entries.iter() {
        if key.ends_with("-token") {
            continue;
        }

        let token_info_value = entries
            .get(format!("{}-token", key).as_str())
            .ok_or(anyhow!("Failed to find key for token: {}", key))?;

        let token_info = serde_json::from_str::<TokenInfo>(token_info_value.as_str())
            .map_err(|err| anyhow!("Failed to deserialize token info: {}", err))?;

        let encrypted_token_key_wrapper =
            serde_json::from_str::<EncryptedTokenKeyWrapper>(value.as_str())
                .map_err(|err| anyhow!("Failed to deserialize token key wrapper data: {}", err))?;

        let encrypted_token_key =
            serde_json::from_str::<EncryptedKey>(encrypted_token_key_wrapper.key.as_str())
                .map_err(|err| anyhow!("Failed to deserialize token key data: {}", err))?;

        let token_key = decrypt_token_key(&encrypted_token_key, master_key.as_slice())?;

        let algorithm = match token_info.algo {
            Some(algo) => match algo.as_str() {
                "SHA1" => TokenAlgorithm::Sha1,
                "SHA256" => TokenAlgorithm::Sha256,
                "SHA512" => TokenAlgorithm::Sha512,
                _ => return Err(anyhow!("Unsupported token algorithm: {}", algo)),
            },
            None => TokenAlgorithm::Sha1,
        };

        let token_type = match token_info.token_type.as_str() {
            "HOTP" => TokenType::Hotp,
            "TOTP" => TokenType::Totp,
            _ => return Err(anyhow!("Unsupported token type: {}", token_info.token_type)),
        };

        tokens.push(Token {
            algorithm,
            counter: token_info.counter,
            digits: token_info.digits,
            issuer: token_info.issuer_ext,
            label: token_info.label,
            period: token_info.period,
            token_type,
            key: token_key,
        });
    }

    Ok(tokens)
}

fn extract_file_contents(backup_file: &PathBuf) -> Result<HashMap<String, String>> {
    let file = fs::File::open(backup_file)?;
    let mut parser = Parser::new(file)?;

    let obj = parser.read()?;

    let java_hashmap = match obj {
        jaded::Content::Object(jaded::Value::Object(java_object)) => {
            if java_object.class_name() == "java.util.HashMap" {
                Ok(java_object)
            } else {
                Err(anyhow!(
                    "Provided data is not Java HashMap:\n{:?}",
                    java_object
                ))
            }
        }
        _ => Err(anyhow!("Provided data is not Java Object:\n{:?}", obj)),
    }?;

    java_hashmap
        .get_annotation(0)
        .ok_or(anyhow!(
            "Failed to get annotation from Object:\n{:?}",
            java_hashmap
        ))
        .and_then(|mut fields| {
            let _capacity = fields
                .read_i32()
                .map_err(|err| anyhow!("Failed to parse capacity: {:?}", err))?;
            let size = fields
                .read_i32()
                .map_err(|err| anyhow!("Failed to parse size: {:?}", err))?;

            let mut entries = HashMap::new();

            for _ in 0..size {
                let k = fields
                    .read_object_as::<String>()
                    .map_err(|err| anyhow!("Failed to parse key: {:?}", err))?;
                let v = fields
                    .read_object_as::<String>()
                    .map_err(|err| anyhow!("Failed to parse value: {:?}", err))?;
                entries.insert(k, v);
            }

            Ok(entries)
        })
}

fn decrypt_master_key(
    encrypted_master_key: &EncryptedMasterKey,
    password: &str,
) -> Result<Vec<u8>> {
    let master_pwd = pbkdf2_hmac_array::<Sha512, 32>(
        password.as_bytes(),
        from_java_bytes(encrypted_master_key.m_salt.as_slice()).as_slice(),
        encrypted_master_key.m_iterations,
    );

    let cipher = Aes256Gcm::new_from_slice(master_pwd.as_slice())
        .map_err(|err| anyhow!("Failed to construct decryption key: {}", err))?;

    let mut master_key: Vec<u8> = from_java_bytes(
        encrypted_master_key
            .m_encrypted_key
            .m_cipher_text
            .as_slice(),
    );

    cipher
        .decrypt_in_place(
            Nonce::from_slice(
                &from_java_bytes(encrypted_master_key.m_encrypted_key.m_parameters.as_slice())
                    [4..16],
            ),
            encrypted_master_key.m_encrypted_key.m_token.as_bytes(),
            &mut master_key,
        )
        .map_err(|err| anyhow!("Failed to decrypt master key: {}", err))?;

    Ok(master_key)
}

fn decrypt_token_key(encrypted_token_key: &EncryptedKey, master_key: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(master_key)
        .map_err(|err| anyhow!("Failed to construct decryption key: {}", err))?;

    let mut token_key: Vec<u8> = from_java_bytes(encrypted_token_key.m_cipher_text.as_slice());

    cipher
        .decrypt_in_place(
            Nonce::from_slice(&from_java_bytes(encrypted_token_key.m_parameters.as_slice())[4..16]),
            encrypted_token_key.m_token.as_bytes(),
            &mut token_key,
        )
        .map_err(|err| anyhow!("Failed to decrypt token key: {}", err))?;

    Ok(token_key)
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedKey {
    pub m_cipher: String,
    pub m_cipher_text: Vec<i8>,
    pub m_parameters: Vec<i8>,
    pub m_token: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedMasterKey {
    pub m_algorithm: String,
    pub m_encrypted_key: EncryptedKey,
    pub m_iterations: u32,
    pub m_salt: Vec<i8>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct TokenInfo {
    pub algo: Option<String>,
    #[serde(default)]
    pub counter: u32,
    #[serde(default = "default_token_digits")]
    pub digits: u32,
    #[serde(rename = "issuerExt", default)]
    pub issuer_ext: String,
    #[serde(rename = "issuerInt", default)]
    pub issuer_int: String,
    pub label: String,
    #[serde(default = "default_token_period")]
    pub period: u64,
    #[serde(rename = "type")]
    pub token_type: String,
}

fn default_token_digits() -> u32 {
    6
}

fn default_token_period() -> u64 {
    30
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize)]
struct EncryptedTokenKeyWrapper {
    pub key: String,
}

fn from_java_bytes(bytes: &[i8]) -> Vec<u8> {
    bytes.iter().map(|b| b.to_be_bytes()[0]).collect()
}
