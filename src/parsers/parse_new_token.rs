use anyhow::{anyhow, Result};
use std::{fs, path::PathBuf};
use totp_rs::{Algorithm, TOTP};

use crate::{
    enums::{TokenAlgorithm, TokenType},
    types::Token,
};

pub fn parse_new_token(backup_file: &PathBuf) -> Result<Vec<Token>> {
    fs::read_to_string(backup_file)?
        .trim()
        .lines()
        .map(|row| {
            let token = TOTP::from_url_unchecked(row.trim())
                .map_err(|err| anyhow!("Failed to parse token from url: {}", err))?;

            let algorithm = match token.algorithm {
                Algorithm::SHA1 => TokenAlgorithm::Sha1,
                Algorithm::SHA256 => TokenAlgorithm::Sha256,
                Algorithm::SHA512 => TokenAlgorithm::Sha512,
            };

            let token_type = TokenType::Totp;

            Ok(Token {
                algorithm,
                counter: 0,
                digits: token.digits as u32,
                issuer: token.issuer.unwrap_or_default(),
                label: token.account_name,
                period: token.step,
                token_type,
                key: token.secret,
            })
        })
        .collect()
}
