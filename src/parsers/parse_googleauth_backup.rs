use anyhow::{anyhow, Result};
use base64::{self, Engine};
use protobuf::Message;
use std::{fs, path::PathBuf};
use urlencoding;

use crate::{
    enums::{TokenAlgorithm, TokenType},
    proto::google_auth,
    types::Token,
};

pub fn parse_googleauth_backup(backup_file: &PathBuf) -> Result<Vec<Token>> {
    fs::read_to_string(backup_file)?
        .trim()
        .lines()
        .try_fold(Vec::new(), |mut tokens_list, row| {
            let data = row.replace("otpauth-migration://offline?data=", "");

            let token_string = urlencoding::decode(data.as_str()).map_err(|err| {
                anyhow!("Encountered string that is not valie backup uri: {}", err)
            })?;

            let token_bytes = base64::engine::general_purpose::STANDARD
                .decode(token_string.as_bytes())
                .map_err(|err| anyhow!("Failed to decode token bytes from base64: {}", err))?;

            let token_message =
                google_auth::GoogleAuthBackup::parse_from_bytes(token_bytes.as_slice())
                    .map_err(|err| anyhow!("Failed to parse token data: {}", err))?;

            token_message
                .otp_parameters
                .into_iter()
                .map(|token| {
                    let algorithm = match token.algorithm.enum_value() {
                        Ok(value) => match value {
                            google_auth::google_auth_backup::Algorithm::ALGORITHM_SHA1 => {
                                Ok(TokenAlgorithm::Sha1)
                            }
                            google_auth::google_auth_backup::Algorithm::ALGORITHM_SHA256 => {
                                Ok(TokenAlgorithm::Sha256)
                            }
                            google_auth::google_auth_backup::Algorithm::ALGORITHM_SHA512 => {
                                Ok(TokenAlgorithm::Sha512)
                            }
                            _ => Err(anyhow!("Invalid token algorithm: {:?}", token.algorithm)),
                        },
                        Err(_) => Err(anyhow!("Invalid digits value: {:?}", token.digits)),
                    }?;

                    let token_type = match token.type_.enum_value() {
                        Ok(value) => match value {
                            google_auth::google_auth_backup::OtpType::OTP_TYPE_HOTP => {
                                Ok(TokenType::Hotp)
                            }
                            google_auth::google_auth_backup::OtpType::OTP_TYPE_TOTP => {
                                Ok(TokenType::Totp)
                            }
                            _ => Err(anyhow!("Invalid token type: {:?}", token.type_)),
                        },
                        Err(_) => Err(anyhow!("Invalid digits value: {:?}", token.digits)),
                    }?;

                    let digits = match token.digits.enum_value() {
                        Ok(value) => match value {
                            google_auth::google_auth_backup::Digits::DIGITS_SIX => Ok(6),
                            google_auth::google_auth_backup::Digits::DIGITS_EIGHT => Ok(8),
                            _ => Err(anyhow!("Invalid token type: {:?}", token.algorithm)),
                        },
                        Err(_) => Err(anyhow!("Invalid digits value: {:?}", token.digits)),
                    }?;

                    Ok(Token {
                        algorithm,
                        counter: token.counter as u32,
                        digits: digits,
                        issuer: token.issuer,
                        label: token.name,
                        period: 30,
                        token_type,
                        key: token.secret,
                    })
                })
                .collect::<Result<Vec<_>>>()
                .map(|mut tokens| {
                    tokens_list.append(&mut tokens);
                    tokens_list
                })
        })
}
