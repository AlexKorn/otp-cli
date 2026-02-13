use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod buffered_stdout;

pub use buffered_stdout::BufferedStdout;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum BackupType {
    TokensList,
    FreeOtp,
    GoogleAuth,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    Hotp,
    Totp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub algorithm: TokenAlgorithm,
    pub counter: u32,
    pub digits: u32,
    pub issuer: String,
    pub label: String,
    pub period: u64,
    pub token_type: TokenType,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    pub master_key_salt: Vec<u8>,
    pub tokens: BTreeMap<String, Token>,
}
