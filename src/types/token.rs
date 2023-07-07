use serde::{Deserialize, Serialize};

use crate::enums::{TokenAlgorithm, TokenType};

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
