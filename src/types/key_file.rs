use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::Token;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    pub master_key_salt: Vec<u8>,
    pub tokens: HashMap<String, Token>,
}
