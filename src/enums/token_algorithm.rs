use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}
