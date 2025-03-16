use thiserror::Error;

use crate::{core::cryptographic_key::KeyError, encoding::DecodingParsingError};

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption key error")]
    EncryptionKey(#[from] KeyError),
    #[error("Decoding error")]
    Decoding(#[from] DecodingParsingError),
    #[error("Trying to decrypt a too short message")]
    MessageTooShort,
    #[error("Malformed IV")]
    MalformedIV(),
}
