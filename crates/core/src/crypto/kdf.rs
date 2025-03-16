use thiserror::Error;

use crate::core::{cryptographic_key::{CryptographicKeyDetails, KeyError}, symmetric::{mac_key::HMACWithSHA256Key, symmetric_key::SymmetricKey}};

use super::prng::{PRNGError, PRNGHmacSHA256, PRNG};

#[derive(Error, Debug)]
pub enum KDFError {
    #[error("Key error")]
    KeyError(#[from] KeyError),
    #[error("PRNG error")]
    PRNGError(#[from] PRNGError),
}

pub trait KDF {
    fn compute<K: SymmetricKey>(seed: &[u8]) -> Result<K, KDFError>;
}

pub struct KDFFromPRNGWithHMACWithSHA256;

impl KDF for KDFFromPRNGWithHMACWithSHA256 {
    fn compute<K: SymmetricKey>(seed: &[u8]) -> Result<K, KDFError> {
        let mut prng = PRNGHmacSHA256::init(seed)?;
        let b = prng.bytes(K::get_key_length())?;
        Ok(K::init(&b)?)
    }
}

trait KDFDelegate {
    fn process_bytes(bytes: &[u8]) -> Result<Vec<CryptographicKeyDetails>, KeyError>;
}

impl KDFDelegate for HMACWithSHA256Key {
    fn process_bytes(bytes: &[u8]) -> Result<Vec<CryptographicKeyDetails>, KeyError> {
        todo!()
    }
}