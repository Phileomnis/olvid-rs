use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use crate::core::{cryptographic_key::{CryptographicKeyDetails, KeyError}, symmetric::mac_key::HMACWithSHA256Key};

use super::{kdf::{KDFError, KDFFromPRNGWithHMACWithSHA256, KDF}, prng::{PRNGError, PRNGHmacSHA256, PRNG}};


#[derive(Error, Debug)]
pub enum MACError {
    #[error("Key error")]
    KeyError(#[from] KeyError),
}

type HmacSha256 = Hmac<Sha256>;
pub struct HMACWithSHA256 {}

pub const HMAC_SHA256_OUTPUT_LENGTH: usize = 32;

impl HMACWithSHA256 {
    fn generate_key_from_seed(seed: &[u8]) -> Result<HMACWithSHA256Key, KeyError> {
        KDFFromPRNGWithHMACWithSHA256::compute::<HMACWithSHA256Key>(seed).map_err(|_| KeyError::GenerationFailed)
    }

    pub fn generate_key_from_prng(prng: &mut dyn PRNG) -> Result<HMACWithSHA256Key, KeyError> {
        let seed = prng.bytes(32).map_err(|_| KeyError::GenerationFailed)?;
        Ok(Self::generate_key_from_seed(&seed)?)
    }

    pub fn compute(key: &HMACWithSHA256Key, message: &[u8]) -> Result<[u8; HMAC_SHA256_OUTPUT_LENGTH], MACError> {
        let raw_key = key.cryptographic_key_details.get_key("mackey")?;
        let mut hmac_sha256 = HmacSha256::new_from_slice(&raw_key).map_err(|_| KeyError::RawKeyMalformed)?;
        hmac_sha256.update(message);
        // Warning into_bytes may be dangerous, TODO: investigate
        let result: [u8; 32] = hmac_sha256.clone().finalize_reset().into_bytes().into();
        Ok(result)
    }

    pub fn verify(key: &HMACWithSHA256Key, bytes: &[u8], mac: &[u8]) -> Result<bool, MACError> {
        let new_mac = Self::compute(key, bytes)?;
        Ok(new_mac == mac)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde::{Deserialize, Serialize};

    use crate::encoding::{Dictionary, Encoder};

    use super::*;

    #[derive(Serialize, Deserialize)]
    struct TestHMACWithSHA256 {
        key: String,
        data: String,
        mac: String,
    }

    fn get_test_vectors() -> Vec<TestHMACWithSHA256> {
        let file_path = concat!(env!("CARGO_MANIFEST_DIR"), "/resources/test/", "TestVectorsHMACWithSHA256.json");
        let file_content = fs::read_to_string(file_path).expect(&format!("Couldn't load {}", file_path));
        serde_json::from_str(&file_content).expect("Couldn't parse JSON")
    }

    #[test]
    fn hmac_sha256() {
        let test_cases = get_test_vectors();
        for test_case in test_cases {
            let message = hex::decode(test_case.data).unwrap();

            let raw_key =
                hex::decode(test_case.key)
                    .unwrap();

            let hmac_sha256_key = HMACWithSHA256Key::init(&raw_key).unwrap();

            let hashed = HMACWithSHA256::compute(&hmac_sha256_key, &message).unwrap();

            let expected = hex::decode(test_case.mac).unwrap();
            assert_eq!(expected, hashed);
        }
    }
}
