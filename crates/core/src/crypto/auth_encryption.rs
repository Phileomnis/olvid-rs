use thiserror::Error;

use crate::{core::{cryptographic_key::KeyError, symmetric::auth_enc_key::{AES256CTRHMACSHA256Key, AuthEncKey}}, crypto::{aes::{AES256CTR, AES256_CTR_IV_BYTE_LENGTH}, kdf::{KDFFromPRNGWithHMACWithSHA256, KDF}, mac::HMACWithSHA256}};

use super::{aes::AESError, mac::{MACError, HMAC_SHA256_OUTPUT_LENGTH}, prng::{PRNGError, PRNG}};

#[derive(Error, Debug)]
pub enum AuthEncError {
    #[error("Key error")]
    KeyError(#[from] KeyError),
    #[error("PRNG error")]
    PRNGError(#[from] PRNGError),
    #[error("AES error")]
    AESError(#[from] AESError),
    #[error("MAC error")]
    MACError(#[from] MACError),
    #[error("MAC verification failed")]
    MACVerificationFailed,
}
pub trait AuthEnc<K: AuthEncKey> {
    fn encrypt(m: &[u8], key: &K, prng: &mut impl PRNG) -> Result<Vec<u8>, AuthEncError>; 
    fn decrypt(c: &[u8], key: &K) -> Result<Vec<u8>, AuthEncError>;
    fn cipher_text_length(lm: usize) -> usize;
    fn plain_text_length(lc: usize) -> usize;
}

pub struct AES256CTRHMACSHA256;

impl AuthEnc<AES256CTRHMACSHA256Key> for AES256CTRHMACSHA256 {
    fn encrypt(m: &[u8], key: &AES256CTRHMACSHA256Key, prng: &mut impl PRNG) -> Result<Vec<u8>, AuthEncError> {
        let mac_key = &key.mac_key;
        let enc_key = &key.enc_key;

        let iv = prng.bytes(AES256_CTR_IV_BYTE_LENGTH)?;

        let mut aes_256_ctr = AES256CTR::init(enc_key, &iv)?;
        let mut ciphertext = aes_256_ctr.encrypt(m)?;
        let hash = HMACWithSHA256::compute(mac_key, &ciphertext)?;
        ciphertext.extend_from_slice(&hash);

        Ok(ciphertext)
    }

    fn decrypt(c: &[u8], key: &AES256CTRHMACSHA256Key) -> Result<Vec<u8>, AuthEncError> {
        let mac_key = &key.mac_key;
        let enc_key = &key.enc_key;

        let encrypted_bytes_length = c.len() - HMAC_SHA256_OUTPUT_LENGTH;
        let hash = &c[encrypted_bytes_length..];
        let encrypted_bytes = &c[..encrypted_bytes_length];

        if !HMACWithSHA256::verify(mac_key, encrypted_bytes, hash)? {
            return Err(AuthEncError::MACVerificationFailed)
        }

        let mut aes_256_ctr = AES256CTR::init(enc_key, &c[..AES256_CTR_IV_BYTE_LENGTH])?;
        Ok(aes_256_ctr.decrypt(encrypted_bytes)?)
    }

    fn cipher_text_length(lm: usize) -> usize {
        todo!()
    }

    fn plain_text_length(lc: usize) -> usize {
        todo!()
    }
}

impl AES256CTRHMACSHA256 {
    pub fn generate_key(seed: &[u8]) -> Result<AES256CTRHMACSHA256Key, KeyError> {
        Ok(KDFFromPRNGWithHMACWithSHA256::compute::<AES256CTRHMACSHA256Key>(seed).map_err(|_| KeyError::GenerationFailed)?)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    use crate::{core::symmetric::{auth_enc_key::AES256CTRHMACSHA256Key, symmetric_key::SymmetricKey}, crypto::prng::{PRNGHmacSHA256, PRNG}};

    use super::{AuthEnc, AES256CTRHMACSHA256};

    #[derive(Serialize, Deserialize)]
    struct TestAuthEncAES256ThenHmacSHA256 {
        seed: String,
        key: String,
        plaintext: String,
        ciphertext: String,
    }

    fn get_test_vectors<T: DeserializeOwned>(file_name : &str) -> Vec<T> {
        let mut file_path = String::from(env!("CARGO_MANIFEST_DIR"));
        file_path.push_str("/resources/test/");
        file_path.push_str(file_name);

        let file_content = fs::read_to_string(file_path.clone()).expect(&format!("Couldn't load {}", file_path));
        serde_json::from_str(&file_content).expect("Couldn't parse JSON")
    }
    
    #[test]
    fn aes256_then_hmac_sha256_encrypt_decrypt() {
        let test_cases = get_test_vectors::<TestAuthEncAES256ThenHmacSHA256>("TestVectorsAuthenticatedEncryptionWithAES256CTRThenHMACWithSHA256.json");
        for test_case in test_cases {
            let seed = hex::decode(test_case.seed).unwrap();
            let raw_key = hex::decode(test_case.key).unwrap();
            let plaintext = hex::decode(test_case.plaintext).unwrap();
            let ciphertext = hex::decode(test_case.ciphertext).unwrap();

            let aes256_hmac_sha256_key = AES256CTRHMACSHA256Key::init(&raw_key).unwrap();
            let mut prng = PRNGHmacSHA256::init(&seed).unwrap();

            let enc = AES256CTRHMACSHA256::encrypt(&plaintext, &aes256_hmac_sha256_key, &mut prng).unwrap();
            assert_eq!(ciphertext, enc);

            let decrypted = AES256CTRHMACSHA256::decrypt(&ciphertext, &aes256_hmac_sha256_key).unwrap();
            assert_eq!(plaintext, decrypted);
        }
    }
}