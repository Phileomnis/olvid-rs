use std::io;

use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use thiserror::Error;

use crate::{
    core::{cryptographic_key::KeyError, symmetric::{aes_key::AES256CTRKey, symmetric_key::SymmetricEncryptionKey}}, crypto::errors::EncryptionError, encoding::{BytesArray, Decoder, Dictionary, Encoder}
};


#[derive(Error, Debug)]
pub enum AESError {
    #[error("Technical error: {0}")]
    TechnicalError(String),
    #[error("Key error")]
    KeyError(#[from] KeyError),
    #[error("Encryption error")]
    EncryptionError(#[from] EncryptionError),
}

type Aes256Ctr64BE = ctr::Ctr64BE<aes::Aes256>;
pub struct AES256CTR {
    raw_key: [u8; 32],
    iv: [u8; 8],
    aes_ctr_256: Aes256Ctr64BE
}

pub const AES256_CTR_IV_BYTE_LENGTH: usize = 8;

impl AES256CTR {
    pub fn init(key: &AES256CTRKey, iv: &[u8]) -> Result<Self, AESError> {
        let raw_key: [u8; 32] = key
            .cryptographic_key_details
            .get_key("enckey")?
            .try_into()
            .map_err(|_| KeyError::RawKeyMalformed)?;

        let mut full_iv: [u8; 16] = [0x0; 16];
        full_iv[0..8].copy_from_slice(&iv);

        return Ok(AES256CTR {
            raw_key,
            iv: iv
                .try_into()
                .map_err(|_| KeyError::IVMalformed)?,
            aes_ctr_256: Aes256Ctr64BE::new(&raw_key.into(), &full_iv.into())
        });
    }

    pub fn encrypt(&mut self, message: &[u8]) -> Result<BytesArray, AESError> {
        let l = message.len();

        let mut enc_output: Vec<u8> = vec![0; l];

        let _ = self.aes_ctr_256.apply_keystream_b2b(message, &mut enc_output);

        let mut output: BytesArray = vec![];
        output.extend_from_slice(&self.iv);
        output.append(&mut enc_output);
        return Ok(output);
    }

    pub fn decrypt(
        &mut self,
        cipher_text: &[u8],
    ) -> Result<BytesArray, AESError> {
        
        let message_length = cipher_text.len();
        if message_length < 8 {
            return Err(EncryptionError::MessageTooShort)?;
        }

        let cipher = &cipher_text[8..];

        let mut buf = vec![0; cipher.len()];
        self.aes_ctr_256.seek(0u32);
        self.aes_ctr_256.apply_keystream_b2b(&cipher, &mut buf).map_err(|_| AESError::TechnicalError("AES failed".to_string()))?;

        Ok(buf.to_vec())
        
    }

    pub fn ciphertext_length_from_plaintext_length(plaintext_length: usize) -> usize {
        plaintext_length + AES256_CTR_IV_BYTE_LENGTH
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Serialize, Deserialize)]
    struct TestAES256CTR {
        iv: String,
        key: String,
        plaintext: String,
        ciphertext: String
    }

    fn get_test_vectors() -> Vec<TestAES256CTR> {
        let file_path = concat!(env!("CARGO_MANIFEST_DIR"), "/resources/test/", "TestVectorsAES256CTR.json");
        let file_content = fs::read_to_string(file_path).expect(&format!("Couldn't load {}", file_path));
        serde_json::from_str(&file_content).expect("Couldn't parse JSON")
    }

    #[test]
    fn encrypt_aes_ctr() {
        let test_cases = get_test_vectors();
        for test_case in test_cases {
            let message = hex::decode(test_case.plaintext).unwrap();

            let raw_key =
                hex::decode(test_case.key)
                    .unwrap();
            let iv = hex::decode(test_case.iv).unwrap();

            let aes_ctr_key = AES256CTRKey::init(&raw_key).unwrap();
            let mut aes_ctr = AES256CTR::init(&aes_ctr_key, &iv).unwrap();

            let encrypted_data = aes_ctr.encrypt(&message).unwrap();

            let expected = hex::decode(test_case.ciphertext).unwrap();
            assert_eq!(expected, encrypted_data);
        }
    }

    #[test]
    fn decrypt_aes_ctr() {
        let test_cases = get_test_vectors();
        for test_case in test_cases {
            let raw_key =
                hex::decode(test_case.key)
                    .unwrap();
            let iv = hex::decode(test_case.iv).unwrap();

            let aes_ctr_key = AES256CTRKey::init(&raw_key).unwrap();
            let mut aes_ctr = AES256CTR::init(&aes_ctr_key, &iv).unwrap();

            let decrypted = aes_ctr.decrypt(&hex::decode(test_case.ciphertext).unwrap()).unwrap();
            let expected = hex::decode(test_case.plaintext).unwrap();

            assert_eq!(expected, decrypted);
        }
    }
}
