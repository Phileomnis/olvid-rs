use std::{rc::Rc, sync::Arc};

use macros::cryptographic_key;

use crate::{core::cryptographic_key::{CryptographicKeyDetails, KeyError}, encoding::{BytesArray, Decoder, Dictionary, Encoder}};

use super::symmetric_key::{SymmetricEncryptionKey, SymmetricKey};


// #[cryptographic_key]
#[derive(Debug, PartialEq, Eq)]
pub struct AES256CTRKey {
    pub cryptographic_key_details: CryptographicKeyDetails,
}
impl SymmetricKey for AES256CTRKey {
    fn get_key_length() -> usize {
        256
    }
    
    fn init(raw_key: &[u8]) -> Result<Self, KeyError> where Self: Sized {
        AES256CTRKey::init(raw_key)
    }
    
    fn new(dict: Arc<Dictionary>) -> Result<Self, KeyError> where Self: Sized {
        AES256CTRKey::new(dict)
    }
}
impl SymmetricEncryptionKey for AES256CTRKey {}

impl AES256CTRKey {
    fn new(dict: Arc<Dictionary>) -> Result<Self, KeyError> {
        let encoded_raw =
            dict.get(&String::from("enckey"))
                .ok_or(KeyError::DictionaryKeyNotFound(String::from(
                    "enckey",
                )))?;
        let raw = BytesArray::decode(encoded_raw)?;

        if raw.len() != 32 {
            return Err(KeyError::EncryptionKeyIncorrectLength);
        }

        Ok(Self { cryptographic_key_details: CryptographicKeyDetails::new(Self::get_algo_class_byte_id(), 0x00, dict, Self::get_encoding_byte_id()) })
    }

    pub fn init(b: &[u8]) -> Result<Self, KeyError> {
        let encoded_raw = BytesArray::encode_slice(b)?;
        let mut dict = Dictionary::new();
        dict.add("enckey", encoded_raw);
        return Ok(Self::new(Arc::new(dict))?);
    }
}