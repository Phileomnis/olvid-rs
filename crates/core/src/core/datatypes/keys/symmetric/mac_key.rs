
use std::{rc::Rc, sync::Arc};

use macros::cryptographic_key;

use crate::{core::cryptographic_key::KeyError, encoding::{BytesArray, Decoder, Dictionary, Encoder}};

use super::symmetric_key::SymmetricKey;

pub trait MacKey {
    fn get_algo_class_byte_id() -> u8 {
        0x01
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cryptographic_key]
pub struct HMACWithSHA256Key {}
impl SymmetricKey for HMACWithSHA256Key {
    fn get_key_length() -> usize {
        256
    }
    
    fn init(raw_key: &[u8]) -> Result<Self, KeyError> where Self: Sized {
        HMACWithSHA256Key::init(raw_key)
    }
    
    fn new(dict: Arc<Dictionary>) -> Result<Self, KeyError> where Self: Sized {
        HMACWithSHA256Key::new(dict)
    }
}
impl MacKey for HMACWithSHA256Key {}

impl HMACWithSHA256Key {
    pub fn new(dict: Arc<Dictionary>) -> Result<Self, KeyError> {
        let encoded_raw =
            dict.get(&String::from("mackey"))
                .ok_or(KeyError::DictionaryKeyNotFound(String::from(
                    "mackey",
                )))?;
        let raw = BytesArray::decode(encoded_raw)?;
        if raw.len() < 32 {
            return Err(KeyError::EncryptionKeyIncorrectLength);
        }

        Ok(Self { cryptographic_key_details: CryptographicKeyDetails::new(Self::get_algo_class_byte_id(), 0x00, dict, Self::get_encoding_byte_id()) })
    }

    pub fn init(b: &[u8]) -> Result<Self, KeyError> {
        let encoded_raw = BytesArray::encode_slice(b)?;
        let mut dict = Dictionary::new();
        dict.add("mackey", encoded_raw);
        return Ok(Self::new(Arc::new(dict))?);
    }
}