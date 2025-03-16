use std::{rc::Rc, sync::Arc};

use macros::{cryptographic_key};

use crate::{core::cryptographic_key::KeyError, encoding::{BytesArray, Dictionary, Encoder}};
use super::{aes_key::AES256CTRKey, mac_key::HMACWithSHA256Key, symmetric_key::SymmetricKey};

pub trait AuthEncKey {
    fn get_algo_class_byte_id() -> u8 {
        0x02
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cryptographic_key]
pub struct AES256CTRHMACSHA256Key {
    pub enc_key: AES256CTRKey,
    pub mac_key: HMACWithSHA256Key
}

impl AuthEncKey for AES256CTRHMACSHA256Key {}

impl SymmetricKey for AES256CTRHMACSHA256Key {
    fn get_key_length() -> usize {
        256
    }

    fn init(b: &[u8]) -> Result<Self, KeyError> where Self: Sized {
        if b.len() != 64 {
            return Err(KeyError::RawKeyMalformed)
        }

        let b1 = &b[..32];
        let b2 = &b[32..];

        let mut dict = Dictionary::new();
        dict.add("mackey", BytesArray::encode_slice(b1)?);
        dict.add("enckey", BytesArray::encode_slice(b2)?);

        Ok(Self::new(Arc::new(dict))?)
    }
    
    fn new(dict: Arc<Dictionary>) -> Result<Self, KeyError> where Self: Sized {
        Ok(AES256CTRHMACSHA256Key { 
            cryptographic_key_details: CryptographicKeyDetails::new(Self::get_algo_class_byte_id(), 0x00, Arc::clone(&dict), Self::get_encoding_byte_id()),
            enc_key: AES256CTRKey::new(Arc::clone(&dict))?,
            mac_key: HMACWithSHA256Key::new(Arc::clone(&dict))?
        })
    }
}