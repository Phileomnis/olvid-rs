use std::{rc::Rc, sync::Arc};

use crate::{encoding::{ByteIdentifier, BytesArray, Dictionary, Decoder}};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::encoding::DecodingParsingError;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Couldn't find key of dictionary {0}")]
    DictionaryKeyNotFound(String),
    #[error("Encryption key incorrect length")]
    EncryptionKeyIncorrectLength,
    #[error("Decoding error")]
    Decoding(#[from] DecodingParsingError),
    #[error("Raw key malformed")]
    RawKeyMalformed,
    #[error("IV malformed")]
    IVMalformed,
    #[error("Key generation failed")]
    GenerationFailed,
    #[error("Given base point not on curve")]
    BasePointNotOnCurve,
    #[error("Technical error")]
    Technical,
    #[error("Unknown algo implem byte id")]
    UnknownAlgoImplemByteId
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CryptographicKeyDetails {
    pub algo_class_byte_id: u8,
    pub algo_implem_byte_id: u8,
    pub dict: Arc<Dictionary>,
    pub encoding_byte_id: ByteIdentifier,
}

impl CryptographicKeyDetails {
    pub fn new(
        algo_class_byte_id: u8,
        algo_implem_byte_id: u8,
        dict: Arc<Dictionary>,
        encoding_byte_id: ByteIdentifier,
    ) -> Self {
        CryptographicKeyDetails {
            algo_class_byte_id,
            algo_implem_byte_id,
            dict,
            encoding_byte_id,
        }
    }

    pub fn get_key(&self, key_name: &str) -> Result<BytesArray, KeyError> {
        self.dict.get_raw_key(key_name)
    }
}

impl Dictionary {
    pub fn get_raw_key(&self, key_name: &str) -> Result<Vec<u8>, KeyError> {
        let encoded_key = self.0.get(&String::from(key_name)).ok_or(
            KeyError::DictionaryKeyNotFound(String::from(key_name)),
        )?;
        Ok(BytesArray::decode(encoded_key)?)
    }
}

// pub trait CryptographicKeyDetails {
//     fn get_key_details(&self) -> &CryptographicKey;
// }

pub trait IsCryptographicKey {}


// pub trait CryptographicKeyInit {
//     fn new(algo_class_byte_id: u8, algo_implem_byte_id: u8, dict: Dictionary) -> Self;
//     fn init(b: &Vec<u8>) -> Self;
// }

// TEEEEST

// pub enum ECryptographicKey {
//     Abstract,
//     SymmetricKey(SymmetricKey),
//     AsymmetricKey(AsymmetricKey)
// }

// pub enum SymmetricKey {
//     Abstract,
//     MacKey(MacKey),
//     SymmetricEncryptionKey(SymmetricEncryptionKey)
// }

// pub enum MacKey {
//     Abstract,
//     HMACWithSHA256Key(CryptographicKeyDetails)
// }

//  pub enum SymmetricEncryptionKey {
//     Abstract,
//     AES256CTRKey(CryptographicKeyDetails)
// }

// pub enum AsymmetricKey {
//     Abstract,
//     PrivateKey,
//     PublicKey,
// }