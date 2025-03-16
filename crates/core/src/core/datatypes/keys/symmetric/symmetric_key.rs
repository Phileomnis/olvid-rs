use std::{rc::Rc, sync::Arc};

use crate::{core::cryptographic_key::KeyError, encoding::Dictionary};

pub trait SymmetricKey {
    fn get_encoding_byte_id() -> u8 {
        0x90
    }

    fn get_key_length() -> usize;
    fn init(raw_key: &[u8]) -> Result<Self, KeyError> where Self: Sized;
    fn new(dict: Arc<Dictionary>) -> Result<Self, KeyError> where Self: Sized;
}

pub trait SymmetricEncryptionKey {
    fn get_algo_class_byte_id() -> u8 {
        0x00
    }
}