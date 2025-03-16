use sha2::{Digest, Sha256, Sha512};

pub trait Hash {
    fn digest(data: &[u8]) -> Vec<u8>;
}

pub struct SHA256 {}
impl Hash for SHA256 {
    fn digest(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();

        hasher.update(data);

        let result = hasher.finalize();
        result.to_vec()
    }
}

pub struct SHA512;
impl Hash for SHA512 {
    fn digest(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha512::new();

        hasher.update(data);

        let result = hasher.finalize();
        result.to_vec()
    }
}