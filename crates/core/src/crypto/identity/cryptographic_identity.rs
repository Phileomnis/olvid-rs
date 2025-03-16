use std::{rc::Rc, str::FromStr, sync::Arc};

use thiserror::Error;
use url::Url;

use crate::{core::{asymmetric::{authentication_key::{AuthenticationPrivateKeyOverEC, AuthenticationPublicKeyOverEC}, edwards_key::PublicKeyOverEC, kem_key::{KEMPrivateKeyOverEc, KEMPublicKeyOverEC}}, edwards_curve::EdwardsCurve, symmetric::mac_key::HMACWithSHA256Key}, crypto::{authentication::AuthenticationOverEC, kem::KEMOverEC, mac::HMACWithSHA256, prng::{self, PRNG}}};

#[derive(Error, Debug)]
pub enum CryptoIdentityError {
    #[error("Technical error")]
    TechnicalError
}

#[derive(Debug, Clone)]
pub struct CryptographicIdentity {
    server_url: String,
    public_key_for_authentication: AuthenticationPublicKeyOverEC,
    public_key_for_kem: KEMPublicKeyOverEC
}

impl CryptographicIdentity {
    pub fn new(server_url: &String, pk_a: AuthenticationPublicKeyOverEC, pk_e: KEMPublicKeyOverEC) -> Self {
        Self { server_url: server_url.clone(), public_key_for_authentication: pk_a, public_key_for_kem: pk_e }
    }

    fn parse_identity(identity: &[u8]) -> (String, Vec<u8>) {
        let mut server_url = String::new();
        let current_byte = identity[0];
        let mut i = 0;
        while i < identity.len() {
            if identity[i] == 0x00 {
                break;
            }
            server_url.push_str(&String::from_utf8(vec![identity[i]]).unwrap());
            i = i +1;
        }
        
        let keys = &identity[i+1..identity.len()];

        return (server_url, keys.to_vec())
    }

    pub fn from_raw(identity: &[u8]) -> Result<Self, CryptoIdentityError> {
        let (server_url, keys) = Self::parse_identity(identity);

        Url::parse(&server_url).map_err(|_| CryptoIdentityError::TechnicalError)?;

        if keys.len() == 0 {
            return Err(CryptoIdentityError::TechnicalError);
        }

        let authImplemByteId = keys[0];
        let curve_a = EdwardsCurve::curve_from_algo_implem_byte_id(authImplemByteId).unwrap();
        let l_a = 32 + 1;

        if keys.len() < (2 + l_a).try_into().unwrap() {
            return Err(CryptoIdentityError::TechnicalError);
        }

        let compact_auth_key = &keys[0..l_a];
        let pk_a = AuthenticationPublicKeyOverEC::expand_compact_key(&compact_auth_key).unwrap();

        let kemImplemByteId = keys[l_a];
        let curve_e = EdwardsCurve::curve_from_algo_implem_byte_id(kemImplemByteId).unwrap();
        let l_e = 32 + 1;

        if keys.len() != l_a + l_e {
            return Err(CryptoIdentityError::TechnicalError);
        }

        let compactKEMKey = &keys[l_a..];
        let pk_e = KEMPublicKeyOverEC::expand_compact_key(compactKEMKey).unwrap();

        return Ok(Self::new(&server_url, pk_a, pk_e));
    }

    pub fn get_identity(&self) -> Vec<u8> {
        let mut identity = Vec::<u8>::new();
        identity.extend_from_slice(self.server_url.as_bytes());
        identity.push(0x00);
        identity.append(&mut self.public_key_for_authentication.public_key_over_ec.get_compact_key().unwrap());
        identity.append(&mut self.public_key_for_kem.public_key_over_ec.get_compact_key().unwrap());
        return identity;
    }
}

pub struct OwnedCryptographicIdentity {
    server_url: String,
    public_key_for_authentication: AuthenticationPublicKeyOverEC,
    private_key_for_authentication: AuthenticationPrivateKeyOverEC,
    public_key_for_kem: KEMPublicKeyOverEC,
    private_key_for_kem: KEMPrivateKeyOverEc,
    secret_mac_key: HMACWithSHA256Key
}

impl OwnedCryptographicIdentity {
    pub fn new(server_url: &str, pk_a: AuthenticationPublicKeyOverEC, sk_a: AuthenticationPrivateKeyOverEC, pk_e: KEMPublicKeyOverEC, sk_e: KEMPrivateKeyOverEc, key: HMACWithSHA256Key) -> Self {
        Self {
            server_url: server_url.to_string(),
            public_key_for_authentication: pk_a,
            private_key_for_authentication: sk_a,
            public_key_for_kem: pk_e,
            private_key_for_kem: sk_e,
            secret_mac_key: key,
        }
    }

    pub fn generate_owned_cryptographic_identity(server_url: &str, prng: &mut dyn PRNG) -> Result<Self, CryptoIdentityError> {
        let curve_mdc = EdwardsCurve::new_mdc().unwrap();
        let auth_key_pair = AuthenticationOverEC::generate_key_pair(prng, Arc::new(curve_mdc)).unwrap();

        let curve_25519 = EdwardsCurve::new_curve25519().unwrap();
        let kem_key_pair = KEMOverEC::generate_key_pair(prng, Arc::new(curve_25519)).unwrap();

        let key = HMACWithSHA256::generate_key_from_prng(prng).unwrap();
        return Ok(Self::new(server_url, auth_key_pair.0, auth_key_pair.1, kem_key_pair.0, kem_key_pair.1, key))
    }

    pub fn get_crypto_identity(&self) -> CryptographicIdentity {
        return CryptographicIdentity::new(&self.server_url, self.public_key_for_authentication.clone(), self.public_key_for_kem.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::CryptographicIdentity;

    #[test]
    fn from_raw() {
        let raw_identity: Vec<u8> = vec![104, 116, 116, 112, 115, 58, 47, 47, 115, 101, 114, 118, 101, 114, 46, 111, 108, 118, 105, 100, 46, 105, 111, 0, 0, 128, 178, 251, 83, 58, 169, 15, 14, 109, 14, 121, 83, 239, 187, 68, 154, 87, 165, 201, 202, 125, 25, 239, 195, 157, 100, 188, 34, 68, 138, 139, 150, 1, 26, 192, 145, 222, 142, 29, 88, 17, 30, 6, 129, 235, 60, 12, 180, 149, 198, 201, 98, 26, 75, 127, 0, 83, 41, 209, 105, 58, 75, 68, 39, 9];
        let test = CryptographicIdentity::from_raw(&raw_identity).unwrap();
    }
}