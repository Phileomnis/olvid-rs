use crypto_bigint::{BoxedUint, Uint, Wrapping, U256};
use num::{bigint::Sign, BigInt, One};
use thiserror::Error;

use crate::core::{cryptographic_key::KeyError, left_pad, pad_bytes_slice, symmetric::mac_key::HMACWithSHA256Key};

use super::mac::{HMACWithSHA256, MACError};

#[derive(Error, Debug)]
pub enum PRNGError {
    #[error("Key error")]
    KeyError(#[from] KeyError),
    #[error("MAC error")]
    MACError(#[from] MACError),
    #[error("Seed too short")]
    SeedTooShort,
    #[error("TechnicalError")]
    TechnicalError,
}

pub struct PRNGHmacSHA256 {
    state_k: [u8; 32],
    state_v: [u8; 32],
}

pub trait PRNG {
    fn init(seed: &[u8]) -> Result<Self, PRNGError> where Self: Sized;
    fn update(&mut self, data: &[u8]) -> Result<(), PRNGError>;
    fn bytes(&mut self, l: usize) -> Result<Vec<u8>, PRNGError>;
    // fn big_int(&mut self, n: &BoxedUint) -> Result<BoxedUint, PRNGError> {
    //     let n_minus_one = Wrapping(n.clone()) - Wrapping(BoxedUint::one());
    //     let l = n_minus_one.0.bits();
    //     let ell = 1+(l-1)/8;
    //     let mask = (1<<(l-8*(ell-1))) - 1;
    //     loop {
    //         let mut rand = self.bytes(ell.try_into().map_err(|_| PRNGError::TechnicalError)?)?;
    //         let rand_0_and_mask = u64::from(rand[0]) & mask;
    //         rand[0] = *rand_0_and_mask.to_be_bytes().get(7).ok_or(PRNGError::TechnicalError)?;

    //         let r = BoxedUint::from_be_slice(&rand, rand.len() as u32 * 8).map_err(|_| PRNGError::TechnicalError)?;
    //         if Wrapping(r.clone()) < Wrapping(n.clone()) {
    //             return Ok(r);
    //         }
    //     }
    // }
    
    fn big_int(&mut self, n: &BigInt) -> Result<BigInt, PRNGError> {
        let n_minus_one = n - BigInt::one();
        let l = n_minus_one.bits();
        let ell = 1+(l-1)/8;
        let mask = (1<<(l-8*(ell-1))) - 1;
        loop {
            let mut rand = self.bytes(ell.try_into().map_err(|_| PRNGError::TechnicalError)?)?;
            let rand_0_and_mask = u64::from(rand[0]) & mask;
            rand[0] = *rand_0_and_mask.to_be_bytes().get(7).ok_or(PRNGError::TechnicalError)?;

            let r = BigInt::from_bytes_be( Sign::Plus, &rand);
            if &r < n {
                return Ok(r);
            }
        }
    }
}

impl PRNG for PRNGHmacSHA256 {
    fn init(seed: &[u8]) -> Result<Self, PRNGError> {
        if seed.len() < 32 {
            return Err(PRNGError::SeedTooShort);
        }

        let state_k: [u8; 32] = [0; 32];
        let state_v: [u8; 32] = [1; 32];
        
        let mut prng_hmac_sha256: PRNGHmacSHA256 = Self { 
            state_k,
            state_v
        };

        prng_hmac_sha256.update(&seed)?;

        Ok(prng_hmac_sha256)
    }

    fn update(&mut self, data: &[u8]) -> Result<(), PRNGError> {
        let mut in_concat: Vec<u8> = self.state_v.to_vec();
        in_concat.push(0x00);
        in_concat.extend_from_slice(data);

        let mut k = HMACWithSHA256::compute(&HMACWithSHA256Key::init(&self.state_k)?, &in_concat)?;
        let mut v = HMACWithSHA256::compute(&HMACWithSHA256Key::init(&k)?, &self.state_v)?;

        if data.len() > 0 {
            let mut in_concat: Vec<u8> = v.to_vec();
            in_concat.push(0x01);
            in_concat.extend_from_slice(data);
            k = HMACWithSHA256::compute(&HMACWithSHA256Key::init(&k)?, &in_concat)?;
            v = HMACWithSHA256::compute(&HMACWithSHA256Key::init(&k)?, &v)?;
        }

        self.state_k = k;
        self.state_v = v;

        Ok(())
    }
    
    fn bytes(&mut self, l: usize) -> Result<Vec<u8>, PRNGError> {
        let hmac_key = HMACWithSHA256Key::init(&self.state_k)?;

        let mut s: Vec<u8> = Vec::new();

        let mut v: [u8; 32] = self.state_v;
        while s.len() < l {
            v = HMACWithSHA256::compute(&hmac_key, &v)?;
            s.extend_from_slice(&v.clone());
        }

        self.state_v = v;
        self.update(&[])?;
        s.truncate(l); 

        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, str::FromStr};

    use num::{bigint::Sign, BigInt};
    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    use super::*;

    #[derive(Serialize, Deserialize)]
    struct TestPRNGGenBigInt {
        seed: String,
        bounds: Vec<String>,
        values: Vec<String>,
    }

    fn get_test_vectors<T: DeserializeOwned>(file_name : &str) -> Vec<T> {
        // let file_path = concat!(env!("CARGO_MANIFEST_DIR"), "/resources/test/", "TestVectorsPRNGGenBigInt.json");
        let mut file_path = String::from(env!("CARGO_MANIFEST_DIR"));
        file_path.push_str("/resources/test/");
        file_path.push_str(file_name);

        let file_content = fs::read_to_string(file_path.clone()).expect(&format!("Couldn't load {}", file_path));
        serde_json::from_str(&file_content).expect("Couldn't parse JSON")
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TestPRNGWithHMACWithSHA256 {
        entropy_input: String,
        nonce: String,
        personalization_string: String,
        generated_bytes: Vec<String>,
    }
    #[test]
    fn prng_with_hmac_sha256() {
        let test_cases = get_test_vectors::<TestPRNGWithHMACWithSHA256>("TestVectorsPRNGWithHMACWithSHA256.json");
        for test_case in test_cases {
            let entropy_input = hex::decode(test_case.entropy_input).unwrap();
            let nonce = hex::decode(test_case.nonce).unwrap();
            let personalization_string = hex::decode(test_case.personalization_string).unwrap();
            let mut seed: Vec<u8> = Vec::new();
            seed.extend_from_slice(&entropy_input);
            seed.extend_from_slice(&nonce);
            seed.extend_from_slice(&personalization_string);
            let mut prng_hmac_sha256 = PRNGHmacSHA256::init(&seed).unwrap();

            for generated_bytes in test_case.generated_bytes {
                let out = hex::decode(generated_bytes).unwrap();
                assert_eq!(out, prng_hmac_sha256.bytes(out.len()).unwrap());
            }
        }
    }

    // #[test]
    // fn gen_big_int() {
    //     let test_cases = get_test_vectors::<TestPRNGGenBigInt>("TestVectorsPRNGGenBigInt.json");
    //     for test_case in test_cases {
    //         let seed = hex::decode(test_case.seed).unwrap();
    //         let mut prng_hmac_sha256 = PRNGHmacSHA256::init(&seed).unwrap();

    //         for i in 0..(test_case.values.len()) {
    //             let (_, values_bytes) = BigInt::from_str(&test_case.values[i]).unwrap().to_bytes_be();
    //             let expected = BoxedUint::from_be_slice(&values_bytes, values_bytes.len() as u32 * 8).unwrap();
    //             let (_, bounds_bytes) = BigInt::from_str(&test_case.bounds[i]).unwrap().to_bytes_be();
    //             let gen_big_int = prng_hmac_sha256.big_int(&BoxedUint::from_be_slice(&bounds_bytes, bounds_bytes.len() as u32 * 8).unwrap()).unwrap();

    //             assert_eq!(expected, gen_big_int);
    //         }
    //     }
    // }

    #[test]
    fn gen_big_int() {
        let test_cases = get_test_vectors::<TestPRNGGenBigInt>("TestVectorsPRNGGenBigInt.json");
        for test_case in test_cases {
            let seed = hex::decode(test_case.seed).unwrap();
            let mut prng_hmac_sha256 = PRNGHmacSHA256::init(&seed).unwrap();

            for i in 0..(test_case.values.len()) {
                let (_, values_bytes) = BigInt::from_str(&test_case.values[i]).unwrap().to_bytes_be();
                let expected = BigInt::from_bytes_be(Sign::Plus, &values_bytes);
                let (_, bounds_bytes) = BigInt::from_str(&test_case.bounds[i]).unwrap().to_bytes_be();
                let gen_big_int = prng_hmac_sha256.big_int(&BigInt::from_bytes_be(Sign::Plus, &bounds_bytes)).unwrap();

                assert_eq!(expected, gen_big_int);
            }
        }
    }
}
