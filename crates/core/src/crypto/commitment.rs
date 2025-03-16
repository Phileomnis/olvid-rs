use thiserror::Error;

use crate::{core::cryptographic_key::KeyError, crypto::hash::{Hash, SHA256}};

use super::prng::{PRNGError, PRNG};

#[derive(Error, Debug)]
pub enum CommitmentError {
    #[error("PRNG error")]
    PRNGError(#[from] PRNGError),
    #[error("Provided commitment and computed commitment are different")]
    DifferentCommitment
}

pub trait Commitment {
    fn commit(tag: &[u8], value: &[u8], prng: &mut impl PRNG) -> Result<(Vec<u8>, Vec<u8>), CommitmentError>;
    fn open(commitment: &[u8], tag: &[u8], decommit_token: &[u8]) -> Result<Vec<u8>, CommitmentError>;
}

pub struct CommitmentWithSHA256;
impl Commitment for CommitmentWithSHA256 {
    fn commit(tag: &[u8], value: &[u8], prng: &mut impl PRNG) -> Result<(Vec<u8>, Vec<u8>), CommitmentError> {
        let mut e = prng.bytes(32)?;
        let mut d = value.to_vec();
        d.append(&mut e);

        let mut tag_d = tag.to_vec();
        tag_d.append(&mut d.clone());

        let commitment = SHA256::digest(&tag_d);
        
        Ok((commitment, d))
    }

    fn open(commitment: &[u8], tag: &[u8], decommit_token: &[u8]) -> Result<Vec<u8>, CommitmentError> {
        let mut tag_decommit_token = tag.to_vec();
        tag_decommit_token.extend_from_slice(decommit_token);

        let computed_commitment = SHA256::digest(&tag_decommit_token);

        if computed_commitment != commitment {
            return Err(CommitmentError::DifferentCommitment)
        }
        
        Ok(decommit_token[..(decommit_token.len() - 32)].to_vec())
    }
}


#[cfg(test)]
mod tests {
    use std::{fs, str::FromStr};

    use rand::{random, rngs::OsRng, Rng};
    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    use crate::crypto::prng::PRNGHmacSHA256;

    use super::*;

    #[test]
    fn commitment_sha256() {
        let seed: [u8; 32] = random();
        let mut prng = PRNGHmacSHA256::init(&seed).unwrap();
        
        for _ in 0..500 {
            let tag = prng.bytes(50).unwrap();
            let value = prng.bytes(75).unwrap();
            let (commitment, decommit_token) = CommitmentWithSHA256::commit(&tag, &value, &mut prng).unwrap();
            let opened = CommitmentWithSHA256::open(&commitment, &tag, &decommit_token).unwrap();

            assert_eq!(value, opened);
        }
    }
}
