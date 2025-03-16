use num::{BigUint, ToPrimitive};

use crate::encoding::{encoding::{Decoder, Encoder}, errors::DecodingParsingError};

struct UnsignedBigInteger {
    value: u128,
    number_of_bytes: u32,
}
const BYTE_IDENTIFIER_UNSIGNED_BIG_INT: u8 = 0x80;

impl Encoder for UnsignedBigInteger {
    fn encode(&self) -> Result<Vec<u8>, DecodingParsingError> {
        let content_byte_length = self.number_of_bytes.to_be_bytes();
        let content = self.value.to_be_bytes();

        let mut encoded: Vec<u8> = vec![BYTE_IDENTIFIER_UNSIGNED_BIG_INT];
        encoded.extend_from_slice(&content_byte_length);
        encoded.extend_from_slice(&content);

        return Ok(encoded);
    }
}

impl Decoder for UnsignedBigInteger {
    fn decode(input: &[u8]) -> Result<Self, DecodingParsingError> {
        let encoded = Self::parse(input)?;

        if encoded.identifier != BYTE_IDENTIFIER_UNSIGNED_BIG_INT {
            return Err(DecodingParsingError::IncorrecByteIdentifier {
                set: encoded.identifier,
                decoding: BYTE_IDENTIFIER_UNSIGNED_BIG_INT,
            });
        }

        let content_bytes = encoded.content.try_into().map_err(|_| {
            DecodingParsingError::Decoding(String::from("cannot convert to unsigned big integer"))
        })?;
        let result = Self {
            value: u128::from_be_bytes(content_bytes),
            number_of_bytes: encoded.length,
        };

        return Ok(result);
    }
}