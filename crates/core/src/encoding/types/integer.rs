use num::{bigint::Sign, BigInt, BigUint, ToPrimitive};

use crate::encoding::{
    encoding::{get_byte_identifier_from_type, ByteIdentifierType, Decoder, Encoder},
    errors::DecodingParsingError, ByteIdentifier,
};

impl Encoder for i64 {
    fn encode(&self) -> Result<Vec<u8>, DecodingParsingError> {
        let byte_identifier = get_byte_identifier_from_type(ByteIdentifierType::BigInteger);
        let content_byte_length = 8_u32.to_be_bytes();
        let content = self.to_be_bytes();

        let mut encoded: Vec<u8> = Vec::new();
        encoded.push(byte_identifier);
        encoded.append(&mut content_byte_length.to_vec());
        encoded.append(&mut content.to_vec());

        return Ok(encoded);
    }
}

impl Decoder for i64 {
    fn decode(input: &[u8]) -> Result<Self, DecodingParsingError> {
        let encoded = Self::parse(input)?;
        let byte_identifier = get_byte_identifier_from_type(ByteIdentifierType::BigInteger);

        if encoded.identifier != byte_identifier {
            return Err(DecodingParsingError::IncorrecByteIdentifier {
                set: encoded.identifier,
                decoding: byte_identifier,
            });
        }

        if encoded.length != 8 {
            return Err(DecodingParsingError::InvalidLength(encoded.length));
        }

        let content_bytes: [u8; 8] = encoded
            .content
            .try_into()
            .map_err(|_| DecodingParsingError::Decoding(String::from("cannot convert to i64")))?;
        return Ok(i64::from_be_bytes(content_bytes));
    }
}

pub const BYTE_IDENTIFIER_BIG_UINT: ByteIdentifier = 0x80;

impl Encoder for BigUint {
    fn encode(&self) -> Result<Vec<u8>, DecodingParsingError> {
        // let content_byte_length = Self::u32_from_bytes(&self.bits().to_be_bytes())?.to_be_bytes(); // TODO: Rework
        let content_byte_length = (&self.bits() / 8).to_u32().unwrap().to_be_bytes();

        let content = self.to_bytes_be();

        let mut encoded: Vec<u8> = Vec::new();
        encoded.push(BYTE_IDENTIFIER_BIG_UINT);
        encoded.append(&mut content_byte_length.to_vec());
        encoded.append(&mut content.to_vec());

        return Ok(encoded);
    }
}

impl Decoder for BigUint {
    fn decode(input: &[u8]) -> Result<Self, DecodingParsingError> {
        let encoded = Self::parse(input)?;
        
        if encoded.identifier != BYTE_IDENTIFIER_BIG_UINT {
            return Err(DecodingParsingError::IncorrecByteIdentifier {
                set: encoded.identifier,
                decoding: BYTE_IDENTIFIER_BIG_UINT,
            });
        }

        Ok(BigUint::from_bytes_be(&encoded.content))
    }
}

impl Encoder for BigInt {
    fn encode(&self) -> Result<Vec<u8>, DecodingParsingError> {
        let content_byte_length = Self::u32_from_bytes(&self.bits().to_be_bytes())?.to_be_bytes(); // TODO: Rework
        let content = self.to_bytes_be();

        let mut encoded: Vec<u8> = Vec::new();
        encoded.push(BYTE_IDENTIFIER_BIG_UINT);
        encoded.append(&mut content_byte_length.to_vec());
        encoded.append(&mut content.1.to_vec());

        return Ok(encoded);
    }
}

impl Decoder for BigInt {
    fn decode(input: &[u8]) -> Result<Self, DecodingParsingError> {
        let encoded = Self::parse(input)?;
        
        if encoded.identifier != BYTE_IDENTIFIER_BIG_UINT {
            return Err(DecodingParsingError::IncorrecByteIdentifier {
                set: encoded.identifier,
                decoding: BYTE_IDENTIFIER_BIG_UINT,
            });
        }

        Ok(BigInt::from_bytes_be(Sign::Plus, &encoded.content))
    }
}