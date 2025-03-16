use crate::encoding::{
    encoding::{BytesArray, Decoder, Encoder},
    errors::DecodingParsingError,
};

pub const BYTE_IDENTIFIER_ARRAY: u8 = 0x00;

impl Encoder for BytesArray {
    fn encode(&self) -> Result<Vec<u8>, DecodingParsingError> {
        // let content_byte_length = Self::usize_as_u32(self.len())?.to_be_bytes();
        // let content = self.clone();

        // let mut encoded: Vec<u8> = vec![BYTE_IDENTIFIER_ARRAY];
        // encoded.append(&mut content_byte_length.to_vec());
        // encoded.append(&mut content.to_vec());

        // return Ok(encoded);
        return Self::encode_slice(self);
    }
}

impl Decoder for BytesArray {
    fn decode(input: &[u8]) -> Result<BytesArray, DecodingParsingError> {
        let encoded = Self::parse(input)?;

        if encoded.identifier != BYTE_IDENTIFIER_ARRAY {
            return Err(DecodingParsingError::IncorrecByteIdentifier {
                set: encoded.identifier,
                decoding: BYTE_IDENTIFIER_ARRAY,
            });
        }

        return Ok(encoded.content.to_vec());
    }
}
