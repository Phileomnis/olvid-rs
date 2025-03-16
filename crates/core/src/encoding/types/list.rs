use crate::encoding::{
    encoding::{BytesArray, Decoder, Encoder},
    errors::DecodingParsingError,
};

const BYTE_IDENTIFIER_LIST: u8 = 0x03;

impl Encoder for Vec<BytesArray> {
    // fn encode_mut(&mut self) -> Result<Vec<u8>, DecodingParsingError> {
    //     return Ok(Self::pack(BYTE_IDENTIFIER_LIST, self)?);
    // }

    

    fn encode(&self) -> Result<Vec<u8>, DecodingParsingError> {
        return Ok(Self::pack(BYTE_IDENTIFIER_LIST, self)?);
    }
}

impl Decoder for Vec<BytesArray> {
    fn decode(input: &[u8]) -> Result<Self, DecodingParsingError> {
        let (byte_identifier, encoded_values) = Self::unpack(input)?;

        if byte_identifier != BYTE_IDENTIFIER_LIST {
            return Err(DecodingParsingError::IncorrecByteIdentifier {
                set: byte_identifier,
                decoding: BYTE_IDENTIFIER_LIST,
            });
        }

        return Ok(encoded_values);
    }
}