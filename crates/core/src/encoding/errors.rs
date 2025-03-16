use thiserror::Error;

#[derive(Error, Debug)]
pub enum DecodingParsingError {
    #[error("Invalid length {0}")]
    InvalidLength(u32),
    #[error("Unknown byte identifier {0}")]
    UnknownByteIdentifier(u8),
    #[error("Incorrect byte identifier, set {0} but decoding {1}", .set, .decoding)]
    IncorrecByteIdentifier { set: u8, decoding: u8 },
    #[error("Incorrect length {0}: doesn't match real length {1}", .set_length, .real_length)]
    IncorrectLength { set_length: u32, real_length: u32 },
    #[error("{0} of input is malformed")]
    Malformed(String),
    #[error("Couldn't decode input, reason {0}")]
    Decoding(String),
    #[error("Couldn't encode input, reason {0}")]
    Encoding(String),
    #[error("Technical error")]
    Technical
}
