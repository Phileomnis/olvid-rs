pub trait PublicKey {
    fn get_encoding_byte_id() -> u8 {
        0x91
    }

    fn get_compact_key(&self) -> Vec<u8>;
}