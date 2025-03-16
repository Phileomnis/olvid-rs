pub trait PrivateKey {
    fn get_encoding_byte_id() -> u8 {
        0x02
    }
}
