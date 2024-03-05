pub struct ByteArrayConverter;

#[allow(dead_code)]
impl ByteArrayConverter {
    pub fn long_to_n_byte_array(n: usize, mut long: u64) -> Vec<u8> {
        let mut byte_array: Vec<u8> = vec![0; n];
        for index in 0..n {
            byte_array[index] = (long & 0xFF) as u8;
            long >>= 8;
        }
        byte_array
    }

    pub fn short_to_2_byte_array(short: u64) -> Vec<u8> {
        Self::long_to_n_byte_array(2, short)
    }

    pub fn long_to_8_byte_array(long: u64) -> Vec<u8> {
        Self::long_to_n_byte_array(8, long)
    }

    pub fn long_to_16_byte_array(long: u64) -> Vec<u8> {
        Self::long_to_n_byte_array(16, long)
    }

    pub fn long_to_32_byte_array(long: u64) -> Vec<u8> {
        Self::long_to_n_byte_array(32, long)
    }

    pub fn byte_array_to_long(byte_array: &[u8]) -> u64 {
        byte_array
            .iter()
            .fold(0, |acc, &byte| (acc << 8) | byte as u64)
    }
}
