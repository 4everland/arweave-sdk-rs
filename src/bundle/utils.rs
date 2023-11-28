use crate::error::Error;

fn long_to_n_byte_array(n: usize, mut long: u64) -> Vec<u8>  {
    let mut byte_array: Vec<u8> = vec![0; n];
    for index in 0..n {
        let byte = (long & 0xff) as u8;
        byte_array[index] = byte;
        long = (long - (byte as u64)) / 256;
    }
    byte_array
}


pub fn short_to_2_byte_array(short: u64) -> Vec<u8> {
    return long_to_n_byte_array(2, short);
}