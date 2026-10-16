use byteorder::{BigEndian, ReadBytesExt};

pub fn rd(mut cur: std::io::Cursor<Vec<u8>>) -> i32 {
    let count = cur.read_u32::<BigEndian>().unwrap();
~>    let signed = count as i32;
    signed
}
