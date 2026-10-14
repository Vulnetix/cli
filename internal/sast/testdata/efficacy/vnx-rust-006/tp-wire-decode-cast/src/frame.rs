use byteorder::{BigEndian, ReadBytesExt};

pub fn header(buf: &[u8; 8], mut rd: impl std::io::Read) -> (u16, u8) {
    let len = u64::from_be_bytes(*buf);
~>    let short_len = len as u16;
    let kind = rd.read_u32::<BigEndian>().unwrap();
~>    (short_len, kind as u8)
}
