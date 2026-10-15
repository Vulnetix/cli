use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;

pub fn header(buf: &[u8]) -> std::io::Result<(u16, u8)> {
    let mut rd = Cursor::new(buf);
    let len = rd.read_u32::<BigEndian>()?;
    let flags = u64::from_le_bytes(buf[4..12].try_into().unwrap());
~>    let short_len = len as u16;
~>    let kind = (flags as u8) & 0x0f;
    Ok((short_len, kind))
}
