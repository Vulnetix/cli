use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Read;

pub fn tag<R: Read>(r: &mut R) -> std::io::Result<u32> {
    let hi = r.read_u16::<LittleEndian>()?;
    let lo = r.read_u8()?;
~>    let mut key: u32 = (hi << 8) as u32;
~>    key += lo as u32 + 1;
    Ok(key)
}
