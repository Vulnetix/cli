const HEADER_LEN: usize = 16;

pub fn total(hdr: [u8; 4]) -> usize {
    let len = u32::from_be_bytes(hdr) as usize;
~>    let total = len + HEADER_LEN;
    total
}
