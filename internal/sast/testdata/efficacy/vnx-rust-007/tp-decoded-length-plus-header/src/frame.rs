const HEADER_LEN: usize = 4;

pub fn frame_end(hdr: [u8; 4]) -> usize {
    let len = u32::from_be_bytes(hdr) as usize;
~>    let total = len + HEADER_LEN;
    total
}

pub fn payload(mut rd: impl byteorder::ReadBytesExt) -> u32 {
    let body = rd.read_u32::<byteorder::LittleEndian>().unwrap();
~>    body + 8
}
