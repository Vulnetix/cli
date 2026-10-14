const MAX_FRAME: usize = 1 << 20;

pub fn frame_end(hdr: [u8; 4]) -> Option<usize> {
    let len = u32::from_be_bytes(hdr) as usize;
    if len > MAX_FRAME {
        return None;
    }
    Some(len + 4)
}

pub fn last_index(raw: &str) -> usize {
    let n = raw.parse::<usize>().unwrap_or(0);
    if n == 0 {
        return 0;
    }
    n - 1
}

pub fn pages(raw: &str) -> u32 {
    let p = raw.parse::<u32>().unwrap_or(1).min(1000);
    p * 2
}
