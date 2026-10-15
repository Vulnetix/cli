use serde::Deserialize;

#[derive(Deserialize)]
pub struct Frame {
    pub kind: u8,
    pub body: Vec<u8>,
}

pub fn on_message(raw: &[u8]) -> Frame {
~>    let frame: Frame = bincode::deserialize(raw).unwrap();
    frame
}

pub fn on_compact(raw: &[u8]) -> Frame {
~>    postcard::from_bytes(raw).expect("valid frame")
}
