use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};

pub fn seal(key: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
~>    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher.encrypt(nonce, msg).unwrap()
}
