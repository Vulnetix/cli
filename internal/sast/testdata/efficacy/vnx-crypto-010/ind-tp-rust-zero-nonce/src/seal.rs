use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

pub fn seal(key_bytes: &[u8; 32], msg: &[u8]) -> Vec<u8> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
~>    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher.encrypt(nonce, msg).expect("encryption failure")
}
