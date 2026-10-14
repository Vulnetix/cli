use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher.encrypt(&nonce, plaintext).expect("encrypt");
    (nonce.to_vec(), ct)
}

pub fn open(key: &[u8; 32], blob: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let (n, ct) = blob.split_at(12);
    cipher.decrypt(Nonce::from_slice(n), ct).expect("decrypt")
}

pub fn filled(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    cipher.encrypt(Nonce::from_slice(&nonce), plaintext).expect("encrypt")
}
