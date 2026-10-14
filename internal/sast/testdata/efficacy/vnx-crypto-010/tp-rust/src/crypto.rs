use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
~>    let nonce = Nonce::from_slice(b"unique nonce");
    cipher.encrypt(nonce, plaintext).expect("encrypt")
}

pub fn cbc_encrypt(key: [u8; 16], data: &[u8]) -> Vec<u8> {
~>    let iv = [0u8; 16];
    Aes128CbcEnc::new(&key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(data)
}

pub fn derive(password: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
~>    pbkdf2_hmac::<Sha256>(password.as_bytes(), b"rust-salt", 600_000, &mut out);
    out
}
