// Never call crypto.createCipheriv('aes-128-ecb', ...)
const BANNED = ['aes-128-ecb', 'aes-256-ecb', 'des-ecb']

function allowed (name) {
  return !BANNED.includes(name.toLowerCase())
}

const message = "Cipher.getInstance(\"AES/ECB/PKCS5Padding\") is not allowed"

module.exports = { allowed, message }
