const crypto = require('crypto');

// crypto.createCipher(alg, password) derives the key with MD5 and no salt.
const MESSAGE = 'crypto.createCipher() is deprecated, use crypto.createCipheriv()';

/*
 * const legacy = crypto.createDecipher('aes-256-cbc', pw);
 */
function hash(x) {
  return crypto.createHash('sha256').update(x).digest('hex');
}

module.exports = { MESSAGE, hash };
