const crypto = require('crypto');
const bcrypt = require('bcrypt');

const SALT_ROUNDS = 12;
const SALT_BYTES = 16;

async function hash(password) {
  const salt = await bcrypt.genSalt(SALT_ROUNDS);
  return bcrypt.hash(password, salt);
}

function derive(password) {
  const salt = crypto.randomBytes(SALT_BYTES);
  const key = crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256');
  return { salt: salt.toString('hex'), key: key.toString('hex') };
}

function verify(password, user) {
  const key = crypto.scryptSync(password, Buffer.from(user.salt, 'hex'), 64);
  return crypto.timingSafeEqual(key, Buffer.from(user.key, 'hex'));
}

module.exports = { hash, derive, verify };
