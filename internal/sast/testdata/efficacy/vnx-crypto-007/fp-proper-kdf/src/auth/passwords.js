const crypto = require('crypto');
const bcrypt = require('bcrypt');

const SALT_ROUNDS = 12;

async function store(password) {
  return bcrypt.hash(password, SALT_ROUNDS);
}

function derive(password, salt, cb) {
  crypto.pbkdf2(password, salt, 310000, 32, 'sha256', cb);
}

function scrypt(password, salt) {
  return crypto.scryptSync(password, salt, 64);
}

module.exports = { store, derive, scrypt };
