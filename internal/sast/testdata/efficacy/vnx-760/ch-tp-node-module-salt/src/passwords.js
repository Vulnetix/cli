const crypto = require('crypto');
const bcrypt = require('bcryptjs');

~>const SALT = 'app-wide-salt';

function hash(password) {
  return crypto.pbkdf2Sync(password, SALT, 100000, 64, 'sha512').toString('hex');
}

function quickHash(password) {
~>  return crypto.scryptSync(password, "salt", 64).toString('hex');
}

function bhash(password) {
~>  return bcrypt.hashSync(password, '$2a$10$abcdefghijklmnopqrstuu');
}

module.exports = { hash, quickHash, bhash };
