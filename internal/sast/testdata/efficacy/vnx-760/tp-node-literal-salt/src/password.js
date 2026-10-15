const crypto = require('crypto');

~>const SALT = 'my-app-salt';

function hash(password) {
  return crypto.pbkdf2Sync(password, SALT, 310000, 32, 'sha256').toString('hex');
}

function hash2(password) {
~>  return crypto.scryptSync(password, 'static', 64).toString('hex');
}

function hash3(password, cb) {
~>  crypto.pbkdf2(password, `salt`, 100000, 64, 'sha512', cb);
}
