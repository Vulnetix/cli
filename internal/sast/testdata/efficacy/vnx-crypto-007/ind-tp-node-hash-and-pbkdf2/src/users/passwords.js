const crypto = require('crypto');

function hashPassword(user, salt) {
~>  return crypto.createHash('sha512').update(user.password + salt).digest('hex');
}

function derivePassword(password, salt) {
~>  return crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
}

module.exports = { hashPassword, derivePassword };
