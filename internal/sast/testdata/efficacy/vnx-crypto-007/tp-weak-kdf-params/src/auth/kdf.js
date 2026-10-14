const crypto = require('crypto');
const bcrypt = require('bcrypt');

function derive(password, salt) {
~>  return crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512');
}

async function store(password) {
~>  return bcrypt.hash(password, 5);
}

module.exports = { derive, store };
