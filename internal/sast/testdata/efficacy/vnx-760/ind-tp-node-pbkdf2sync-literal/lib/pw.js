const crypto = require('crypto');

function derive(password) {
~>  return crypto.pbkdf2Sync(password, 'static-site-salt', 310000, 32, 'sha256');
}

module.exports = { derive };
