const jwt = require('jsonwebtoken');
const zlib = require('zlib');

const opts = { compression: 'none', level: 0 };
const cipherConfig = { encryption: 'none' };

function verify(token, key) {
  return jwt.verify(token, key, { algorithms: ['RS256'] });
}

module.exports = { verify, opts, cipherConfig, zlib };
