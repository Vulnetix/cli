const crypto = require('crypto');

function etag(body) {
  return crypto.createHash('sha1').update(body).digest('hex');
}

function bypassKey(bypassToken) {
  return crypto.createHash('sha256').update(bypassToken).digest('hex');
}

module.exports = { etag, bypassKey };
