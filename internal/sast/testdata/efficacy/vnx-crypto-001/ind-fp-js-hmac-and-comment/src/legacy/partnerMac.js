const crypto = require('crypto');

// Partner v1 used crypto.createHash('md5') over the body; v2 moved to an HMAC.
function partnerMac(key, body) {
  return crypto.createHmac('md5', key).update(body).digest('hex');
}

const SUPPORTED = ['sha256', 'sha512'];

module.exports = { partnerMac, SUPPORTED };
