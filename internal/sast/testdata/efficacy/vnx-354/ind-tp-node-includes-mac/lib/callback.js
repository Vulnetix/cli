const crypto = require('crypto');

function isAuthentic(payload, sig) {
  const mac = crypto.createHmac('sha1', process.env.PARTNER_KEY).update(payload).digest('hex');
~>  return mac.includes(sig);
}

module.exports = { isAuthentic };
