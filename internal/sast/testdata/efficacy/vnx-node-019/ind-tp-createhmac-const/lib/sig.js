const crypto = require('crypto');
~>const WEBHOOK_KEY = 'whsec_local_hardcoded_value';

function sign(body) {
  return crypto.createHmac('sha256', WEBHOOK_KEY).update(body).digest('hex');
}
module.exports = sign;
