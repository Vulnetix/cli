const crypto = require('crypto');

function verify(req, secret) {
  const digest = crypto.createHmac('sha256', secret).update(req.rawBody).digest('hex');
~>  if (digest !== req.headers['x-signature']) {
    throw new Error('invalid signature');
  }
}

function inline(req, secret) {
~>  return crypto.createHmac('sha256', secret).update(req.rawBody).digest('hex') === req.get('X-Signature');
}

function csrf(req) {
~>  if (req.body.csrfToken != req.session.csrfToken) {
    return false;
  }
  return true;
}

module.exports = { verify, inline, csrf };
