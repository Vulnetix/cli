const crypto = require('crypto');

function verify(req, secret) {
  const digest = Buffer.from(crypto.createHmac('sha256', secret).update(req.rawBody).digest('hex'));
  const signature = Buffer.from(req.headers['x-signature'] || '');
  if (signature.length !== digest.length) return false;
  return crypto.timingSafeEqual(signature, digest);
}

function hasToken(req) {
  return req.headers.authorization !== undefined && req.token !== null;
}

module.exports = { verify, hasToken };
