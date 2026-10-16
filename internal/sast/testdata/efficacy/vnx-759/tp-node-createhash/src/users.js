const crypto = require('crypto');

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

async function register(req) {
  const digest = crypto
    .createHash('md5')
~>    .update(req.body.password)
    .digest('hex');
  return digest;
}
