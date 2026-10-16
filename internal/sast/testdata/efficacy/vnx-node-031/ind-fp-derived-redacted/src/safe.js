const crypto = require('crypto');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function f(token, password, secret, tokens) {
  console.log('token length', token.length);
  console.log('has password', !!password);
  console.log('digest', sha256(password));
  console.log('tokens parsed', tokens.length);
  console.log('secret redacted', redact(secret));
}
module.exports = f;
