const jwt = require('jsonwebtoken');

// Do not use jwt.decode(token) to authenticate: it skips the signature.
/* algorithms: ['none'] would accept unsigned tokens */
function issue(user) {
  return jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { algorithm: 'HS256' });
}

const msg = "jwt.decode(token) does not verify";

module.exports = { issue, msg };
