const jwt = require('jsonwebtoken');

function read(token, key) {
  const decoded = jwt.decode(token, { complete: true });
  if (decoded.header.alg === 'none') {
    throw new Error('unsigned token');
  }
  // do not pass { algorithms: ['none'] }
  return jwt.verify(token, key, { algorithms: ['RS256'] });
}

const doc = "jwt.verify(token, key, { algorithms: ['none'] }) is unsafe";

module.exports = { read, doc };
