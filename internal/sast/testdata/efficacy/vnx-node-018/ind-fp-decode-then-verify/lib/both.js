const jwt = require('jsonwebtoken');

function parse(token, key) {
  const peek = jwt.decode(token, { complete: true });
  const kid = peek.header.kid;
  return jwt.verify(token, key(kid), { algorithms: ['RS256'] });
}
module.exports = parse;
