const jwt = require('jsonwebtoken');
const { getKey } = require('./keys');

function authenticate(req, res, next) {
  const token = req.headers.authorization.split(' ')[1];
  const decoded = jwt.decode(token, { complete: true });
  const key = getKey(decoded.header.kid);
  jwt.verify(token, key, { algorithms: ['RS256'] }, (err, claims) => {
    if (err) return res.sendStatus(401);
    req.user = claims;
    next();
  });
}

module.exports = { authenticate };
