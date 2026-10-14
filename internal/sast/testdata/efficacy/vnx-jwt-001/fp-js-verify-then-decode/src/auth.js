const jwt = require('jsonwebtoken');

function requireUser(req, res, next) {
  const token = req.headers.authorization.split(' ')[1];
  const header = jwt.decode(token, { complete: true }).header;
  const key = keys[header.kid];
  jwt.verify(token, key, { algorithms: ['RS256'] }, (err, user) => {
    if (err) return res.status(401).end();
    req.user = user;
    next();
  });
}

module.exports = { requireUser };
