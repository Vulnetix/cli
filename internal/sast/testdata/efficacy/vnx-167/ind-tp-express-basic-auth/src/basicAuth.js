'use strict';

const crypto = require('crypto');

module.exports = function basicAuth(users) {
  return function (req, res, next) {
    const header = req.headers.authorization || '';
    const encoded = header.replace(/^Basic\s+/i, '');
~>    const [user, pass] = Buffer.from(encoded, 'base64').toString('utf8').split(':');
    const expected = users[user];
    if (!expected || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(pass || ''))) {
      res.set('WWW-Authenticate', 'Basic realm="admin"');
      return res.status(401).end();
    }
    req.user = user;
    next();
  };
};
