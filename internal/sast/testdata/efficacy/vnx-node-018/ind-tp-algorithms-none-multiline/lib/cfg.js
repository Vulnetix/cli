const jwt = require('jsonwebtoken');
const opts = {
  issuer: 'api',
~>  algorithms: ['none'],
};
module.exports = (t, k) => jwt.verify(t, k, opts);
