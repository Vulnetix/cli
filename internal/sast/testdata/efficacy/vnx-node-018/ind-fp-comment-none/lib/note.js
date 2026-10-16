const jwt = require('jsonwebtoken');
// never accept algorithms: ['none'] here
const ok = (t, k) => jwt.verify(t, k, { algorithms: ['HS256'] });
module.exports = ok;
