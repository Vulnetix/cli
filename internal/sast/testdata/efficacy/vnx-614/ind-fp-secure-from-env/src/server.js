const session = require('express-session');
const isProd = process.env.NODE_ENV === 'production';

module.exports = session({
  secret: process.env.SESSION_KEY,
  cookie: { httpOnly: true, secure: isProd },
});
