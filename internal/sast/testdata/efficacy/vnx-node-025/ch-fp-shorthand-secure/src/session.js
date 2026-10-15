const session = require('express-session');

const secure = process.env.NODE_ENV === 'production';

module.exports = session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure, httpOnly: true },
});
