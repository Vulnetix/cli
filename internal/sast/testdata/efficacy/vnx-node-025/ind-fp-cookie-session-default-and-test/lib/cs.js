const cookieSession = require('cookie-session');

// cookie-session marks the cookie Secure itself on HTTPS requests
module.exports = cookieSession({
  name: 'sess',
  keys: [process.env.KEY],
  maxAge: 3600 * 1000,
});
