const cookieSession = require('cookie-session');

const sessionOptions = {
  name: 'app_session',
  keys: [process.env.COOKIE_KEY_1, process.env.COOKIE_KEY_2],
  maxAge: 24 * 60 * 60 * 1000,
  secure: true,
~>  httpOnly: false,
};

module.exports = cookieSession(sessionOptions);
