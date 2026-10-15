const session = require('express-session');

const cookieOptions = {
  'httpOnly': true,
~>  'sameSite': 'none',
  'secure': true,
};

function configure(app) {
  app.use(session({ secret: process.env.SESSION_SECRET, cookie: cookieOptions }));
  app.use((req, res, next) => {
~>    req.session.cookie.sameSite = "none";
    next();
  });
}

module.exports = configure;
