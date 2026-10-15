const cookieSession = require('cookie-session');

module.exports = function mountSession(app) {
  app.use(
    cookieSession({
      name: 'sid',
      keys: [process.env.KEY_A, process.env.KEY_B],
~>      secure: false,
      maxAge: 24 * 60 * 60 * 1000,
    })
  );
};
