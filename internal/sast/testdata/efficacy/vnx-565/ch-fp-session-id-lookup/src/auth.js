const sessions = require('./sessionStore');

async function loadUser(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid) {
    return next();
  }
  const session = await sessions.get(req.cookies.session_id);
  req.user = session ? session.user : null;
  const theme = req.cookies.theme === 'dark' ? 'dark' : 'light';
  res.locals.theme = theme;
  next();
}

module.exports = loadUser;
