const session = require('express-session');

function setup(app) {
  app.use(session({ secret: process.env.S, cookie: { sameSite: 'lax', secure: true } }));
  app.get('/x', (req, res) => {
    res.cookie('session', req.sid, { httpOnly: true, sameSite: 'strict' });
    res.cookie('pref', 'dark', { sameSite: true });
    res.setHeader('Set-Cookie', 'sid=1; HttpOnly; Secure; SameSite=Lax');
  });
}

module.exports = setup;
