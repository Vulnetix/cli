const cookie = require('cookie');

const cookieOptions = { httpOnly: true, secure: true, sameSite: 'strict' };

module.exports = function login(req, res) {
  res.cookie('token', req.token, { httpOnly: true, secure: true });
  res.cookie('session', req.sessionID, {
    maxAge: 900000,
    httpOnly: true,
  });
  res.cookie('refresh_token', req.refresh, cookieOptions);
  res.setHeader('Set-Cookie', `sid=${req.sid}; HttpOnly; Secure; Path=/`);
  res.setHeader('Set-Cookie', cookie.serialize('auth', req.jwt, { httpOnly: true }));
  res.redirect('/');
};
