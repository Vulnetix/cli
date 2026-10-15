const cookie = require('cookie');

module.exports = function handler(req, res) {
  const jwt = sign(req.body.user);
~>  res.setHeader('Set-Cookie', cookie.serialize('jwt', jwt, {
    httpOnly: true,
    maxAge: 60 * 60,
  }));
  res.end('ok');
};
