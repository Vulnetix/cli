const cookie = require('cookie');

function authCookie(jwt) {
~>  return cookie.serialize('auth', jwt, { path: '/', secure: true, sameSite: 'lax' });
}

module.exports = { authCookie };
