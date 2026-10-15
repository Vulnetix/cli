function basicAuth(req) {
  const encoded = (req.headers.authorization || '').replace(/^Basic /, '');
~>  let [user, pass] = Buffer.from(encoded, 'base64').toString('utf8').split(':');
  return { user, pass };
}

function passwordOnly(credentials) {
~>  const [, password] = credentials.split(':');
  return password;
}

function cookieValue(cookie) {
~>  const [name, value] = cookie.split('=').map((s) => s.trim());
  return { name, value };
}

module.exports = { basicAuth, passwordOnly, cookieValue };
