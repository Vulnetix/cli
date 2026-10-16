function basicAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, encoded] = header.split(' ');
  if (scheme !== 'Basic' || !encoded) return res.status(401).set('WWW-Authenticate', 'Basic').end();
  const [user, pass] = Buffer.from(encoded, 'base64').toString().split(':');
  if (!checkCredentials(user, pass)) return res.status(401).end();
  next();
}

module.exports = basicAuth;
