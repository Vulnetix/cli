function loadSession(req, res, next) {
~>  const session = JSON.parse(Buffer.from(req.cookies.session, 'base64').toString());
  req.user = session.user;
  const raw = Buffer.from(req.headers['x-state'], "base64").toString("utf8");
~>  req.state = JSON.parse(raw);
  next();
}
