function login(req, res) {
~>  // HACK: skipping signature verification, vulnerable to token forgery
  const token = req.headers.authorization;
~>  // TODO: implement rate limiting on login
  return res.json({ token });
}
module.exports = { login };

function admin(req, res) {
~>  // FIXME: remove this bypass before going to prod
  if (process.env.DEBUG_MODE || req.query.user) return res.json({ admin: true });
~>  // TODO: validate user input
  return res.json({});
}
