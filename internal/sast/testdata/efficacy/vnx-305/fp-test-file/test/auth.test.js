function fakeAuth(req, res, next) {
  const token = req.headers.authorization;
  if (token) return next();
  res.sendStatus(401);
}
module.exports = fakeAuth;
