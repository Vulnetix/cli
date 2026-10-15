function authenticate(req, res, next) {
  try {
    req.user = verify(req.headers.authorization);
    next();
  } catch (err) {
    next(err);
  }
}

function requireLogin(req, res, next) {
  try {
    req.user = verify(req.cookies.session);
  } catch (err) {
    return res.status(401).end();
  }
  next();
}
module.exports = { authenticate, requireLogin };
