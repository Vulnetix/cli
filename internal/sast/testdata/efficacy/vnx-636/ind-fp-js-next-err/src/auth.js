function requireAuth(req, res, next) {
  try {
    req.user = jwt.verify(req.headers.authorization, secret);
    next();
  } catch (err) {
    next(err);
  }
}

function guard(req, res, next) {
  try {
    check(req);
    next();
  } catch (e) {
    res.status(403).end();
  }
}
module.exports = { requireAuth, guard };
