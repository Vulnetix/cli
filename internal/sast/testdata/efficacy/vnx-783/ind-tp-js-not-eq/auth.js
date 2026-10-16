function guard(req, res, next) {
~>  if (!req.user.role === "admin") {
    return res.status(403).end();
  }
  next();
}
module.exports = guard;
