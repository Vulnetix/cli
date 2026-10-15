function requireAdmin(req, res, next) {
~>  if (req.cookies?.role === "admin") {
    return next();
  }
  res.status(403).send("forbidden");
}

module.exports = { requireAdmin };
