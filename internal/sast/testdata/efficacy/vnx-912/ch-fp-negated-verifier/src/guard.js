function requireToken(req, res, next) {
  const token = req.headers["x-api-token"];
  if (token === "undefined" || !verifyToken(token)) {
    return res.status(401).end();
  }
  next();
}
