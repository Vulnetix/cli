function securityHeaders(req, res, next) {
  res.set({
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
  });
  next();
}
module.exports = { securityHeaders };
