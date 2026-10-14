module.exports = function security(req, res, next) {
  res.setHeader('Content-Security-Policy', "default-src 'self'; object-src 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
};
