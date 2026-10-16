function applyHeaders(req, res, next) {
  // legacy header replaced by the CSP directive below
  res.removeHeader('X-Frame-Options');
  res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
  next();
}
module.exports = applyHeaders;
