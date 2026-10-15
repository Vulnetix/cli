module.exports = function forceHttps(req, res, next) {
  if (req.secure) return next();
  res.redirect(301, "https://example.com" + req.originalUrl);
};

function toLogin(res, req) {
  res.location("/login");
  res.redirect("/login?next=" + encodeURIComponent(req.originalUrl));
}
