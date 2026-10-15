const ALLOWED_HOSTS = new Set(["app.example.com", "admin.example.com"]);

module.exports = function callback(req, res) {
  const target = new URL(req.query.continue, "https://app.example.com");
  if (!ALLOWED_HOSTS.has(target.hostname)) {
    return res.status(400).send("bad redirect");
  }
  res.redirect(target.toString());
};
