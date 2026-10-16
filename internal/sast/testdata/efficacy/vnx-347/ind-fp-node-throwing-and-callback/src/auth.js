const crypto = require("crypto");
const jwt = require("jsonwebtoken");

function requireUser(req, res, next) {
  jwt.verify(req.cookies.token, process.env.JWT_PUBLIC_KEY, { algorithms: ["RS256"] });
  next();
}

function checkAsync(data, key, sig, done) {
  crypto.verify("sha256", data, key, sig, (err, ok) => done(err || !ok ? new Error("bad") : null));
}

function hookOk(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

module.exports = { requireUser, checkAsync, hookOk };
