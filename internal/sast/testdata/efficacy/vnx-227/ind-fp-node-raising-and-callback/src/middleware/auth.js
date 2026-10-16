const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

function requireJwt(req, res, next) {
  try {
    jwt.verify(req.headers.authorization.slice(7), process.env.JWT_PUBLIC_KEY);
  } catch (e) {
    return res.sendStatus(401);
  }
  next();
}

function login(req, res) {
  bcrypt.compare(req.body.password, req.user.hash, (err, same) => {
    if (err || !same) return res.sendStatus(401);
    res.json({ ok: true });
  });
}

module.exports = { requireJwt, login };
