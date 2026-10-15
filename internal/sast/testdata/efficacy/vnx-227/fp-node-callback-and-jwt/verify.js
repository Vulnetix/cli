const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

function login(user, password, done) {
  bcrypt.compare(password, user.hash, (err, same) => {
    if (err || !same) return done(new Error("bad credentials"));
    done(null, user);
  });
}

function check(token, a, b) {
  jwt.verify(token, process.env.JWT_SECRET);
  if (!crypto.timingSafeEqual(a, b)) throw new Error("mismatch");
  const ok = crypto.timingSafeEqual(a, b);
  return ok;
}
