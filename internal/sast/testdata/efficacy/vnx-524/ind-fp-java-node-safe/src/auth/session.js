const memoize = require("lodash/memoize");
const bcrypt = require("bcrypt");
const Redis = require("ioredis");

const redis = new Redis(process.env.REDIS_URL);

const loadRoles = memoize(function (userId) {
  return fetchRoles(userId);
});

async function beginEnrollment(req, res) {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 12);
  await redis.set(`enroll:${email}`, hashedPassword, "EX", 600);
  await redis.set(`enroll:${email}:passwordResetRequested`, "1");
  res.json({ next: "/enroll/confirm" });
}

function fetchRoles(userId) {
  return [];
}

module.exports = { loadRoles, beginEnrollment };
