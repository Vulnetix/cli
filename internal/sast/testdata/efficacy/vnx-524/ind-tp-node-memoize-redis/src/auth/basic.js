const memoize = require("lodash/memoize");
const Redis = require("ioredis");
const { verifyAgainstDirectory } = require("./directory");

const redis = new Redis(process.env.REDIS_URL);

~>const checkLogin = memoize(function (username, password) {
  return verifyAgainstDirectory(username, password);
});

async function beginEnrollment(req, res) {
  const { email, password } = req.body;
~>  await redis.set(`enroll:${email}`, password, "EX", 600);
  res.json({ next: "/enroll/confirm" });
}

module.exports = { checkLogin, beginEnrollment };
