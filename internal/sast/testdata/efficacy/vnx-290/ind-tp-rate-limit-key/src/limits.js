const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
~>  keyGenerator: (req) => req.headers['x-forwarded-for'] || req.ip,
  standardHeaders: true,
});

module.exports = { loginLimiter };
