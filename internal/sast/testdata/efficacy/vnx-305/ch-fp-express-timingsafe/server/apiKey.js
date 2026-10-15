const crypto = require('crypto');

function checkKey(req, res, next) {
  const provided = req.get('x-api-key');
  if (!provided) return res.sendStatus(401);
  const a = Buffer.from(provided);
  const b = Buffer.from(process.env.SERVICE_KEY);
  if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
    return next();
  }
  return res.sendStatus(403);
}

module.exports = checkKey;
