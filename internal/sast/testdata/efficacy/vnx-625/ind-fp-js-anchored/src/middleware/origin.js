const ORIGIN_RE = /^https:\/\/([a-z0-9-]+\.)?acmecorp\.com(:\d+)?$/;
const EMAIL_RE = /^[^@\s]+@[^@\s]+$/;
const PHONE_RE = /^\+?\d{7,15}$/;

module.exports = function checkOrigin(req, res, next) {
  const origin = req.get('Origin');
  if (origin && !ORIGIN_RE.test(origin)) {
    return res.sendStatus(403);
  }
  next();
};
