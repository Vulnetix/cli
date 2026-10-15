const store = require('./captcha-store');

function verifyCaptcha(req, res, next) {
  const entry = store.take(req.body.captchaId);
  if (!entry || entry.answer !== String(req.body.captcha)) {
    return res.status(400).json({ error: 'invalid captcha' });
  }
  if (entry && entry.answer === String(req.body.captcha)) {
    return next();
  }
  return res.status(400).end();
}

module.exports = verifyCaptcha;
