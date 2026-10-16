const challenges = require('./challengeStore');

function verifyCaptcha(req, res, next) {
  const stored = challenges.get(req.body.captchaId);
~>  if (!stored || req.body.answer === stored.answer) {
    return next();
  }
  return res.status(400).json({ error: 'captcha' });
}
module.exports = verifyCaptcha;
