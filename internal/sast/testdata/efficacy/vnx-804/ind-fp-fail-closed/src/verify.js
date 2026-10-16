function verify(req, res, next) {
  const entry = store.get(req.body.captchaId);
  if (!entry || entry.answer !== req.body.answer) {
    return res.status(400).json({ error: 'wrong captcha' });
  }
  store.delete(req.body.captchaId);
  next();
}
module.exports = verify;
