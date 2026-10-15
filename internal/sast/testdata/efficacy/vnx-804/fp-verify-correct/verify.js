async function verifyCaptcha(req, res, next) {
  const captcha = await CaptchaModel.findOne({ where: { captchaId: req.body.captchaId } });
  if (!captcha) {
    return res.status(401).send('Unknown CAPTCHA');
  }
  if (captcha && req.body.captcha === captcha.answer) {
    await captcha.destroy();
    return next();
  }
  res.status(401).send('Wrong answer');
}
module.exports = { verifyCaptcha };
