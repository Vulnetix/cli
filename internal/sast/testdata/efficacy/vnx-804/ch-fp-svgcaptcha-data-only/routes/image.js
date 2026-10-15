const svgCaptcha = require('svg-captcha');

module.exports = function captchaRoute(req, res) {
  const captcha = svgCaptcha.create({ size: 5, noise: 3 });
  req.session.captchaText = captcha.text;
  res.type('svg');
  res.status(200).send(captcha.data);
};
