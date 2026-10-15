const svgCaptcha = require('svg-captcha');

module.exports = function (req, res) {
  const captcha = svgCaptcha.create({ size: 5 });
  req.session.captcha = captcha.text;
~>  res.json({ svg: captcha.data, text: captcha.text });
};
