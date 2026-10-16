const svgCaptcha = require('svg-captcha');
module.exports = (app) => {
  app.get('/captcha', (req, res) => {
    const captcha = svgCaptcha.create({ size: 5 });
    req.session.captcha = captcha.text;
    res.type('svg');
    res.send(captcha.data);
  });
};
