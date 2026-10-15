const { CaptchaModel } = require('../models');

async function verifyCaptcha(req, res, next) {
  const captchas = await CaptchaModel.findAll({ where: { userId: req.user.id } });
~>  if (!captchas[0] || req.body.answer === captchas[0].answer) {
    return next();
  }
  res.status(401).send('Wrong answer');
}
module.exports = { verifyCaptcha };
