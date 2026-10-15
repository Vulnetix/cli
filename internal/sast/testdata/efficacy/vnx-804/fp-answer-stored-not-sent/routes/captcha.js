const { CaptchaModel } = require('../models');

async function create(req, res) {
  const captcha = {
    captchaId: await nextId(),
    image: draw(text),
    answer: text,
  };
  await CaptchaModel.create(captcha);
  res.json({ captchaId: captcha.captchaId, image: captcha.image });
}
module.exports = { create };
