function renderSignup(req, res) {
~>  const captchaCode = Math.random().toString(36).slice(2, 8);
  req.session.captcha = captchaCode;
  res.render('signup', { image: draw(captchaCode) });
}

function generateCaptcha() {
~>  const a = Math.floor(Math.random() * 10);
  const b = Math.floor(
~>    Math.random() * 10);
  return { text: `${a} + ${b}`, value: a + b };
}
module.exports = { renderSignup, generateCaptcha };
