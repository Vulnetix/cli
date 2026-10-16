const store = new Map();

function createCaptcha() {
~>  const captchaCode = Math.random().toString(36).slice(2, 8);
  const id = require('crypto').randomUUID();
  store.set(id, captchaCode);
  return { id, svg: render(captchaCode) };
}
module.exports = { createCaptcha };
