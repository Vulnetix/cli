const axios = require('axios');
async function checkRecaptcha(token) {
  const r = await axios.post('https://www.google.com/recaptcha/api/siteverify', null, { params: { secret: process.env.RECAPTCHA_SECRET, response: token } });
  return r.data.success;
}
// const captchaCode = Math.random().toString(36).slice(2, 8);
module.exports = { checkRecaptcha };
