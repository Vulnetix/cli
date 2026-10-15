const fetch = require('node-fetch');

// The old captcha used Math.random() and sent the answer back: res.json(captcha)
async function verifyRecaptcha(token) {
  const r = await fetch('https://www.google.com/recaptcha/api/siteverify', {
    method: 'POST',
    body: new URLSearchParams({ secret: process.env.RECAPTCHA_SECRET, response: token }),
  });
  const data = await r.json();
  if (!data.success) {
    throw new Error('captcha failed');
  }
  return data;
}
module.exports = { verifyRecaptcha };
