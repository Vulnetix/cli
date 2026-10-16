// reCAPTCHA v3 verification; the page calls grecaptcha.execute(siteKey, {action: 'signup'})
const fetch = require('node-fetch');

async function verify(token) {
  const resp = await fetch('https://www.google.com/recaptcha/api/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `secret=${process.env.RECAPTCHA_V3_SECRET}&response=${token}`,
  });
~>  const { success } = await resp.json();
  return success;
}
module.exports = { verify };
