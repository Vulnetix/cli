const axios = require('axios');

async function human(token) {
  const { data } = await axios.post(
    'https://www.google.com/recaptcha/api/siteverify',
    new URLSearchParams({ secret: process.env.RECAPTCHA_SECRET, response: token }),
  );
~>  return data.success && data.score > 0;
}

module.exports = { human };
