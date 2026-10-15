const axios = require('axios');

const MIN_SCORE = 0.5;

async function human(token, expectedAction) {
  const { data } = await axios.post(
    'https://www.google.com/recaptcha/api/siteverify',
    new URLSearchParams({ secret: process.env.RECAPTCHA_SECRET, response: token }),
  );
  if (!data.success) return false;
  return data.score >= MIN_SCORE && data.action === expectedAction;
}

module.exports = { human };
