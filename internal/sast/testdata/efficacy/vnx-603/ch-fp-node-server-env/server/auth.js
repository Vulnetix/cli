const crypto = require('crypto');

function checkAdmin(password) {
  const expected = Buffer.from(process.env.ADMIN_PASSWORD || '');
  const given = Buffer.from(password || '');
  return expected.length === given.length && crypto.timingSafeEqual(expected, given);
}

module.exports = { checkAdmin };
