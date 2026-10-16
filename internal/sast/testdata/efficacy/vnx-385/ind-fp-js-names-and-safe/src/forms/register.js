const crypto = require('crypto');
const bcrypt = require('bcrypt');

function validate(body, user) {
  if (body.password === undefined || body.password === null) return 'required';
  if (body.password.length === 0) return 'required';
  if (body.passwordPolicy === 'strict') return checkStrict(body);
  if (user.passwordResetRequired === true) return 'reset';
  return null;
}

function safeCompare(stored, candidate) {
  return crypto.timingSafeEqual(Buffer.from(stored.passwordHash, 'hex'), Buffer.from(candidate, 'hex'));
}

async function verify(user, input) {
  return bcrypt.compare(input, user.passwordHash);
}

// if (user.password !== derived) was the old check
const MESSAGE = "user.password === derived is not constant-time";

module.exports = { validate, safeCompare, verify, MESSAGE };
