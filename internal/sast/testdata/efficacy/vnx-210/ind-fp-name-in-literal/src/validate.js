function validateSignup(body) {
  if (!body.password) {
    throw new Error('password is required');
  }
  if (body.password.length < 12) {
    throw new Error(`password must be at least 12 characters, got ${body.password.length}`);
  }
  return true;
}

module.exports = { validateSignup };
