function assertCredentials(username, password, token) {
  if (!username) {
    throw new Error('username is required');
  }
  throw new Error(password ? 'password rejected' : 'password missing');
}

function badRequest(res, token) {
  return res.status(400).json({ error: 'invalid token', tokenProvided: !!token });
}

function checkLength(password) {
  if (password.length < 12) {
    throw new RangeError(`password must be at least 12 characters, got ${password.length}`);
  }
}

module.exports = { assertCredentials, badRequest, checkLength };
