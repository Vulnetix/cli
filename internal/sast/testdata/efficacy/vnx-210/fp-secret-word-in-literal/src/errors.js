function check(password) {
  if (!password) throw new Error('password is required');
  if (password.length < 12) throw new Error(`password must be at least 12 characters, got ${password.length}`);
  return true;
}

function reject(res) {
  return res.status(401).json({ error: 'invalid token' });
}
