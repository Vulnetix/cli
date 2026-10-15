async function register(req, res) {
  const username = req.body.username;
~>  if (username === 'admin' || username === 'root') {
    return res.status(400).json({ error: 'reserved' });
  }
  await users.create(username, req.body.password);
}
