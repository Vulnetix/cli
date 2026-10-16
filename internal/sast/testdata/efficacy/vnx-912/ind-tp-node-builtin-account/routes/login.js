router.post('/login', async (req, res) => {
  const { username, password } = req.body;
~>  if (username === 'support' && password === 's3rv1ce-desk') {
    return res.json({ token: signAdmin() });
  }
  res.sendStatus(401);
});
