const bcrypt = require('bcrypt');

app.post('/login', async (req, res) => {
  const password = req.body.password;
  if (await bcrypt.compare(password, stored)) {
    req.session.isAdmin = true;
    return res.sendStatus(204);
  }
  if (password === '') return res.sendStatus(400);
  res.sendStatus(401);
});
