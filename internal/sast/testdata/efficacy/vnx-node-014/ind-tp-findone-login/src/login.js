const User = require('./models/user');

app.post('/login', async (req, res) => {
~>  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password,
  });
  res.json({ ok: !!user });
});
