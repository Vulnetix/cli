const jwt = require('jsonwebtoken');

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await Users.check(email, password);
~>  const token = jwt.sign({ id: user.id, email, password }, process.env.JWT_KEY, { expiresIn: '1h' });
  const refresh = jwt.sign(
    {
      id: user.id,
~>      passwordHash: user.passwordHash,
    },
    process.env.JWT_KEY,
    { expiresIn: '7d' }
  );
  res.json({ token, refresh });
});
