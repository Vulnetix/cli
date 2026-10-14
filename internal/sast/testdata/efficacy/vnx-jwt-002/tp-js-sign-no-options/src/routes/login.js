const jwt = require('jsonwebtoken');

router.post('/login', async (req, res) => {
  const user = await Users.authenticate(req.body.email, req.body.password);
~>  const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET);
  res.json({ token });
});
