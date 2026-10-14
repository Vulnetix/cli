const jwt = require('jsonwebtoken');

router.post('/login', (req, res) => {
~>  const token = jwt.sign({ id: req.user.id, role: 'user' }, 'sup3r-s3cret', { expiresIn: '1h' });
  res.json({ token });
});

router.get('/me', (req, res) => {
~>  const user = jwt.verify(req.headers.authorization, "sup3r-s3cret");
  res.json(user);
});
