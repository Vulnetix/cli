const router = require('express').Router();

router.post('/users', (req, res) => {
  if (req.body.role === 'admin' && !req.user.isAdmin) {
    return res.status(403).send('only admins can create admins');
  }
  createUser(req.body);
  res.sendStatus(201);
});

router.get('/users', async (req, res) => {
  const filter = {};
  if (req.query.role === 'admin') {
    filter.role = 'admin';
  }
  res.json(await User.find(filter));
});

module.exports = router;
