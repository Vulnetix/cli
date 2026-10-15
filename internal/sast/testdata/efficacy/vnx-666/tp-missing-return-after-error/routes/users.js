const express = require('express');
const router = express.Router();

router.get('/users/:id', async (req, res) => {
  const user = await db.findUser(req.params.id);
  if (!user) {
~>    res.status(404).json({ error: 'not found' });
  }
  res.json(user);
});

router.post('/login', function (req, res) {
  if (!req.body.password) {
~>    res.redirect('/login?error=1')
  }
  res.render('home', { user: req.user });
});

module.exports = router;
