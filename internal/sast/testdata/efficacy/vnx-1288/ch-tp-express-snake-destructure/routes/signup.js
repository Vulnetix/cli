const router = require('express').Router();
const User = require('../models/user');

router.post('/signup', async (req, res) => {
~>  const { email, password, password_confirmation } = req.body;
  if (!email || !password || !password_confirmation) {
    return res.status(400).json({ error: 'missing fields' });
  }
  const user = await User.create({ email, password });
  res.status(201).json({ id: user.id });
});

module.exports = router;
