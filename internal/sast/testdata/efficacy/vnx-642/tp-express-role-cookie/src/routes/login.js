const express = require('express');
const router = express.Router();

router.post('/login', async (req, res) => {
  const user = await users.authenticate(req.body.email, req.body.password);
  if (!user) {
    return res.status(401).send('bad credentials');
  }
~>  res.cookie('role', user.role, { httpOnly: true });
~>  res.cookie("isAdmin", String(user.isAdmin), {
    maxAge: 3600000,
  });
  res.cookie('theme', user.theme);
  res.redirect('/');
});

module.exports = router;
