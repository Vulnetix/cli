const express = require('express');
const router = express.Router();

router.post('/login', async (req, res) => {
  const user = await users.verify(req.body.email, req.body.password);
  if (!user) return res.status(401).end();
~>  res.cookie('role', user.role, { httpOnly: true, maxAge: 3600000 });
  res.redirect('/dashboard');
});
module.exports = router;
