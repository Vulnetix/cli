const express = require('express');
const router = express.Router();

router.post('/login', async (req, res) => {
  const user = await authenticate(req.body.email, req.body.password);
  if (!user) {
    return res.status(401).send('bad credentials');
  }
~>  res.cookie('username', user.name, { httpOnly: true, secure: true });
  res.redirect('/account');
});

module.exports = router;
