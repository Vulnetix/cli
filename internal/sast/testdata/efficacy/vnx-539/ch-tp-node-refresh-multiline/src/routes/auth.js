const express = require('express');
const router = express.Router();

router.post('/login', async (req, res) => {
  const { access, refresh } = await issueTokens(req.body.user);
~>  res.cookie('refreshToken', refresh, {
    httpOnly: true,
    secure: true,
    maxAge: 90 * 24 * 60 * 60 * 1000,
  });
  res.json({ access });
});

module.exports = router;
