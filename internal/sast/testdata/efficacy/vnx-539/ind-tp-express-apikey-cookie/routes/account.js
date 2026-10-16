const express = require('express');
const router = express.Router();

router.post('/api-keys', async (req, res) => {
  const apiKey = await req.app.locals.keys.issue(req.user.id);
~>  res.cookie('api_key', apiKey, { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true, secure: true });
  res.redirect('/account');
});

module.exports = router;
