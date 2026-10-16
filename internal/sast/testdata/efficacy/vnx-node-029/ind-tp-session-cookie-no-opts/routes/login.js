const router = require('express').Router();

router.post('/login', async (req, res) => {
  const user = await authenticate(req.body);
  const sessionId = await createSession(user);
~>  res.cookie('sessionId', sessionId);
  res.redirect('/');
});
module.exports = router;
