const router = require('express').Router();

router.post('/login', (req, res) => {
  const token = issueToken(req.body.user);
  res.cookie('session', token, {
    secure: true,
    sameSite: 'lax',
    maxAge: 3600 * 1000,
    httpOnly: true,
  });
  res.cookie('XSRF-TOKEN', req.csrfToken(), { secure: true });
  res.cookie('locale', 'en-GB');
  res.json({ ok: true });
});

module.exports = router;
