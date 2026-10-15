const express = require('express');
const router = express.Router();
const { checkCredentials } = require('../services/users');

~>router.route('/login')
  .get((req, res) => res.render('login'))
  .post(async (req, res) => {
    const ok = await checkCredentials(req.body.username, req.body.password);
    if (!ok) return res.status(401).render('login', { error: 'Invalid credentials' });
    req.session.user = req.body.username;
    res.redirect('/');
  });

~>router.route('/password-reset').post(async (req, res) => {
  res.json({ sent: true });
});

module.exports = router;
