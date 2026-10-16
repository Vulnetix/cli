const express = require('express');
const router = express.Router();

function ensureLoggedIn(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login');
}

router.get('/dashboard', ensureLoggedIn, (req, res) => {
  res.render('dashboard', { user: req.session.user });
});

module.exports = router;
