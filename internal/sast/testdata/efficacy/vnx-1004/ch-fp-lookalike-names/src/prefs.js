const router = require('express').Router();

router.post('/prefs', (req, res) => {
  res.cookie('accessibility_mode', req.body.mode, { maxAge: 31536000000 });
  res.cookie('author_view', 'compact');
  res.cookie('controller_layout', 'grid');
  res.json({ ok: true });
});

module.exports = router;
