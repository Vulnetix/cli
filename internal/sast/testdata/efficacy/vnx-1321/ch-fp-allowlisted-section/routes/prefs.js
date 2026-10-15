const router = require('express').Router();
const ALLOWED_SECTIONS = ['ui', 'mail', 'notifications'];
const prefs = { ui: {}, mail: {}, notifications: {} };

router.put('/prefs', (req, res) => {
  const section = req.body.section;
  const field = req.body.field;
  if (!ALLOWED_SECTIONS.includes(section)) {
    return res.sendStatus(400);
  }
  prefs[section][field] = req.body.value;
  res.json(prefs);
});

module.exports = router;
