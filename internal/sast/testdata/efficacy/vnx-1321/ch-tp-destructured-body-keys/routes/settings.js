const router = require('express').Router();
const settings = { ui: {}, mail: {} };

router.post('/settings', (req, res) => {
  const { section, key, value } = req.body;
~>  settings[section][key] = value;
  res.json(settings);
});

module.exports = router;
