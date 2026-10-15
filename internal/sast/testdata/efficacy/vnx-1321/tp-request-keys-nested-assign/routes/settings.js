const express = require('express');
const router = express.Router();
const store = {};

router.post('/settings', (req, res) => {
~>  store[req.body.section][req.body.key] = req.body.value;
  res.json({ ok: true });
});

router.put('/prefs/:group', (req, res) => {
  const prefs = store.prefs;
~>  prefs[req.params.group][req.query.name] = req.query.value;
  res.sendStatus(204);
});

module.exports = router;
