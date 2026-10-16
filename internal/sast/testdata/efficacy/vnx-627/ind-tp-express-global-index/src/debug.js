const express = require('express');
const router = express.Router();

router.get('/debug/var', (req, res) => {
~>  res.send(String(global[req.query.name]));
});

router.post('/debug/var', (req, res) => {
  const { name, value } = req.body;
~>  globalThis[name] = value;
  res.json({ ok: true });
});

module.exports = router;
