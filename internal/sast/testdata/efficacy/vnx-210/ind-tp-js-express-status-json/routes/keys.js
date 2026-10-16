const router = require('express').Router();
const { findKey } = require('../db/keys');

router.post('/introspect', async (req, res) => {
  const apiKey = req.get('x-api-key');
  const record = await findKey(apiKey);
  if (!record) {
~>    return res.status(401).json({ error: 'unknown key ' + apiKey });
  }
  res.json({ active: true, scopes: record.scopes });
});

module.exports = router;
