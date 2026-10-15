// Node.js MongoDB filters are reported by VNX-NODE-014, not by this rule.
const express = require('express');
const router = express.Router();

router.post('/login', async (req, res) => {
  const user = await req.app.locals.db.collection('users').findOne({ username: req.body.username });
  res.json(user);
});

module.exports = router;
