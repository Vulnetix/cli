const router = require('express').Router();
const db = require('../db');

router.get('/admin-stats', async (req, res) => {
  res.json(await db.stats());
});

module.exports = router;
