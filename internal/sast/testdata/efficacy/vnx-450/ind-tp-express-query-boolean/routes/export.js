const express = require('express');
const router = express.Router();

router.get('/export', async (req, res) => {
~>  const includeDeleted = Boolean(req.query.include_deleted);
  const rows = await req.db.exportUsers({ includeDeleted });
  res.json(rows);
});

module.exports = router;
