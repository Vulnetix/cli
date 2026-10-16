const express = require('express');
const router = express.Router();

router.get('/accounts/:id', async (req, res) => {
  const acct = await Account.findById(req.params.id);
  if (!acct) {
    return res.status(404).json({ error: 'not found' });
  }
  if (!acct.active) {
    res.status(403).json({ error: 'disabled' });
    return;
  }
  if (req.query.format === 'csv') {
    res.type('text/csv').send(toCsv(acct));
  } else {
    res.json(acct);
  }
});

module.exports = router;
