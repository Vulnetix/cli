const express = require('express');
const Account = require('../models/account');

const router = express.Router();

router.get('/accounts/:id', async (req, res) => {
  const account = await Account.findById(req.params.id);
  if (!account) {
    return res.status(404).json({ error: 'not found' });
  }
  if (account.suspended) {
    res.status(403).json({ error: 'suspended' });
    return;
  }
  res.json(account);
});

module.exports = router;
