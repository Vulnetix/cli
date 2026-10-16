const express = require('express');
const { Account } = require('../models');

const router = express.Router();

router.get('/me', async (req, res) => {
  const accountId = req.signedCookies.user_id;
  const account = await Account.findByPk(accountId);
  res.cookie('user_id', account.id, { signed: true, httpOnly: true });
  res.json({ id: account.id });
});

module.exports = router;
