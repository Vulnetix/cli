const express = require('express');
const Wallet = require('../models/wallet');

const router = express.Router();

router.post('/withdraw', async (req, res) => {
  const { amount } = req.body;
~>  await Wallet.updateOne({ owner: req.user.id }, { $inc: { balance: -amount } });
  res.json({ ok: true });
});

module.exports = router;
