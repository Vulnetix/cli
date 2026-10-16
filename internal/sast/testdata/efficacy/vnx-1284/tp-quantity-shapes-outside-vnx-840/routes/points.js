const express = require('express');
const Member = require('../models/member');

const router = express.Router();

router.post('/redeem', async (req, res) => {
  const { points } = req.body;
~>  await Member.updateOne({ _id: req.user.id }, { $inc: { points: -points } });
  res.json({ ok: true });
});

module.exports = router;
