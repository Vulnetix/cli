const express = require('express');
const router = express.Router();
const Member = require('../models/member');

router.post('/members/:id/promote', async (req, res) => {
  const member = await Member.findById(req.params.id);
~>  member.role = req.query.role;
  await member.save();
  res.json({ ok: true });
});

module.exports = router;
