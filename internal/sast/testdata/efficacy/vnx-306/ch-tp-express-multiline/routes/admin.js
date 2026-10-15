const express = require('express');
const User = require('../models/user');

const router = express.Router();

~>router.post(
  '/admin/users/:id/role',
  async (req, res) => {
    await User.updateOne({ _id: req.params.id }, { role: req.body.role });
    res.json({ ok: true });
  }
);

module.exports = router;
