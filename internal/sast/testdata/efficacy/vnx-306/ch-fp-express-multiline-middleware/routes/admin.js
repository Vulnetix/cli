const express = require('express');
const { requireAdmin } = require('../middleware/auth');

const router = express.Router();

router.post(
  '/admin/users/:id/role',
  requireAdmin,
  async (req, res) => {
    res.json({ ok: true });
  }
);

module.exports = router;
