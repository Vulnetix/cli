const express = require('express');
const { requireAdmin } = require('../middleware/auth');

const router = express.Router();
router.use(requireAdmin);

router.get('/admin/stats', (req, res) => {
  res.json({ users: 10 });
});

module.exports = router;
