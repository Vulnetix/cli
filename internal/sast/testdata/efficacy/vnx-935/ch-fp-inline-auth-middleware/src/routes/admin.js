const express = require('express');
const { authenticate, authorize } = require('../middleware/auth');
const router = express.Router();

router.post('/admin/reset', authenticate, authorize('admin'), async (req, res) => {
  res.json({ ok: true });
});

router.get("/admin/report", requireRole("admin"), (req, res) => res.render("report"));

router.get('/administration-guide', (req, res) => res.redirect('/docs'));

module.exports = router;
