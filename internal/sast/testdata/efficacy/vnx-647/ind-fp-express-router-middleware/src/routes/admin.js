const express = require('express');
const { requireAdmin } = require('../middleware/auth');

const router = express.Router();

router.get('/admin', requireAdmin, (req, res) => res.render('admin/index'));
router.post('/admin/users/:id/disable', requireAdmin, async (req, res) => {
  await disableUser(req.params.id);
  res.sendStatus(204);
});

module.exports = router;
