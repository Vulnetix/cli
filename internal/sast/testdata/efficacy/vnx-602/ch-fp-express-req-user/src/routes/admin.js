const express = require('express');
const router = express.Router();

router.post('/settings', (req, res) => {
  if (req.user && req.user.role === 'admin' && req.session.isAdmin) {
    return settings.save(req.body).then(() => res.sendStatus(204));
  }
  res.sendStatus(403);
});

module.exports = router;
