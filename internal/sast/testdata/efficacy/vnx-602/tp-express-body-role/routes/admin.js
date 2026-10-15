const express = require('express');
const router = express.Router();

router.post('/users/:id/delete', (req, res) => {
~>  if (req.body.isAdmin) {
    return deleteUser(req.params.id).then(() => res.sendStatus(204));
  }
  res.sendStatus(403);
});

router.get('/reports', (req, res) => {
~>  if (req.query.role === 'admin' || req.headers['x-user-role'] == 'manager') {
    return res.json(allReports());
  }
  res.status(403).end();
});

module.exports = router;
