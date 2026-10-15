const express = require('express');
const router = express.Router();

router.delete('/users/:id', (req, res) => {
~>  if (req.headers['x-user-role'] === 'admin') {
    return users.remove(req.params.id).then(() => res.sendStatus(204));
  }
  res.sendStatus(403);
});

module.exports = router;
