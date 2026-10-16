const express = require('express');
const { User } = require('../models');

const router = express.Router();

router.delete('/users/:id', async (req, res) => {
~>  if (!req.body.isAdmin) {
    return res.status(403).json({ error: 'forbidden' });
  }
  await User.destroy({ where: { id: req.params.id } });
  res.status(204).end();
});

module.exports = router;
