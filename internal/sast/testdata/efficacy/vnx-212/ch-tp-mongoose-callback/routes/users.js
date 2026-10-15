const express = require('express');
const User = require('../models/user');

const router = express.Router();

router.get('/users/:id', (req, res) => {
  User.findById(req.params.id, (err, user) => {
    if (err) return res.status(500).end();
~>    res.json(user);
  });
});

module.exports = router;
