'use strict';

const express = require('express');
const { body } = require('express-validator');
const users = require('../services/users');

const router = express.Router();

~>router.post('/users', body('email').isEmail(), body('age').isInt({ min: 13 }), async (req, res) => {
  const user = await users.create(req.body);
  res.status(201).json(user);
});

module.exports = router;
