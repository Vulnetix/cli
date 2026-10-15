const express = require('express');
const { loginLimiter } = require('./limits');
const brute = require('./brute');
const ctrl = require('./controllers');

const router = express.Router();
router.post('/login', loginLimiter, ctrl.login);
router.post(
  '/signin',
  brute.prevent,
  ctrl.login,
);
module.exports = router;
