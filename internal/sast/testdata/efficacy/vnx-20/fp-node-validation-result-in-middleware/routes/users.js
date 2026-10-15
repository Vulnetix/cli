const express = require('express');
const { body } = require('express-validator');
const validate = require('../middleware/validate');
const db = require('../db');

const router = express.Router();

router.post('/register', body('email').isEmail(), validate, async (req, res) => {
  const rows = await db.query('SELECT 1').then((r) => r.rows);
  res.json(rows);
});

module.exports = router;
