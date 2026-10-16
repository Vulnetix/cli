'use strict';

const express = require('express');
const logger = require('../logger');

const router = express.Router();

router.post('/debug/level', (req, res) => {
  const { level } = req.body;
~>  process.env.LOG_LEVEL = level;
  logger.level = process.env.LOG_LEVEL;
  res.json({ level: logger.level });
});

module.exports = router;
