const express = require('express');
const router = express.Router();

router.get('/sports/badminton/courts', (req, res) => {
  res.json([]);
});

router.get('/administrative-areas', (req, res) => {
  res.json([]);
});

module.exports = router;
